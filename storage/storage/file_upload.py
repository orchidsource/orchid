import asyncio
import os
import random
from typing import List, Optional, Set, Callable

import aiohttp
from aiohttp import FormData
from icecream import ic

from server.cluster_file import ClusterFileStatus
from server.providers import Providers
from server.server_model import Server, ServerStatus
from storage.repository import Repository
from storage.storage_model import EncodedFileStatus
from storage.table_util import print_table


class FileUpload:
    def __init__(self, repo: Repository, providers: Providers):
        self.repo = repo
        self.providers = providers

    async def push(
            self,
            filename: str,
            providers_list: Optional[List[Server]] = None,
            dryrun: bool = False,
            overwrite: bool = False,
            progress_callback: Callable[[int, int, int, int], None] = None,
    ):
        local_file_status: EncodedFileStatus = self.repo.file_status(filename)
        print(f"Push file: {local_file_status.file}")

        # Confirm that the file is fully available locally
        if local_file_status.local_availability() < 1:
            print(local_file_status)
            print("Not enough shards available to upload file.")
            return
        else:
            print(f"File {local_file_status.file.name} local availability: {local_file_status.local_availability()}.")

        # Determine the universe of providers available for this file
        if providers_list is None:
            providers_list = self.providers.servers
        print(f"Providers: {providers_list}")

        # Determine the current availability of the file on the set of providers
        cluster_file: ClusterFileStatus = await ClusterFileStatus(
            providers_list, local_file_status.file).fetch()
        print("Current cluster file availability:", cluster_file.cluster_availability())

        # Check that all the specified providers are available
        for provider in providers_list:
            status = cluster_file.server_status_map[provider].server_status
            if status == ServerStatus.OK:
                continue
            if status == ServerStatus.UNREACHABLE:
                print(f"Provider {provider.name} is currently unreachable.")
            else:
                print(f"Provider {provider.name} is not available.")
            print("Please specify a different set of providers.")
            return

        # Get a map of the current file status by server
        if overwrite:
            server_file_status_map: dict[Server, EncodedFileStatus | None] = {}
        else:
            server_file_status_map: dict[Server, EncodedFileStatus | None] = (
                cluster_file.server_file_status_map(local_file_status.file))

        # Determine the shards to upload
        upload0: Set[int]
        upload1: Set[int]
        if overwrite:
            print("Overwriting any existing shards.")
            upload0 = set(local_file_status.shards0)
            upload1 = set(local_file_status.shards1)
        else:
            upload0, upload1 = cluster_file.missing_shards(local_file_status)

        if not upload0 and not upload1:
            print("No shards to upload.")
            return

        assignments: dict[Server, tuple[list[int], list[int]]] = (
            self.assign_shards_to_servers(providers_list, server_file_status_map, upload0, upload1))

        print("Shard Upload Plan:")
        print_table(["Provider", "Type 0", "Type 1"],
                    [(provider.name, assignments[provider][0], assignments[provider][1]) for provider in assignments])

        if dryrun:
            print("Stopping.")
            return

        # Upload the shards
        filename = local_file_status.file.name
        tasks = []

        async def _add_task_for_shard(provider: Server, node_type: int, shard_index: int):
            shard_file_path = self.repo.shard_path(filename, node_type=node_type, node_index=shard_index)
            config_file_path = self.repo.file_config_path(filename)
            url = f'{provider.url}/upload'
            auth = provider.auth_token
            task = asyncio.create_task(self.upload_file(
                config_file_path, shard_file_path, node_type, shard_index, url, auth,
                progress_callback=progress_callback, task_index=len(tasks)))
            tasks.append(task)

        for provider in assignments:
            for shard in assignments[provider][0]:
                await _add_task_for_shard(provider, node_type=0, shard_index=shard)
            for shard in assignments[provider][1]:
                await _add_task_for_shard(provider, node_type=1, shard_index=shard)

        await asyncio.gather(*tasks)
        ...

    @staticmethod
    # Create a map that assigns each server a list of shards to upload.
    # Shards are assigned round-robin to servers that do not already have them.
    def assign_shards_to_servers(
            providers_list, server_file_status_map, upload0, upload1) -> dict[Server, tuple[list[int], list[int]]]:

        map: dict[Server, tuple[list[int], list[int]]] = {server: ([], []) for server in providers_list}
        # Assign the type 0 shards
        while upload0:
            start = len(upload0)
            for provider in providers_list:
                provider_map = server_file_status_map.get(provider)
                applicable_shards = upload0 - set(provider_map.shards0 if provider_map else [])
                if applicable_shards:
                    shard = applicable_shards.pop()
                    map[provider][0].append(shard)
                    upload0.remove(shard)
            # If we looped over all providers and did not assign any shards, then we have a problem.
            if len(upload0) == start:
                raise Exception("Error in shard mapping: type 0")
        # Assign the type 1 shards
        while upload1:
            start = len(upload1)
            for provider in providers_list:
                provider_map = server_file_status_map.get(provider)
                applicable_shards = upload1 - set(provider_map.shards1 if provider_map else [])
                if applicable_shards:
                    shard = applicable_shards.pop()
                    map[provider][1].append(shard)
                    upload1.remove(shard)
            # If we looped over all providers and did not assign any shards, then we have a problem.
            if len(upload1) == start:
                raise Exception("Error in shard mapping: type 1.")

        return map

    @staticmethod
    async def upload_file(
            config_file_path: str,
            shard_file_path: str,
            node_type: int,
            shard_index: int,
            url: str,
            auth: str = None,
            # id/index, progress, total, node_type
            progress_callback: Callable[[int, int, int, int], None] = None,
            timeout: int = 60 * 60 * 24 * 7,
            task_index: int = 0,  # for logging and progress reporting
    ):
        async with aiohttp.ClientSession() as session:
            data = FormData()
            data.add_field('config', open(config_file_path, 'rb'), filename='config', content_type='application/json')
            # TODO: demo
            demo = False  # slow down the progress to show the UI
            reporter = ProgressReporter(
                shard_file_path, progress_callback, task_index=task_index, node_type=node_type, demo=demo)
            data.add_field('file', reporter, filename='file', content_type='application/octet-stream')
            data.add_field('node_type', str(node_type))
            data.add_field('shard_index', str(shard_index))
            headers = {'Authorization': auth} if auth else {}
            async with session.post(url, data=data, headers=headers, timeout=timeout) as response:
                # Process response if necessary
                return await response.text()


class ProgressReporter:
    # For demo purposes, we slow down the progress to show the UI
    demo_chunk_size = 16
    demo_sleep_random = 0.2

    def __init__(self,
                 file_path: str, callback: callable, chunk_size: int = 1024 * 1024,
                 task_index: int = -1,
                 node_type: int = -1,
                 demo: bool = False):
        self.file_path = file_path
        self.callback = callback
        self.chunk_size = chunk_size if not demo else self.demo_chunk_size
        self.total_size = os.path.getsize(file_path)
        self.uploaded = 0
        self.task_index = task_index
        self.node_type = node_type
        self.demo = demo

    async def __aiter__(self):
        with open(self.file_path, 'rb') as file:
            while True:
                chunk = file.read(self.chunk_size)
                if not chunk:
                    break
                self.uploaded += len(chunk)
                if self.callback:
                    self.callback(self.task_index, self.uploaded, self.total_size, self.node_type)
                if self.demo:
                    # a random float between 0 and 1
                    sleep = random.random() * self.demo_sleep_random
                    await asyncio.sleep(sleep)
                yield chunk


# main
if __name__ == '__main__':
    async def main():
        repo = Repository.default()
        file0 = repo.list()[0]
        shard_path = repo.shard_path(file0, node_type=0, node_index=0)
        config_path = repo.file_config_path(file0)
        # url = 'http://localhost:8090/upload'
        url = 'http://localhost:5001/upload'

        def callback(file, progress, total, type):
            ic(file, progress, total)

        response = await FileUpload.upload_file(
            config_file_path=config_path, shard_file_path=shard_path,
            node_type=0, shard_index=0, url=url, progress_callback=callback)
        ic(response)
        ...


    asyncio.run(main())
...
