/* Orchid - WebRTC P2P VPN Market (on Ethereum)
 * Copyright (C) 2017-2020  The Orchid Authors
*/

/* GNU Affero General Public License, Version 3 {{{ */
/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
**/
/* }}} */


use std::io::{self, Write};
use std::ffi::c_void;

use risc0_zkvm::sha;


type Output = extern "C" fn(baton: *mut c_void, data: *const u8, size: usize);


#[no_mangle]
pub extern "C" fn riscy_image(
    elf_data: *const u8, elf_size: usize,
    image_data: *mut u8
) {
    let elf = unsafe { std::slice::from_raw_parts(elf_data, elf_size) };
    let image = risc0_zkvm::compute_image_id(elf).unwrap();
    unsafe { std::ptr::copy_nonoverlapping(image.as_bytes().as_ptr(), image_data, 32); }
}


#[no_mangle]
pub extern "C" fn riscy_execute(
    elf_data: *const u8, elf_size: usize,
    input_data: *const u8, input_size: usize,
    journal_code: Output, journal_data: *mut c_void
) {
    let elf = unsafe { std::slice::from_raw_parts(elf_data, elf_size) };
    let input = unsafe { std::slice::from_raw_parts(input_data, input_size) };

    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&input)
    .build().unwrap();

    let executor = risc0_zkvm::default_executor();
    let info = executor.execute(env, elf).unwrap();
    let journal = info.journal.bytes;
    journal_code(journal_data, journal.as_ptr(), journal.len());
}

#[no_mangle]
pub extern "C" fn riscy_prove(
    elf_data: *const u8, elf_size: usize,
    input_data: *const u8, input_size: usize,
    receipt_code: Output, receipt_data: *mut c_void
) {
    let elf = unsafe { std::slice::from_raw_parts(elf_data, elf_size) };
    let input = unsafe { std::slice::from_raw_parts(input_data, input_size) };

    let env = risc0_zkvm::ExecutorEnv::builder()
        .write_slice(&input)
    .build().unwrap();

    let prover = risc0_zkvm::default_prover();
    let info = prover.prove(env, elf).unwrap();
    let receipt = bincode::serialize(&info.receipt).unwrap();
    receipt_code(receipt_data, receipt.as_ptr(), receipt.len());
}

#[no_mangle]
pub extern "C" fn riscy_verify(
    receipt_data: *const u8, receipt_size: usize,
    image_data: *const u8,
    journal_code: Output, journal_data: *mut c_void
) {
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(unsafe { std::slice::from_raw_parts(receipt_data, receipt_size) }).unwrap();
    let image = sha::Digest::from(unsafe { *(image_data as *const [u8; 32]) });
    receipt.verify(image).unwrap();
    let journal = receipt.journal.bytes;
    journal_code(journal_data, journal.as_ptr(), journal.len());
}
