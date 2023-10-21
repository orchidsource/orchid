
# Generate some random data
dd if=/dev/urandom of="file_1KB.dat" bs=1K count=1

# Encode a file, writing n files for each of the two node types to a ".encoded" directory.
./storage.sh encode \
  --path "file_1KB.dat" \
  --encoding0 reed_solomon --k0 3 --n0 5 \
  --encoding1 reed_solomon --k1 3 --n1 5 \
  --overwrite

# Decode a file from an encoded storage directory, tolerant of missing files (erasures).
./storage.sh decode \
  --encoded "file_1KB.dat.encoded" \
  --recovered "recovered.dat" \
  --overwrite

# Compare the original and decoded files.
cmp -s "file_1KB.dat" "recovered.dat" && echo "Passed" || echo "Failed"


# Generate shard recovery files: Using k (3) type 0 node sources (helper nodes), generate recovery
# files for restoration of node type 1 index 0.
for helper_node in 0 1 2
do
./storage.sh generate_recovery_file \
  --recover_node_index 0 \
  --recover_encoding reed_solomon --k 3 --n 5 \
  --data_path "file_1KB.dat.encoded/type0_node${helper_node}.dat" \
  --output_path "recover_type1_node0/recover_${helper_node}.dat" \
  --overwrite
done

# Recover the shard for node type 1 index 0 from the k (3) recovery files.
./storage.sh recover_node \
  --k 3 --n 5 --encoding reed_solomon \
  --files_dir "recover_type1_node0" \
  --output_path "recovered_type1_0.dat" \
  --overwrite

# Compare the original and recovered data shards.
cmp -s "file_1KB.dat.encoded/type1_node0.dat" "recovered_type1_0.dat" && echo "Passed" || echo "Failed"

