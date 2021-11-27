use std::collections::HashMap;
use std::env;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;
use std::str::FromStr;
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

const HASH_BYTES: usize = 20;
const OBJECTS_DIRECTORY: &str = ".git/objects";
const PACKS_DIRECTORY: &str = ".git/objects/pack";
const COMMIT_OBJECT_TYPE: &[u8] = b"commit";
const TREE_OBJECT_TYPE: &[u8] = b"tree";
const BLOB_OBJECT_TYPE: &[u8] = b"blob";
const TAG_OBJECT_TYPE: &[u8] = b"tag";
const INDEX_FILE_SUFFIX: &str = ".idx";
const PACK_FILE_SUFFIX: &str = ".pack";
const LONG_OFFSET_FLAG: u32 = 1 << 31;
const TYPE_BITS: u8 = 3;
const VARINT_ENCODING_BITS: u8 = 7;
const TYPE_BYTE_SIZE_BITS: u8 = VARINT_ENCODING_BITS - TYPE_BITS;
const VARINT_CONTINUE_FLAG: u8 = 1 << VARINT_ENCODING_BITS;
const COPY_INSTRUCTION_FLAG: u8 = 1 << 7;
const COPY_OFFSET_BYTES: u8 = 4;
const COPY_SIZE_BYTES: u8 = 3;
const COPY_ZERO_SIZE: usize = 0x10000;

const fn cumulative_objects_position(first_byte: u8) -> u64 {
  4 + 4 + first_byte as u64 * 4
}
const TOTAL_OBJECTS_POSITION: u64 = cumulative_objects_position(u8::MAX);
fn hash_position(object_index: u32) -> u64 {
  TOTAL_OBJECTS_POSITION + 4 + object_index as u64 * HASH_BYTES as u64
}
fn crc32_position(total_objects: u32, object_index: u32) -> u64 {
  hash_position(total_objects) + object_index as u64 * 4
}
fn offset_position(total_objects: u32, object_index: u32) -> u64 {
  crc32_position(total_objects, total_objects) + object_index as u64 * 4
}
fn long_offset_position(total_objects: u32, offset_index: u32) -> u64 {
  offset_position(total_objects, total_objects) + offset_index as u64 * 8
}

fn make_error(message: &str) -> Error {
  Error::new(ErrorKind::Other, message)
}

fn keep_bits(value: usize, bits: u8) -> usize {
  value & ((1 << bits) - 1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hash([u8; HASH_BYTES]);

fn hex_char_value(hex_char: u8) -> Option<u8> {
  match hex_char {
    b'0'..=b'9' => Some(hex_char - b'0'),
    b'a'..=b'f' => Some(hex_char - b'a' + 10),
    _ => None,
  }
}

fn hex_to_hash(hex_hash: &[u8]) -> Option<Hash> {
  const BITS_PER_CHAR: usize = 4;
  const CHARS_PER_BYTE: usize = 8 / BITS_PER_CHAR;

  let byte_chunks = hex_hash.chunks_exact(CHARS_PER_BYTE);
  if !byte_chunks.remainder().is_empty() {
    return None
  }

  let bytes = byte_chunks.map(|hex_digits| {
    hex_digits.iter().try_fold(0, |value, &byte| {
      let char_value = hex_char_value(byte)?;
      Some(value << BITS_PER_CHAR | char_value)
    })
  }).collect::<Option<Vec<_>>>()?;
  let bytes = <[u8; HASH_BYTES]>::try_from(bytes).ok()?;
  Some(Hash(bytes))
}

impl FromStr for Hash {
  type Err = Error;

  fn from_str(hex_hash: &str) -> io::Result<Self> {
    hex_to_hash(hex_hash.as_bytes()).ok_or_else(|| {
      make_error(&format!("Invalid hash: {}", hex_hash))
    })
  }
}

impl Display for Hash {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    for byte in self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

#[derive(Clone, Copy, Debug)]
enum ObjectType {
  Commit,
  Tree,
  Blob,
  Tag,
}

enum PackObjectType {
  Base(ObjectType),
  OffsetDelta,
  HashDelta,
}

#[derive(Debug)]
struct Object {
  object_type: ObjectType,
  contents: Vec<u8>,
}

impl Object {
  fn hash(&self) -> Hash {
    use ObjectType::*;

    let hash = Sha1::new()
      .chain(match self.object_type {
        Commit => COMMIT_OBJECT_TYPE,
        Tree => TREE_OBJECT_TYPE,
        Blob => BLOB_OBJECT_TYPE,
        Tag => TAG_OBJECT_TYPE,
      })
      .chain(b" ")
      .chain(self.contents.len().to_string())
      .chain(b"\0")
      .chain(&self.contents)
      .finalize();
    Hash(<[u8; HASH_BYTES]>::try_from(hash.as_slice()).unwrap())
  }
}

fn read_bytes<R: Read, const N: usize>(stream: &mut R) -> io::Result<[u8; N]> {
  let mut bytes = [0; N];
  stream.read_exact(&mut bytes)?;
  Ok(bytes)
}

fn at_end_of_stream<R: Read>(stream: &mut R) -> io::Result<bool> {
  // Try to read a byte and check whether there was one to read
  let bytes_read = stream.read(&mut [0])?;
  Ok(bytes_read == 0)
}

fn read_u32<R: Read>(stream: &mut R) -> io::Result<u32> {
  let bytes = read_bytes(stream)?;
  Ok(u32::from_be_bytes(bytes))
}

fn read_u64<R: Read>(stream: &mut R) -> io::Result<u64> {
  let bytes = read_bytes(stream)?;
  Ok(u64::from_be_bytes(bytes))
}

fn read_hash<R: Read>(stream: &mut R) -> io::Result<Hash> {
  let bytes = read_bytes(stream)?;
  Ok(Hash(bytes))
}

fn read_until_delimiter<R: Read>(stream: &mut R, delimiter: u8) -> io::Result<Vec<u8>> {
  let mut bytes = vec![];
  loop {
    let [byte] = read_bytes(stream)?;
    if byte == delimiter {
      break
    }

    bytes.push(byte);
  }
  Ok(bytes)
}

fn read_varint_byte<R: Read>(stream: &mut R) -> io::Result<(u8, bool)> {
  let [byte] = read_bytes(stream)?;
  let value = byte & !VARINT_CONTINUE_FLAG;
  let more_bytes = byte & VARINT_CONTINUE_FLAG != 0;
  Ok((value, more_bytes))
}

fn read_size_encoding<R: Read>(stream: &mut R) -> io::Result<usize> {
  let mut value = 0;
  let mut length = 0;
  loop {
    let (byte_value, more_bytes) = read_varint_byte(stream)?;
    value |= (byte_value as usize) << length;
    if !more_bytes {
      return Ok(value)
    }

    length += VARINT_ENCODING_BITS;
  }
}

fn read_type_and_size<R: Read>(stream: &mut R) -> io::Result<(u8, usize)> {
  // Object type and uncompressed pack data size
  // are stored in a "size-encoding" variable-length integer.
  // Bits 4 through 6 store the type and the remaining bits store the size.
  let value = read_size_encoding(stream)?;
  let object_type = keep_bits(value >> TYPE_BYTE_SIZE_BITS, TYPE_BITS) as u8;
  let size = keep_bits(value, TYPE_BYTE_SIZE_BITS)
           | (value >> VARINT_ENCODING_BITS << TYPE_BYTE_SIZE_BITS);
  Ok((object_type, size))
}

fn read_offset_encoding<R: Read>(stream: &mut R) -> io::Result<u64> {
  // Like the object length, the offset for an OffsetDelta object
  // is stored in a variable number of bytes,
  // with the most significant bit of each byte indicating whether more bytes follow.
  // However, the object length encoding allows redundant values,
  // e.g. the 7-bit value [n] is the same as the 14- or 21-bit values [n, 0] or [n, 0, 0].
  // Instead, the offset encoding adds 1 to the value of each byte except the least significant one.
  // And just for kicks, the bytes are ordered from *most* to *least* significant.
  let mut value = 0;
  loop {
    let (byte_value, more_bytes) = read_varint_byte(stream)?;
    value = (value << VARINT_ENCODING_BITS) | byte_value as u64;
    if !more_bytes {
      return Ok(value)
    }

    value += 1;
  }
}

fn read_partial_int<R: Read>(
  stream: &mut R, bytes: u8, present_bytes: &mut u8
) -> io::Result<usize> {
  let mut value = 0;
  for byte_index in 0..bytes {
    if *present_bytes & 1 != 0 {
      let [byte] = read_bytes(stream)?;
      value |= (byte as usize) << (byte_index * 8);
    }
    *present_bytes >>= 1;
  }
  Ok(value)
}

fn seek(file: &mut File, offset: u64) -> io::Result<()> {
  file.seek(SeekFrom::Start(offset))?;
  Ok(())
}

fn get_offset(file: &mut File) -> io::Result<u64> {
  file.seek(SeekFrom::Current(0))
}

// Read a pack index file sequentially and assert that it is valid.
// This is not how git actually uses the index, but helpful to see its structure.
fn read_pack_index(file: &str) -> io::Result<()> {
  let mut file = File::open(Path::new(PACKS_DIRECTORY).join(file))?;

  // Check index header
  let magic = read_bytes(&mut file)?;
  assert_eq!(magic, *b"\xfftOc");
  let version = read_u32(&mut file)?;
  assert_eq!(version, 2);

  // For each of the 256 possible first bytes `b` of a hash,
  // read the cumulative number of objects with first byte <= `b`
  let mut cumulative_objects = [0; 1 << u8::BITS];
  for objects in &mut cumulative_objects {
    *objects = read_u32(&mut file)?;
  }

  // Read the hash of each of the objects.
  // Check that the hashes have the correct first byte and are sorted.
  let mut previous_objects = 0;
  for (first_byte, &objects) in cumulative_objects.iter().enumerate() {
    // The difference in the cumulative number of objects
    // is the number of objects with this first byte
    let mut previous_hash = None;
    for _ in 0..(objects - previous_objects) {
      // We already know the first byte of the hash, so ensure it matches
      let hash = read_hash(&mut file)?;
      assert_eq!(hash.0[0], first_byte as u8);
      if let Some(previous_hash) = previous_hash {
        assert!(hash > previous_hash);
      }
      previous_hash = Some(hash);
    }
    previous_objects = objects;
  }
  // `cumulative_objects[255]` is the total number of objects
  let total_objects = previous_objects;

  // Read a checksum of the packed data for each object
  for _ in 0..total_objects {
    let _crc32 = read_u32(&mut file)?;
  }

  // Read the offset of each object within the pack file
  let mut long_offsets = 0;
  for _ in 0..total_objects {
    let pack_offset = read_u32(&mut file)?;
    if pack_offset & LONG_OFFSET_FLAG != 0 {
      // If the most significant bit is set,
      // the offset is instead an index into the 64-bit offsets
      let offset_index = pack_offset & !LONG_OFFSET_FLAG;
      long_offsets = long_offsets.max(offset_index + 1);
    }
  }

  // Read the list of 64-bit offsets, if there are any
  for _ in 0..long_offsets {
    let _pack_offset = read_u64(&mut file)?;
  }

  // Read a SHA-1 checksum of the pack file and this index file
  let _pack_checksum: [_; HASH_BYTES] = read_bytes(&mut file)?;
  let _index_checksum: [_; HASH_BYTES] = read_bytes(&mut file)?;

  // We should be at the end of the index file
  let end = at_end_of_stream(&mut file)?;
  assert!(end);
  Ok(())
}

fn get_object_index_bounds(index_file: &mut File, hash: Hash)
  -> io::Result<(u32, u32)>
{
  // The previous cumulative object count is the lower bound (inclusive)
  let first_byte = hash.0[0];
  let index_lower_bound = if first_byte == 0 {
    seek(index_file, cumulative_objects_position(0))?;
    // There aren't any hashes with a lower first byte than 0
    0
  }
  else {
    seek(index_file, cumulative_objects_position(first_byte - 1))?;
    read_u32(index_file)?
  };
  // The next cumulative object count is the upper bound (exclusive)
  let index_upper_bound = read_u32(index_file)?;
  Ok((index_lower_bound, index_upper_bound))
}

fn get_object_index(index_file: &mut File, hash: Hash)
  -> io::Result<Option<u32>>
{
  use std::cmp::Ordering::*;

  // Track the range of possible indices for the object hash
  let (mut left_index, mut right_index) =
    get_object_index_bounds(index_file, hash)?;
  while left_index < right_index {
    // Compare with the object hash in the middle of the range
    let mid_index = left_index + (right_index - left_index) / 2;
    seek(index_file, hash_position(mid_index))?;
    let mid_hash = read_hash(index_file)?;
    match hash.cmp(&mid_hash) {
      Less => right_index = mid_index, // the object is to the left
      Equal => return Ok(Some(mid_index)), // we found the object
      Greater => left_index = mid_index + 1, // the object is to the right
    }
  }
  // If the range is empty, the object isn't in the index file
  Ok(None)
}

fn get_pack_offset_at_index(index_file: &mut File, object_index: u32)
  -> io::Result<u64>
{
  seek(index_file, TOTAL_OBJECTS_POSITION)?;
  let total_objects = read_u32(index_file)?;
  seek(index_file, offset_position(total_objects, object_index))?;
  let pack_offset = read_u32(index_file)?;
  if pack_offset & LONG_OFFSET_FLAG == 0 {
    // If the flag bit isn't set, the offset is just a 32-bit offset
    Ok(pack_offset as u64)
  }
  else {
    // If the flag bit is set, the rest of the offset
    // is an index into the 64-bit offsets
    let offset_index = pack_offset & !LONG_OFFSET_FLAG;
    seek(index_file, long_offset_position(total_objects, offset_index))?;
    read_u64(index_file)
  }
}

// Gets the offset of an object in a pack file.
// `pack` is the name of the pack file, without ".idx" or ".pack".
fn get_pack_offset(pack: &str, hash: Hash) -> io::Result<Option<u64>> {
  let path = Path::new(PACKS_DIRECTORY)
    .join(pack.to_string() + INDEX_FILE_SUFFIX);
  let mut file = File::open(path)?;
  let object_index = get_object_index(&mut file, hash)?;
  let object_index = match object_index {
    Some(object_index) => object_index,
    _ => return Ok(None),
  };

  let pack_offset = get_pack_offset_at_index(&mut file, object_index)?;
  Ok(Some(pack_offset))
}

// Reads the contents of a zlib stream from a file
// and ensures the decompressed contents have the correct size
fn read_zlib_stream(file: &mut File, size: usize) -> io::Result<Vec<u8>> {
  let offset = get_offset(file)?;
  let mut decompressed = ZlibDecoder::new(file);
  let mut contents = Vec::with_capacity(size);
  decompressed.read_to_end(&mut contents)?;
  // Reset the offset since ZlibDecoder uses BufReader,
  // which may consume extra bytes
  let zlib_end = offset + decompressed.total_in();
  seek(decompressed.into_inner(), zlib_end)?;
  if contents.len() != size {
    return Err(make_error("Incorrect decompressed size"))
  }

  Ok(contents)
}

// Read a pack file sequentially and compute its objects' contents.
// git only does this to construct the index file.
// Looking up an object then uses the index file to find its offset in the pack.
fn read_pack_file(file: &str) -> io::Result<()> {
  use ObjectType::*;

  let mut file = File::open(Path::new(PACKS_DIRECTORY).join(file))?;

  let magic = read_bytes(&mut file)?;
  assert_eq!(magic, *b"PACK");
  let version = read_u32(&mut file)?;
  assert_eq!(version, 2);
  let total_objects = read_u32(&mut file)?;

  // Map from offsets to the objects that were read
  let mut read_objects = HashMap::new();
  for _ in 0..total_objects {
    let offset = get_offset(&mut file)?;
    let (object_type, size) = read_type_and_size(&mut file)?;
    let object = match object_type {
      // Undeltified
      1..=4 => {
        let object_type = match object_type {
          1 => Commit,
          2 => Tree,
          3 => Blob,
          _ => Tag,
        };
        let contents = read_zlib_stream(&mut file, size)?;
        Object { object_type, contents }
      }
      // Offset delta
      6 => {
        let delta_offset = read_offset_encoding(&mut file)?;
        let base_offset = offset.checked_sub(delta_offset).unwrap();
        let delta_start = get_offset(&mut file)?;
        let object = apply_delta(&mut file, &read_objects[&base_offset])?;
        seek(&mut file, delta_start)?;
        read_zlib_stream(&mut file, size)?;
        object
      },
      // Hash delta
      7 => {
        let hash = read_hash(&mut file)?;
        let base_object = read_object(hash)?;
        let delta_start = get_offset(&mut file)?;
        let object = apply_delta(&mut file, &base_object)?;
        seek(&mut file, delta_start)?;
        read_zlib_stream(&mut file, size)?;
        object
      },
      _ => panic!("Unexpected object type {}", object_type),
    };
    read_objects.insert(offset, object);
  }

  // This checksum should match `_pack_checksum` in the index file
  let _pack_checksum: [_; HASH_BYTES] = read_bytes(&mut file)?;

  // We should be at the end of the pack file
  let end = at_end_of_stream(&mut file)?;
  assert!(end);
  Ok(())
}

fn apply_delta_instruction<R: Read>(
  stream: &mut R, base: &[u8], result: &mut Vec<u8>
) -> io::Result<bool> {
  // Check if the stream has ended, meaning the new object is done
  let instruction = match read_bytes(stream) {
    Ok([instruction]) => instruction,
    Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(false),
    Err(err) => return Err(err),
  };
  if instruction & COPY_INSTRUCTION_FLAG == 0 {
    // Data instruction; the instruction byte specifies the number of data bytes
    if instruction == 0 {
      // Appending 0 bytes doesn't make sense, so git disallows it
      return Err(make_error("Invalid data instruction"))
    }

    // Append the provided bytes
    let mut data = vec![0; instruction as usize];
    stream.read_exact(&mut data)?;
    result.extend_from_slice(&data);
  }
  else {
    // Copy instruction
    let mut nonzero_bytes = instruction;
    let offset =
      read_partial_int(stream, COPY_OFFSET_BYTES, &mut nonzero_bytes)?;
    let mut size =
      read_partial_int(stream, COPY_SIZE_BYTES, &mut nonzero_bytes)?;
    if size == 0 {
      // Copying 0 bytes doesn't make sense, so git assumes a different size
      size = COPY_ZERO_SIZE;
    }
    // Copy bytes from the base object
    let base_data = base.get(offset..(offset + size)).ok_or_else(|| {
      make_error("Invalid copy instruction")
    })?;
    result.extend_from_slice(base_data);
  }
  Ok(true)
}

fn apply_delta(pack_file: &mut File, base: &Object) -> io::Result<Object> {
  let Object { object_type, contents: ref base } = *base;
  let mut delta = ZlibDecoder::new(pack_file);
  let base_size = read_size_encoding(&mut delta)?;
  if base.len() != base_size {
    return Err(make_error("Incorrect base object length"))
  }

  let result_size = read_size_encoding(&mut delta)?;
  let mut result = Vec::with_capacity(result_size);
  while apply_delta_instruction(&mut delta, base, &mut result)? {}
  if result.len() != result_size {
    return Err(make_error("Incorrect object length"))
  }

  // The object type is the same as the base object
  Ok(Object { object_type, contents: result })
}

fn read_pack_object(pack_file: &mut File, offset: u64) -> io::Result<Object> {
  use ObjectType::*;
  use PackObjectType::*;

  seek(pack_file, offset)?;
  let (object_type, size) = read_type_and_size(pack_file)?;
  let object_type = match object_type {
    1 => Base(Commit),
    2 => Base(Tree),
    3 => Base(Blob),
    4 => Base(Tag),
    6 => OffsetDelta,
    7 => HashDelta,
    _ => {
      return Err(make_error(&format!("Invalid object type: {}", object_type)))
    }
  };
  match object_type {
    // Undeltified representation
    Base(object_type) => {
      let mut contents = Vec::with_capacity(size);
      ZlibDecoder::new(pack_file).read_to_end(&mut contents)?;
      if contents.len() != size {
        return Err(make_error("Incorrect object size"))
      }

      Ok(Object { object_type, contents })
    }
    // Deltified; base object is at an offset in the same packfile
    OffsetDelta => {
      let delta_offset = read_offset_encoding(pack_file)?;
      let base_offset = offset.checked_sub(delta_offset).ok_or_else(|| {
        make_error("Invalid OffsetDelta offset")
      })?;
      let offset = get_offset(pack_file)?;
      let base_object = read_pack_object(pack_file, base_offset)?;
      seek(pack_file, offset)?;
      apply_delta(pack_file, &base_object)
    }
    // Deltified; base object is given by a hash outside the packfile
    HashDelta => {
      let hash = read_hash(pack_file)?;
      let base_object = read_object(hash)?;
      apply_delta(pack_file, &base_object)
    }
  }
}

fn unpack_object(pack: &str, offset: u64) -> io::Result<Object> {
  let path = Path::new(PACKS_DIRECTORY)
    .join(pack.to_string() + PACK_FILE_SUFFIX);
  let mut file = File::open(path)?;
  read_pack_object(&mut file, offset)
}

fn strip_index_file_name(file_name: &OsStr) -> Option<&str> {
  let file_name = file_name.to_str()?;
  file_name.strip_suffix(INDEX_FILE_SUFFIX)
}

fn read_packed_object(hash: Hash) -> io::Result<Object> {
  for pack_or_index in fs::read_dir(PACKS_DIRECTORY)? {
    let pack_or_index = pack_or_index?;
    let file_name = pack_or_index.file_name();
    // Skip any files that aren't `.idx` files
    let pack = match strip_index_file_name(&file_name) {
      Some(pack) => pack,
      _ => continue,
    };

    // Hash may or may not exist in this packfile.
    // If not, try the other packfiles.
    let pack_offset = get_pack_offset(pack, hash)?;
    let pack_offset = match pack_offset {
      Some(pack_offset) => pack_offset,
      _ => continue,
    };

    // Object is found in this packfile; unpack it
    return unpack_object(pack, pack_offset)
  }
  Err(make_error(&format!("Object {} not found", hash)))
}

fn decimal_char_value(decimal_char: u8) -> Option<u8> {
  match decimal_char {
    b'0'..=b'9' => Some(decimal_char - b'0'),
    _ => None,
  }
}

fn parse_decimal(decimal_str: &[u8]) -> Option<usize> {
  let mut value = 0usize;
  for &decimal_char in decimal_str {
    let char_value = decimal_char_value(decimal_char)?;
    value = value.checked_mul(10)?;
    value = value.checked_add(char_value as usize)?;
  }
  Some(value)
}

fn read_unpacked_object(hash: Hash) -> io::Result<Object> {
  use ObjectType::*;

  let hex_hash = hash.to_string();
  let (directory_name, file_name) = hex_hash.split_at(2);
  let object_file = Path::new(OBJECTS_DIRECTORY)
    .join(directory_name)
    .join(file_name);
  let object_file = File::open(object_file)?;
  let mut object_stream = ZlibDecoder::new(object_file);
  let object_type = read_until_delimiter(&mut object_stream, b' ')?;
  let object_type = match &object_type[..] {
    COMMIT_OBJECT_TYPE => Commit,
    TREE_OBJECT_TYPE => Tree,
    BLOB_OBJECT_TYPE => Blob,
    TAG_OBJECT_TYPE => Tag,
    _ => {
      return Err(make_error(
        &format!("Invalid object type: {:?}", object_type)
      ))
    }
  };
  let size = read_until_delimiter(&mut object_stream, b'\0')?;
  let size = parse_decimal(&size).ok_or_else(|| {
    make_error(&format!("Invalid object size: {:?}", size))
  })?;
  let mut contents = Vec::with_capacity(size);
  object_stream.read_to_end(&mut contents)?;
  if contents.len() != size {
    return Err(make_error("Incorrect object size"))
  }

  Ok(Object { object_type, contents })
}

fn read_object(hash: Hash) -> io::Result<Object> {
  let object = match read_unpacked_object(hash) {
    // Found in objects directory
    Ok(object) => object,
    // Not found in objects directory; look in packfiles
    Err(err) if err.kind() == ErrorKind::NotFound => read_packed_object(hash)?,
    err => return err,
  };

  let object_hash = object.hash();
  if object_hash != hash {
    return Err(make_error(
      &format!("Object {} has wrong hash {}", hash, object_hash)
    ))
  }

  Ok(object)
}

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, hash] = <[String; 2]>::try_from(args).unwrap();
  let hash = Hash::from_str(&hash)?;
  let Object { object_type, contents } = read_object(hash)?;
  println!("Object type: {:?}", object_type);
  println!("{}", String::from_utf8_lossy(&contents));
  Ok(())
}
