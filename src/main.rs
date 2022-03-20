use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::rc::Rc;
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
const CHUNK_LENGTH_DIGITS: usize = 4;
// git reserves chunk lengths 65521 to 65535
const MAX_CHUNK_LENGTH: usize = 65520;
const BRANCH_REF_PREFIX: &str = "refs/heads/";
const SIDE_BAND_CAPABILITY: &str = "side-band-64k";
const REQUESTED_CAPABILITIES: &[&str] = &["ofs-delta", SIDE_BAND_CAPABILITY];
const CONFIG_FILE: &str = ".git/config";
// `r#` is handy for string literals with quotes
const REMOTE_ORIGIN_SECTION: &str = r#"[remote "origin"]"#;
const URL_PARAMETER: &str = "url";
const REMOTE_ORIGIN_REFS_DIRECTORY: &str = ".git/refs/remotes/origin";
const TEMP_PACK_FILE: &str = ".git/objects/pack/temp.pack";
const TEMP_INDEX_FILE: &str = ".git/objects/pack/idx.pack";

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

#[derive(Clone, Debug)]
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

// Call reader() to process a zlib stream from a file.
// Reset the file offset afterwards to the end of the zlib stream,
// since ZlibDecoder uses BufReader, which may consume extra bytes.
fn read_zlib_stream_exact<T, F>(file: &mut File, reader: F) -> io::Result<T>
  where F: FnOnce(&mut ZlibDecoder<&mut File>) -> io::Result<T>
{
  let offset = get_offset(file)?;
  let mut decompressed = ZlibDecoder::new(file);
  let result = reader(&mut decompressed);
  let zlib_end = offset + decompressed.total_in();
  seek(decompressed.into_inner(), zlib_end)?;
  result
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
  read_zlib_stream_exact(pack_file, |delta| {
    let base_size = read_size_encoding(delta)?;
    if base.len() != base_size {
      return Err(make_error("Incorrect base object length"))
    }

    let result_size = read_size_encoding(delta)?;
    let mut result = Vec::with_capacity(result_size);
    while apply_delta_instruction(delta, base, &mut result)? {}
    if result.len() != result_size {
      return Err(make_error("Incorrect object length"))
    }

    // The object type is the same as the base object
    Ok(Object { object_type, contents: result })
  })
}

// Cache of objects read from a pack file.
// This is necessary so that HashDelta objects can find their base object
// within a packfile while its index file is being build.
// It also optimizes reading a packfile by avoiding recomputing objects.
#[derive(Default)]
struct PackObjectCache {
  by_hash: HashMap<Hash, Rc<Object>>,
  by_offset: HashMap<u64, Rc<Object>>,
}

fn read_pack_object(
  pack_file: &mut File,
  offset: u64,
  cache: &mut PackObjectCache,
) -> io::Result<Rc<Object>> {
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
  let object = match object_type {
    // Undeltified representation
    Base(object_type) => {
      read_zlib_stream_exact(pack_file, |decompressed| {
        let mut contents = Vec::with_capacity(size);
        decompressed.read_to_end(&mut contents)?;
        if contents.len() != size {
          return Err(make_error("Incorrect object size"))
        }

        Ok(Object { object_type, contents })
      })
    }
    // Deltified; base object is at an offset in the same packfile
    OffsetDelta => {
      let delta_offset = read_offset_encoding(pack_file)?;
      let base_offset = offset.checked_sub(delta_offset).ok_or_else(|| {
        make_error("Invalid OffsetDelta offset")
      })?;
      let offset = get_offset(pack_file)?;
      let base_object =
        if let Some(object) = cache.by_offset.get(&base_offset) {
          Rc::clone(object)
        }
        else {
          read_pack_object(pack_file, base_offset, cache)?
        };
      seek(pack_file, offset)?;
      apply_delta(pack_file, &base_object)
    }
    // Deltified; base object is given by a hash outside the packfile
    HashDelta => {
      let hash = read_hash(pack_file)?;
      let object;
      let base_object =
        if let Some(object) = cache.by_hash.get(&hash) {
          object
        }
        else {
          object = read_object(hash)?;
          &object
        };
      apply_delta(pack_file, &base_object)
    }
  }?;
  let object = Rc::new(object);
  cache.by_hash.insert(object.hash(), Rc::clone(&object));
  cache.by_offset.insert(offset, Rc::clone(&object));
  Ok(object)
}

fn unpack_object(pack: &str, offset: u64) -> io::Result<Object> {
  let path = Path::new(PACKS_DIRECTORY)
    .join(pack.to_string() + PACK_FILE_SUFFIX);
  let mut file = File::open(path)?;
  let object = read_pack_object(
    &mut file,
    offset,
    &mut PackObjectCache::default(),
  )?;
  Ok(Object::clone(&object))
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

// A parsed .git/config file, represented as
// a map of section -> parameter -> value
#[derive(Debug)]
struct ConfigFile(HashMap<String, HashMap<String, String>>);

impl ConfigFile {
  fn read() -> io::Result<Self> {
    let config_file = File::open(CONFIG_FILE)?;
    let mut sections = HashMap::new();
    // The parameter values for the current section
    let mut parameters: Option<&mut HashMap<String, String>> = None;
    for line in BufReader::new(config_file).lines() {
      let line = line?;
      if let Some(parameter_line) = line.strip_prefix('\t') {
        // The line is indented, so it's a parameter in a section
        let (parameter, value) = parameter_line.split_once(" = ")
          .ok_or_else(|| {
            make_error(&format!("Invalid parameter line: {:?}", parameter_line))
          })?;
        // All parameters should be under a section
        let parameters = parameters.as_mut().ok_or_else(|| {
          make_error("Config parameter is not in a section")
        })?;
        parameters.insert(parameter.to_string(), value.to_string());
      }
      else {
        // The line starts a new section
        parameters = Some(sections.entry(line).or_default());
      }
    }
    Ok(ConfigFile(sections))
  }

  fn get_origin_url(&self) -> Option<&str> {
    let remote_origin_section = self.0.get(REMOTE_ORIGIN_SECTION)?;
    let url = remote_origin_section.get(URL_PARAMETER)?;
    Some(url)
  }
}

fn save_remote_ref(branch: &str, hash: Hash) -> io::Result<()> {
  let origin_ref_path = Path::new(REMOTE_ORIGIN_REFS_DIRECTORY).join(branch);
  fs::create_dir_all(origin_ref_path.parent().unwrap())?;
  let mut origin_ref_file = File::create(origin_ref_path)?;
  write!(origin_ref_file, "{}\n", hash)
}

// Creates a temporary pack index for the temporary packfile
// and returns the packfile's checksum
fn build_pack_index() -> io::Result<Hash> {
  let mut pack_file = File::open(TEMP_PACK_FILE)?;
  let magic = read_bytes(&mut pack_file)?;
  if magic != *b"PACK" {
    return Err(make_error("Invalid packfile"))
  }

  let version = read_u32(&mut pack_file)?;
  if version != 2 {
    return Err(make_error("Unexpected packfile version"))
  }

  let total_objects = read_u32(&mut pack_file)?;
  let mut object_cache = PackObjectCache::default();
  let mut first_byte_objects = [0u32; 1 << u8::BITS];
  let mut object_offsets = Vec::with_capacity(total_objects as usize);
  for _ in 0..total_objects {
    let offset = get_offset(&mut pack_file)?;
    let object = read_pack_object(&mut pack_file, offset, &mut object_cache)?;
    let object_hash = object.hash();
    first_byte_objects[object_hash.0[0] as usize] += 1;
    // Larger offsets would require a version-2 pack index
    let offset = u32::try_from(offset).map_err(|_| {
      make_error("Packfile is too large")
    })?;
    object_offsets.push((object_hash, offset));
  }
  let pack_checksum = read_hash(&mut pack_file)?;
  assert!(at_end_of_stream(&mut pack_file)?);

  // Create a version-1 pack index since it's simpler than version 2
  let mut index_file = File::create(TEMP_INDEX_FILE)?;
  let mut cumulative_objects = 0;
  for objects in first_byte_objects {
    cumulative_objects += objects;
    index_file.write_all(&cumulative_objects.to_be_bytes())?;
  }
  object_offsets.sort();
  for (hash, offset) in object_offsets {
    index_file.write_all(&offset.to_be_bytes())?;
    index_file.write_all(&hash.0)?;
  }
  index_file.write_all(&pack_checksum.0)?;
  // TODO: this should be a SHA-1 hash of the contents of the index file.
  // But git doesn't check it when reading the index file, so we'll skip it.
  index_file.write_all(&[0; HASH_BYTES])?;
  Ok(pack_checksum)
}

struct Refs {
  capabilities: HashSet<String>,
  // Map of ref name (e.g. "refs/heads/main") to commit hashes
  refs: HashMap<String, Hash>,
}

struct Transport {
  ssh_input: ChildStdin,
  ssh_output: ChildStdout,
}

impl Transport {
  fn connect(repository: &str) -> io::Result<Self> {
    // `repository` will look like "git@github.com:git/git.git".
    // "git@github.com" is the SSH login (user "git", hostname "github.com").
    // "git/git.git" specifies the repository to fetch on this server.
    let repository_pieces: Vec<_> = repository.split(':').collect();
    let [login, repository] = <[&str; 2]>::try_from(repository_pieces)
      .map_err(|_| {
        make_error(&format!("Invalid SSH repository: {}", repository))
      })?;
    // Start an SSH process to connect to this repository.
    // We don't wait for the `ssh` command to finish because we are going to
    // communicate back and forth with the server through its standard input and output.
    let mut ssh_process = Command::new("ssh")
      .args([login, "git-upload-pack", repository])
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .spawn()?;
    let ssh_input = ssh_process.stdin.take().ok_or_else(|| {
      make_error("Failed to open ssh stdin")
    })?;
    let ssh_output = ssh_process.stdout.take().ok_or_else(|| {
      make_error("Failed to open ssh stdout")
    })?;
    Ok(Transport { ssh_input, ssh_output })
  }

  fn read_chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
    // Chunks start with 4 hexadecimal digits indicating their length,
    // including the length digits
    let length_digits: [_; CHUNK_LENGTH_DIGITS] =
      read_bytes(&mut self.ssh_output)?;
    let chunk_length = length_digits.iter().try_fold(0, |value, &byte| {
      let char_value = hex_char_value(byte)?;
      Some(value << 4 | char_value as usize)
    }).ok_or_else(|| {
      make_error(&format!("Invalid chunk length: {:?}", length_digits))
    })?;
    // The chunk "0000" indicates the end of a sequence of chunks
    if chunk_length == 0 {
      return Ok(None)
    }

    let chunk_length = chunk_length.checked_sub(CHUNK_LENGTH_DIGITS)
      .ok_or_else(|| {
        make_error(&format!("Chunk length too short: {}", chunk_length))
      })?;
    let mut chunk = vec![0; chunk_length];
    self.ssh_output.read_exact(&mut chunk)?;
    Ok(Some(chunk))
  }

  fn read_text_chunk(&mut self) -> io::Result<Option<String>> {
    let chunk = self.read_chunk()?;
    let chunk = match chunk {
      Some(chunk) => chunk,
      _ => return Ok(None),
    };

    let mut text_chunk = String::from_utf8(chunk).map_err(|_| {
      make_error("Invalid text chunk")
    })?;
    // Text chunks should end with a newline character, but don't have to.
    // Remove it if it exists.
    if text_chunk.ends_with('\n') {
      text_chunk.pop();
    }
    Ok(Some(text_chunk))
  }

  fn write_text_chunk(&mut self, chunk: Option<&str>) -> io::Result<()> {
    let chunk_length = match chunk {
      // Includes the 4 hexadecimal digits at the start and the \n at the end
      Some(chunk) => CHUNK_LENGTH_DIGITS + chunk.len() + 1,
      _ => 0,
    };
    if chunk_length >= MAX_CHUNK_LENGTH {
      return Err(make_error("Chunk is too large"))
    }

    write!(self.ssh_input, "{:04x}", chunk_length)?;
    if let Some(chunk) = chunk {
      write!(self.ssh_input, "{}\n", chunk)?;
    }
    Ok(())
  }

  fn receive_refs(&mut self) -> io::Result<Refs> {
    let head_chunk = match self.read_text_chunk()? {
      Some(chunk) => chunk,
      _ => return Err(make_error("No chunk received from server")),
    };

    let (head_ref, capabilities) = head_chunk.split_once('\0').ok_or_else(|| {
      make_error("Invalid capabilities chunk")
    })?;
    let capabilities = capabilities.split(' ').map(str::to_string).collect();
    let mut refs = HashMap::new();
    let mut add_ref = |chunk: &str| -> io::Result<()> {
      let (hash, ref_name) = chunk.split_once(' ').ok_or_else(|| {
        make_error("Invalid ref chunk")
      })?;
      let hash = Hash::from_str(hash)?;
      refs.insert(ref_name.to_string(), hash);
      Ok(())
    };
    add_ref(head_ref)?;
    while let Some(chunk) = self.read_text_chunk()? {
      add_ref(&chunk)?;
    }
    Ok(Refs { capabilities, refs })
  }

  fn send_wants(&mut self, hashes: &[Hash], capabilities: &[&str])
    -> io::Result<()>
  {
    let mut first_want = true;
    for hash in hashes {
      let mut chunk = format!("want {}", hash);
      if first_want {
        // Only the first want should list capabilities
        for capability in capabilities {
          chunk.push(' ');
          chunk += capability;
        }
      }
      self.write_text_chunk(Some(&chunk))?;
      first_want = false;
    }
    self.write_text_chunk(None)
  }

  // Sends haves for all refs under the given ref directory
  fn send_haves_dir(&mut self, ref_path: &mut PathBuf) -> io::Result<()> {
    let entries = fs::read_dir(&ref_path);
    if let Err(err) = &entries {
      if err.kind() == ErrorKind::NotFound {
        // If .git/refs/remotes/origin doesn't exist, there are no haves
        return Ok(())
      }
    }

    for entry in entries? {
      let entry = entry?;
      ref_path.push(entry.file_name());
      let entry_type = entry.file_type()?;
      if entry_type.is_dir() {
        // Explore subdirectories recursively (to find refs containing '/')
        self.send_haves_dir(ref_path)?;
      }
      else {
        let hash = fs::read_to_string(&ref_path)?;
        let hash = Hash::from_str(hash.trim_end())?;
        self.write_text_chunk(Some(&format!("have {}", hash)))?;
      }
      ref_path.pop();
    }
    Ok(())
  }

  fn send_haves(&mut self) -> io::Result<()> {
    fn valid_have_response(response: Option<&str>) -> bool {
      // Expect "ACK {HASH}" if acknowledged, "NAK" otherwise
      match response {
        Some("NAK") => true,
        Some(response) => {
          match response.strip_prefix("ACK ") {
            Some(hash) => Hash::from_str(hash).is_ok(),
            _ => false,
          }
        }
        _ => false,
      }
    }

    // Send haves for all the most recent commits we have fetched
    self.send_haves_dir(&mut PathBuf::from(REMOTE_ORIGIN_REFS_DIRECTORY))?;
    self.write_text_chunk(Some("done"))?;
    let response = self.read_text_chunk()?;
    if !valid_have_response(response.as_deref()) {
      return Err(make_error("Invalid ACK/NAK"))
    }

    Ok(())
  }

  fn receive_side_band_pack(&mut self, pack_file: &mut File) -> io::Result<()> {
    while let Some(chunk) = self.read_chunk()? {
      let (&chunk_type, chunk) = chunk.split_first().ok_or_else(|| {
        make_error("Missing side-band chunk type")
      })?;
      match chunk_type {
        1 => pack_file.write_all(chunk)?,
        2 => io::stderr().write_all(chunk)?,
        3 => {
          let err = format!("Fetch error: {}", String::from_utf8_lossy(chunk));
          return Err(make_error(&err))
        }
        _ => {
          let err = format!("Invalid side-band chunk type {}", chunk_type);
          return Err(make_error(&err))
        }
      }
    }
    Ok(())
  }

  fn fetch(&mut self) -> io::Result<()> {
    let Refs { capabilities, refs } = self.receive_refs()?;
    // Request all the capabilities that we want and the server supports
    let use_capabilities: Vec<_> = REQUESTED_CAPABILITIES.iter()
      .copied()
      .filter(|&capability| capabilities.contains(capability))
      .collect();
    // Request all refs corresponding to branches
    // (not tags, pull requests, etc.)
    let branch_refs: Vec<_> = refs.iter()
      .filter_map(|(ref_name, &hash)| {
        ref_name.strip_prefix(BRANCH_REF_PREFIX).map(|branch| (branch, hash))
      })
      .collect();
    let wants: Vec<_> = branch_refs.iter().map(|&(_, hash)| hash).collect();
    self.send_wants(&wants, &use_capabilities)?;

    self.send_haves()?;

    let mut pack_file = File::create(TEMP_PACK_FILE)?;
    if capabilities.contains(SIDE_BAND_CAPABILITY) {
      self.receive_side_band_pack(&mut pack_file)?;
    }
    else {
      io::copy(&mut self.ssh_output, &mut pack_file)?;
    }
    let pack_hash = build_pack_index()?;
    let pack_file_name = Path::new(PACKS_DIRECTORY)
      .join(format!("pack-{}{}", pack_hash, PACK_FILE_SUFFIX));
    fs::rename(TEMP_PACK_FILE, pack_file_name)?;
    let index_file_name = Path::new(PACKS_DIRECTORY)
      .join(format!("pack-{}{}", pack_hash, INDEX_FILE_SUFFIX));
    fs::rename(TEMP_INDEX_FILE, index_file_name)?;

    for (branch, hash) in branch_refs {
      save_remote_ref(branch, hash)?;
    }
    Ok(())
  }
}

fn main() -> io::Result<()> {
  let config = ConfigFile::read()?;
  let origin_url = config.get_origin_url().ok_or_else(|| {
    make_error("Missing remote 'origin'")
  })?;
  let mut transport = Transport::connect(origin_url)?;
  transport.fetch()
}
