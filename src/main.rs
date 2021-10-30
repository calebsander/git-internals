use std::env;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{self, Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::{self, FromStr};
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

const HASH_BYTES: usize = 20;
const HEAD_FILE: &str = ".git/HEAD";
const BRANCH_REFS_DIRECTORY: &str = ".git/refs/heads";
const REF_PREFIX: &str = "ref: refs/heads/";
const OBJECTS_DIRECTORY: &str = ".git/objects";
const COMMIT_HEADER: &[u8] = b"commit ";
const TREE_LINE_PREFIX: &[u8] = b"tree ";
const PARENT_LINE_PREFIX: &[u8] = b"parent ";
const AUTHOR_LINE_PREFIX: &[u8] = b"author ";
const COMMITTER_LINE_PREFIX: &[u8] = b"committer ";
const TREE_HEADER: &[u8] = b"tree ";
const BLOB_HEADER: &[u8] = b"blob ";
const EMPTY_FILE: &str = "/dev/null";
const DIFF_LEFT_FILE: &str = ".git/a";
const DIFF_RIGHT_FILE: &str = ".git/b";

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
      Error::new(ErrorKind::Other, format!("Invalid hash: {}", hex_hash))
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

enum Head {
  Commit(Hash),
  Branch(String),
}

impl Head {
  fn get_hash(&self) -> io::Result<Hash> {
    use Head::*;

    match self {
      Commit(hash) => Ok(*hash),
      Branch(branch) => {
        let ref_file = Path::new(BRANCH_REFS_DIRECTORY).join(branch);
        let hash_contents = fs::read_to_string(ref_file)?;
        Hash::from_str(hash_contents.trim_end())
      }
    }
  }
}

fn get_head() -> io::Result<Head> {
  use Head::*;

  let hash_contents = fs::read_to_string(HEAD_FILE)?;
  let hash_contents = hash_contents.trim_end();
  Ok(match hash_contents.strip_prefix(REF_PREFIX) {
    Some(branch) => Branch(branch.to_string()),
    _ => {
      let hash = Hash::from_str(hash_contents)?;
      Commit(hash)
    }
  })
}

fn read_object(hash: Hash) -> io::Result<Vec<u8>> {
  let hex_hash = hash.to_string();
  let (directory_name, file_name) = hex_hash.split_at(2);
  let object_file = Path::new(OBJECTS_DIRECTORY)
    .join(directory_name)
    .join(file_name);
  let object_file = File::open(object_file)?;
  let mut contents = vec![];
  ZlibDecoder::new(object_file).read_to_end(&mut contents)?;
  let contents_hash = Sha1::digest(&contents);
  if contents_hash.as_slice() != hash.0 {
    return Err(Error::new(
      ErrorKind::Other,
      format!("Object {} has wrong hash {:x}", hash, contents_hash),
    ))
  }

  Ok(contents)
}

fn decimal_char_value(decimal_char: u8) -> Option<u8> {
  match decimal_char {
    b'0'..=b'9' => Some(decimal_char - b'0'),
    _ => None,
  }
}

// Parses a decimal string, e.g. "123", into its value, e.g. 123.
// Returns None if any characters are invalid or the value overflows a usize.
fn parse_decimal(decimal_str: &[u8]) -> Option<usize> {
  let mut value = 0usize;
  for &decimal_char in decimal_str {
    let char_value = decimal_char_value(decimal_char)?;
    value = value.checked_mul(10)?;
    value = value.checked_add(char_value as usize)?;
  }
  Some(value)
}

// Like str::split_once(), except for slices
fn split_once<T: PartialEq>(slice: &[T], delimiter: T) -> Option<(&[T], &[T])> {
  let index = slice.iter().position(|element| *element == delimiter)?;
  Some((&slice[..index], &slice[index + 1..]))
}

// Checks that an object's header has the expected type, e.g. "commit ",
// and the object size is correct
fn check_header<'a>(object: &'a [u8], header: &[u8]) -> Option<&'a [u8]> {
  let object = object.strip_prefix(header)?;
  let (size, object) = split_once(object, b'\0')?;
  let size = parse_decimal(size)?;
  if object.len() != size {
    return None
  }

  Some(object)
}

#[derive(Debug)]
struct Commit {
  tree: Hash,
  parents: Vec<Hash>,
  author: String, // name, email, and timestamp (not parsed)
  committer: String, // same contents as `author`
  message: String, // includes commit description
}

fn parse_commit(object: &[u8]) -> Option<Commit> {
  let object = check_header(object, COMMIT_HEADER)?;

  let object = object.strip_prefix(TREE_LINE_PREFIX)?;
  let (tree, mut object) = split_once(object, b'\n')?;
  let tree = hex_to_hash(tree)?;

  let mut parents = vec![];
  while let Some(object_rest) = object.strip_prefix(PARENT_LINE_PREFIX) {
    let (parent, object_rest) = split_once(object_rest, b'\n')?;
    let parent = hex_to_hash(parent)?;
    parents.push(parent);
    object = object_rest;
  }

  let object = object.strip_prefix(AUTHOR_LINE_PREFIX)?;
  let (author, object) = split_once(object, b'\n')?;
  let author = String::from_utf8(author.to_vec()).ok()?;

  let object = object.strip_prefix(COMMITTER_LINE_PREFIX)?;
  let (committer, object) = split_once(object, b'\n')?;
  let committer = String::from_utf8(committer.to_vec()).ok()?;

  let object = object.strip_prefix(b"\n")?;
  let message = String::from_utf8(object.to_vec()).ok()?;

  Some(Commit { tree, parents, author, committer, message })
}

fn read_commit(hash: Hash) -> io::Result<Commit> {
  let object = read_object(hash)?;
  parse_commit(&object).ok_or_else(|| {
    Error::new(ErrorKind::Other, format!("Malformed commit object: {}", hash))
  })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
  Directory,
  File,
  // We'll ignore other modes for now
}

#[derive(Debug)]
struct TreeEntry {
  mode: Mode,
  name: String,
  hash: Hash,
}

#[derive(Debug)]
struct Tree(Vec<TreeEntry>);

fn parse_tree(object: &[u8]) -> Option<Tree> {
  let mut object = check_header(object, TREE_HEADER)?;
  let mut entries = vec![];
  while !object.is_empty() {
    let (mode, object_rest) = split_once(object, b' ')?;
    let mode = match mode {
      b"40000" => Mode::Directory,
      b"100644" => Mode::File,
      _ => return None,
    };

    let (name, object_rest) = split_once(object_rest, b'\0')?;
    let name = String::from_utf8(name.to_vec()).ok()?;

    let hash = object_rest.get(..HASH_BYTES)?;
    let hash = Hash(*<&[u8; HASH_BYTES]>::try_from(hash).unwrap());
    object = &object_rest[HASH_BYTES..];

    entries.push(TreeEntry { mode, name, hash });
  }
  Some(Tree(entries))
}

fn read_tree(hash: Hash) -> io::Result<Tree> {
  let object = read_object(hash)?;
  parse_tree(&object).ok_or_else(|| {
    Error::new(ErrorKind::Other, format!("Malformed tree object: {}", hash))
  })
}

#[derive(Debug)]
struct Blob(Vec<u8>);

fn read_blob(hash: Hash) -> io::Result<Blob> {
  let object = read_object(hash)?;
  let bytes = check_header(&object, BLOB_HEADER).ok_or_else(|| {
    Error::new(ErrorKind::Other, format!("Malformed blob object: {}", hash))
  })?;
  Ok(Blob(bytes.to_vec()))
}

// Prints the diff between two blobs with the given filename
fn diff_blob(path: &Path, blob1: Option<Hash>, blob2: Option<Hash>)
  -> io::Result<()>
{
  // If the hashes match, the blob objects are the same
  if blob1 == blob2 {
    return Ok(())
  }

  // We will store each blob's contents in a temporary file,
  // so print the real filename of the blobs
  println!("{}", path.display());
  // If either blob is missing, compare an empty file instead
  let filename1 = match blob1 {
    Some(blob) => {
      let blob = read_blob(blob)?;
      fs::write(DIFF_LEFT_FILE, blob.0)?;
      DIFF_LEFT_FILE
    }
    _ => EMPTY_FILE,
  };
  let filename2 = match blob2 {
    Some(blob) => {
      let blob = read_blob(blob)?;
      fs::write(DIFF_RIGHT_FILE, blob.0)?;
      DIFF_RIGHT_FILE
    }
    _ => EMPTY_FILE,
  };
  // Run `diff -u FILENAME1 FILENAME2` to produce a git-like diff
  Command::new("diff").args(&["-u", filename1, filename2]).status()?;
  Ok(())
}

// Reads a tree if a tree hash is given, or simulates an empty tree
fn read_optional_tree(hash: Option<Hash>) -> io::Result<Tree> {
  match hash {
    Some(hash) => read_tree(hash),
    // If the tree doesn't exist, pretend it's empty
    _ => Ok(Tree(vec![])),
  }
}

// Prints the diffs of all files under two trees with the given filename
fn diff_tree(path: &mut PathBuf, tree1: Option<Hash>, tree2: Option<Hash>)
  -> io::Result<()>
{
  use std::cmp::Ordering::*;

  // If the hashes match, the tree objects are the same
  if tree1 == tree2 {
    return Ok(())
  }

  let tree1 = read_optional_tree(tree1)?;
  let tree2 = read_optional_tree(tree2)?;

  // Since the entries are sorted by name, we can merge them together
  let mut entries_left1 = tree1.0.as_slice();
  let mut entries_left2 = tree2.0.as_slice();
  while let (Some((entry1, entries_rest1)), Some((entry2, entries_rest2))) =
    (entries_left1.split_first(), entries_left2.split_first())
  {
    match entry1.name.cmp(&entry2.name) {
      // Only compare the entries if they are both files or both directories.
      // Otherwise, treat them as separate entries.
      Equal if entry1.mode == entry2.mode => {
        diff_entry(path, Some(entry1), Some(entry2))?;
        entries_left1 = entries_rest1;
        entries_left2 = entries_rest2;
      }
      // The entry only exists in the left tree, so it was deleted
      Less | Equal => {
        diff_entry(path, Some(entry1), None)?;
        entries_left1 = entries_rest1;
      }
      // The entry only exists in the right tree, so it was added
      Greater => {
        diff_entry(path, None, Some(entry2))?;
        entries_left2 = entries_rest2;
      }
    }
  }
  // Process any remaining entries after one of the trees is finished
  for entry in entries_left1 {
    diff_entry(path, Some(entry), None)?;
  }
  for entry in entries_left2 {
    diff_entry(path, None, Some(entry))?;
  }
  Ok(())
}

// Prints the diff under two tree entries, which may be blobs or trees
fn diff_entry(
  path: &mut PathBuf,
  entry1: Option<&TreeEntry>,
  entry2: Option<&TreeEntry>,
) -> io::Result<()> {
  use Mode::*;

  // At least one of the entries must be provided.
  // If both are provided, they must have the same name and mode.
  let entry = entry1.or(entry2).unwrap();
  let hash1 = entry1.map(|entry| entry.hash);
  let hash2 = entry2.map(|entry| entry.hash);
  // Append the name to the path, e.g. "dir1/dir2" becomes "dir1/dir2/file"
  path.push(&entry.name);
  match entry.mode {
    File => diff_blob(path, hash1, hash2)?,
    Directory => diff_tree(path, hash1, hash2)?,
  }
  // Reset the path
  path.pop();
  Ok(())
}

// This program works like `git diff COMMIT1 COMMIT2`,
// where COMMIT1 and COMMIT2 are full commit hashes
fn main() -> io::Result<()> {
  // Read 2 commit hashes from the command-line arguments
  let args: Vec<_> = env::args().collect();
  let [_, commit1, commit2] = <[String; 3]>::try_from(args).map_err(|args| {
    Error::new(ErrorKind::Other, format!("Usage: {} COMMIT1 COMMIT2", args[0]))
  })?;
  let commit1 = Hash::from_str(&commit1)?;
  let commit2 = Hash::from_str(&commit2)?;

  // Diff the trees corresponding to the commits
  let commit1 = read_commit(commit1)?;
  let commit2 = read_commit(commit2)?;
  diff_tree(&mut PathBuf::new(), Some(commit1.tree), Some(commit2.tree))?;
  // Remove the temporary files we might have created
  let _ = fs::remove_file(DIFF_LEFT_FILE);
  let _ = fs::remove_file(DIFF_RIGHT_FILE);
  Ok(())
}
