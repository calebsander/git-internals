# Git Internals part 2: packfiles

This post continues the "Git Internals" series.
In [part 1](https://dev.to/calebsander/git-internals-part-1-the-git-object-model-474m), we introduced git's object storage model.
This post will look at object storage in more depth, so I recommend looking at that post first if you haven't already.

[First](#a-convenient-lie), we'll see that git usually does *not* store objects the way we saw last time.
We'll introduce the "packfile", which is what git uses instead.

Then, we'll look at the two parts of a packfile: the `.idx` and `.pack` files.
Since git uses the `.idx` file to access the `.pack` file, [we'll examine the `.idx` file](#packfile-indices) first.
Then [we'll dig into the `.pack` file](#reading-an-object-from-a-packfile) to understand how git can store objects more efficiently by "packing" them together.
The design of the `.pack` file is much more interesting, so I recommend skipping past the `.idx` discussion to the `.pack` section if your time is limited.

The source code for this post can be found [here](https://github.com/calebsander/git-internals/tree/part2).

## A convenient lie

In the last post, we saw that git objects (including commits, trees, and blobs) are stored in the `.git/objects` directory.
So let's clone a repository and look at its objects:
```
$ git clone git@github.com:git/git.git
$ cd git
$ ls -R .git/objects
info pack

.git/objects/info:

.git/objects/pack:
pack-d851c0ab72a0034ab858061940ed04abebe20d32.idx
pack-d851c0ab72a0034ab858061940ed04abebe20d32.pack
```
What happened to all the object files?!

Given the title of this post, you might guess that the files in the `.git/objects/pack` directory have something to do with it.
We can test this hypothesis by temporarily moving the packfiles:
```bash
$ git show # successfully displays the current commit
$ mv .git/objects/pack/* . # move the pack-* files out of the .git directory
$ git show
fatal: bad object HEAD
```
So all the objects must be stored somehow in the `.idx` or `.pack` file.
If we look at their sizes, we can see that the `.pack` file is about 20 times larger (174 vs 8.5 MB), so it looks like that's where the objects are:
```
ls -lh .git/objects/pack/*
-r--r--r--  1 csander  staff   8.5M Nov 11 20:17 .git/objects/pack/pack-d851c0ab72a0034ab858061940ed04abebe20d32.idx
-r--r--r--  1 csander  staff   174M Nov 11 20:17 .git/objects/pack/pack-d851c0ab72a0034ab858061940ed04abebe20d32.pack
```
The corresponding `.idx` ("index") file doesn't contain any additional information; it is generated from the `.pack` file.
However, git is also unable to read objects if the `.idx` file is moved.
This suggests that the `.idx` file is needed to find the objects within the `.pack` file.

## Why packfiles?

The convenient lie from the last post was that each object is stored as an individual file.
While git does store *new* objects like this, git may combine multiple objects into a packfile to reduce storage space.

In its simplest form, a packfile is essentially the concatenation of (compressed) object files.
This makes it easier to transfer many objects during a git push or pull (more accurately, a fetch).
However, the real benefit of a packfile is that it can store objects as diffs ("deltas") from other objects.
As mentioned in the last post, git tends to create many similar objects, such as the new blob created when making a small change to a file.
Whereas storing objects individually would require storing each entire blob, a packfile can store just one of the blobs and express the other as a delta from the first.

git generates packfiles in two main cases:
- Transferring objects during a push or pull.
  For the common git protocols, communicating with a remote repository always involves sending a packfile.
  We'll look at git transports in detail in the next post.
- Periodic "garbage collection" of the `.git/objects` folder.
  If git decides there are too many individual objects, it combines them into a packfile to reduce the repository's size on disk.

## What's in a packfile?

Unfortunately, unlike individual object files, `.pack` and `.idx` file formats are neither straightforward nor human-readable.
The best description of how they work is the `Documentation/technical/pack-format.txt` file within the git source code, rendered [here](https://git-scm.com/docs/pack-format).
We'll implement the specification, which will require filling in a few details where the documentation is vague.
The `.idx` (packfile index) file is what git reads first to find an object within a packfile, so we'll start with it.

## Packfile indices

The goal of a packfile index is to take an object hash (e.g. `4d53e91c6b2c3f5b5c7375e579a453fc5053c08b`) and efficiently locate it in a packfile.
This is important to ensure that reading objects from packfiles isn't too much slower than reading them from the `.git/objects` directory (the approach we covered in the last post).
Since an object could be located anywhere within a many-MB packfile, the `.idx` file acts as a map from hashes to positions within the packfile.

So, if we want to find an object, we first check the `.git/objects` directory for an unpacked object file (e.g. `.git/objects/4d/53e91c6b2c3f5b5c7375e579a453fc5053c08b`).
If it isn't unpacked, we look through each packfile index until we find the packfile containing the object.

### The index header

The packfile index starts with the magic bytes `[0xff, b't', b'O', b'c']` ("table of contents"?).
This is followed by the version number 2, stored as a big-endian 32-bit integer (i.e. the bytes `[0, 0, 0, 2]`).
(There is a version 1 format as well, but we will ignore it since git no longer creates it.)
We'll start by asserting that the index file has the correct header:
```rust
use std::fs::File;
use std::io::{self, Read};

const PACKS_DIRECTORY: &str = ".git/objects/pack";

// Reads a fixed number of bytes from a stream.
// Rust's "const generics" make this function very useful.
fn read_bytes<R: Read, const N: usize>(stream: &mut R)
  -> io::Result<[u8; N]>
{
  let mut bytes = [0; N];
  stream.read_exact(&mut bytes)?;
  Ok(bytes)
}

// Reads a big-endian 32-bit (4-byte) integer from a stream
fn read_u32<R: Read>(stream: &mut R) -> io::Result<u32> {
  let bytes = read_bytes(stream)?;
  Ok(u32::from_be_bytes(bytes))
}

fn read_pack_index(file: &str) -> io::Result<()> {
  let mut file = File::open(Path::new(PACKS_DIRECTORY).join(file))?;

  // Check index header
  let magic = read_bytes(&mut file)?;
  assert_eq!(magic, *b"\xfftOc");
  let version = read_u32(&mut file)?;
  assert_eq!(version, 2);

  // TODO: read the rest of the index
}

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, index_file] = <[String; 2]>::try_from(args).unwrap();
  read_pack_index(&index_file)
}
```
And it runs successfully:
```
$ cd git
$ cargo run pack-d851c0ab72a0034ab858061940ed04abebe20d32.idx
```

### The list of hashes

Recall that the index file acts as a map from object hashes to offsets within the pack.
It's structured much like a hash map (no pun intended).
The hash map has 256 buckets, and the first byte of an object's hash determines which one it falls into.
Then, since multiple hashes can have the same first byte, each bucket contains a list of all the hashes with that first byte.
The hashes in each bucket are pre-sorted so a hash can be quickly found within its bucket using a binary search.
(Since the buckets are ordered by the first byte of the hash, this means that *all* the hashes in the index file are in sorted order.)

```rust
// Copied from the last post
struct Hash([u8; HASH_BYTES]);

// Read an object hash from a stream
fn read_hash<R: Read>(stream: &mut R) -> io::Result<Hash> {
  let bytes = read_bytes(stream)?;
  Ok(Hash(bytes))
}

fn read_pack_index(file: &str) -> io::Result<()> {
  // ...

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

  // TODO: read the rest of the index
}
```

### The object offsets

Now we've read all the object hashes, but we still haven't figured out where the objects are in the packfile.

Following the list of objects, there are two more lists.
These lists both have with one element corresponding to every object.
First is a list of checksums (specifically, CRC-32s) of the packed objects.
These aren't necessary to read the objects, so we'll ignore them.
Then, there is the list of positions of the objects within the packfile.
For example, if an object's packed data starts at byte 1234 of the packfile, the 32-bit integer 1234 would be stored in this list.

```rust
fn read_pack_index(file: &str) -> io::Result<()> {
  // ...

  // Read a checksum of the packed data for each object
  for _ in 0..total_objects {
    let _crc32 = read_u32(&mut file)?;
  }

  // Read the offset of each object within the packfile
  for _ in 0..total_objects {
    let _pack_offset = read_u32(&mut file)?;
    // TODO: there's one more step needed to read large pack offsets
  }
}
```

And this is all we need to read our example `.idx` file!
However, storing each pack offset as a 32-bit integer means we can't represent an offset into a packfile larger than 2<sup>32</sup> bytes (4 GB).
(This limitation with version 1 index files is the reason for version 2.)
The index file could support larger packfiles by storing the offset as a 64-bit integer, but this would waste space for the vast majority of packfiles.

Instead, the most significant bit of the 32-bit pack offset indicates whether a 64-bit offset is needed.
If it is set, the value is instead an index into a list of 64-bit offsets directly after the 32-bit offsets:
```rust
// The most significant bit of a 32-bit integer
const LONG_OFFSET_FLAG: u32 = 1 << 31;

// Just like read_u32(), except reads a 64-bit integer
fn read_u64<R: Read>(stream: &mut R) -> io::Result<u64> {
  let bytes = read_bytes(stream)?;
  Ok(u64::from_be_bytes(bytes))
}

fn read_pack_index(file: &str) -> io::Result<()> {
  // ...

  // Read the offset of each object within the packfile
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
}
```

### Looking up an object offset

Now we've seen how the pack index is laid out by reading it sequentially.
But this isn't how the pack index is read.
It's instead designed to efficiently take an object hash and determine its offset in the packfile.
Keep an eye on how few reads this process requires.

First, we use two consecutive entries in `cumulative_objects` to get bounds on the index of an object within the index file.
(Sorry about the overloaded term "index". I'll use "index" to refer to the location of the object in the sorted list of objects and "index file" to refer to the `.idx` file.)
```rust
use std::io::{Seek, SeekFrom};

const fn cumulative_objects_position(first_byte: u8) -> u64 {
  // Skip the magic bytes, version number,
  // and previous cumulative object counts
  4 + 4 + first_byte as u64 * 4
}

fn seek(file: &mut File, offset: u64) -> io::Result<()> {
  file.seek(SeekFrom::Start(offset))?;
  Ok(())
}

// Gets lower and upper bounds on the index of an object hash
// in an index file, using the cumulative object counts
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
```

Then, to actually find the object's index, we perform a binary search between these index bounds:
```rust
const TOTAL_OBJECTS_POSITION: u64 = cumulative_objects_position(u8::MAX);
fn hash_position(object_index: u32) -> u64 {
  // Skip the cumulative object counts and the previous hashes
  TOTAL_OBJECTS_POSITION + 4 + object_index as u64 * HASH_BYTES as u64
}

fn get_object_index(index_file: &mut File, hash: Hash)
  -> io::Result<Option<u32>>
{
  use std::cmp::Ordering::*;

  // Track the range of possible indices for the object hash.
  // (left_index is inclusive, right_index is exclusive)
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
```

Finally, we use the object's index to read its offset from the offset list.
(Note that we need to read the total number of objects so we can calculate where the offset list starts.)
If the offset is a long offset, we need one more read.
```rust
fn crc32_position(total_objects: u32, object_index: u32) -> u64 {
  // Skip the hashes and previous CRC-32s
  hash_position(total_objects) + object_index as u64 * 4
}
fn offset_position(total_objects: u32, object_index: u32) -> u64 {
  // Skip the CRC-32s and previous object offsets
  crc32_position(total_objects, total_objects) + object_index as u64 * 4
}
fn long_offset_position(total_objects: u32, offset_index: u32) -> u64 {
  // Skip the short object offsets and previous long object offsets
  offset_position(total_objects, total_objects) + offset_index as u64 * 8
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
```

Combining these functions, we can use an index file to find an object in the corresponding pack file:
```rust
// Gets the offset of an object in a packfile.
// `pack` is the name of the packfile, without ".idx" or ".pack".
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

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, pack, object] = <[String; 3]>::try_from(args).unwrap();
  let offset = get_pack_offset(&pack, Hash::from_str(&object).unwrap())?;
  println!("{:?}", offset);
  Ok(())
}
```
Looking up a real object shows its offset in the pack, and looking up a fake object shows it's not in the pack:
```
$ cargo run pack-d851c0ab72a0034ab858061940ed04abebe20d32 4d53e91c6b2c3f5b5c7375e579a453fc5053c08b
Some(3827)
$ cargo run pack-d851c0ab72a0034ab858061940ed04abebe20d32 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
None
```

## Reading an object from a packfile

After the `.idx` file tells us where an object is located in a packfile, we need to actually read it from there.

The packfile data for an object (much like an unpacked object) starts with its type and size.
However, where an unpacked object would have a header like `"commit 189\u{0}"`, the packed object only needs 2 bytes for this information.
As in several other places in packfiles, git stores the type and length as a variable-length integer.
Variable-length integers allow arbitrarily large values, while using few bytes in the common case of small values.
(This is very similar to how [UTF-8](https://en.wikipedia.org/wiki/UTF-8) works.)

Specifically, git uses the upper bit of each byte to indicate whether there are additional bytes and the remaining 7 bits as data.
For example, the bytes `[0b1xxxxxxx, 0b1yyyyyyy, 0b0zzzzzzz]` represent the integer `0bzzzzzzzyyyyyyyxxxxxxx`.
Note that values 0 to 127 only require a single byte `0b0xxxxxxx`.

```rust
// Each byte contributes 7 bits of data
const VARINT_ENCODING_BITS: u8 = 7;
// The upper bit indicates whether there are more bytes
const VARINT_CONTINUE_FLAG: u8 = 1 << VARINT_ENCODING_BITS;

// Read 7 bits of data and a flag indicating whether there are more
fn read_varint_byte<R: Read>(stream: &mut R) -> io::Result<(u8, bool)> {
  let [byte] = read_bytes(stream)?;
  let value = byte & !VARINT_CONTINUE_FLAG;
  let more_bytes = byte & VARINT_CONTINUE_FLAG != 0;
  Ok((value, more_bytes))
}

// Read a "size encoding" variable-length integer.
// (There's another slightly different variable-length format
// called the "offset encoding".)
fn read_size_encoding<R: Read>(stream: &mut R) -> io::Result<usize> {
  let mut value = 0;
  let mut length = 0; // the number of bits of data read so far
  loop {
    let (byte_value, more_bytes) = read_varint_byte(stream)?;
    // Add in the data bits
    value |= (byte_value as usize) << length;
    // Stop if this is the last byte
    if !more_bytes {
      return Ok(value)
    }

    length += VARINT_ENCODING_BITS;
  }
}
```

The object type and size are combined into a single variable-length integer.
There upper 3 data bits of the first byte indicate the object type, and the rest of the bits form the size.
For example, the bytes `[0b1tttxxxx, 0b0yyyyyyy]` would indicate a type of `0bttt` and a size of `0byyyyyyyxxxx`.
So let's see what the value of this integer is for our packed object:
```rust
const PACK_FILE_SUFFIX: &str = ".pack";

fn read_pack_object(pack_file: &mut File, offset: u64) -> io::Result<()> {
  seek(pack_file, offset)?;
  let type_and_size = read_size_encoding(pack_file)?;
  println!("Type and size: {:b}", type_and_size);
  Ok(())
}

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, pack, object] = <[String; 3]>::try_from(args).unwrap();
  let offset = get_pack_offset(&pack, Hash::from_str(&object).unwrap())?;
  let path = Path::new(PACKS_DIRECTORY).join(pack + PACK_FILE_SUFFIX);
  let mut file = File::open(path)?;
  read_pack_object(&mut file, offset.unwrap())
}
```
```
$ cargo run pack-d851c0ab72a0034ab858061940ed04abebe20d32 4d53e91c6b2c3f5b5c7375e579a453fc5053c08b
Type and size: 100010011010
```
Since the variable-length integer was read as `0byyyyyyytttxxxx`, this means `yyyyyyy` is `0010001`, `ttt` is `001`, and `xxxx` is `1010`.
The type is therefore 1, meaning a commit, and the length is `0b00100011010` (282).

We can use a few bitwise operations to extract the type and length:
```rust
// The number of bits storing the object type
const TYPE_BITS: u8 = 3;
// The number of bits of the object size in the first byte.
// Each additional byte has VARINT_ENCODING_BITS of size.
const TYPE_BYTE_SIZE_BITS: u8 = VARINT_ENCODING_BITS - TYPE_BITS;

// Read the lower `bits` bits of `value`
fn keep_bits(value: usize, bits: u8) -> usize {
  value & ((1 << bits) - 1)
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
```

### Undeltified objects

We've already seen the object type 1 (for commit).
The other allowed object types are 2 (tree), 3 (blob), 4 (tag), 6 (offset delta), and 7 (hash delta).
We'll first handle the non-delta object types.
Aside from their headers, their contents are stored as zlib-compressed data, just like in unpacked object files.
```rust
#[derive(Clone, Copy, Debug)]
enum ObjectType {
  Commit,
  Tree,
  Blob,
  Tag,
}

// A packed object can either store the object's contents directly,
// or as a "delta" from another object
enum PackObjectType {
  Base(ObjectType),
  OffsetDelta,
  HashDelta,
}

// An object, which may be read from a packfile or an unpacked file
#[derive(Debug)]
struct Object {
  object_type: ObjectType,
  contents: Vec<u8>,
}

// Shorthand for making an io::Error
fn make_error(message: &str) -> Error {
  Error::new(ErrorKind::Other, message)
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
    Base(object_type) => {
      // The object contents are zlib-compressed
      let mut contents = Vec::with_capacity(size);
      ZlibDecoder::new(pack_file).read_to_end(&mut contents)?;
      if contents.len() != size {
        return Err(make_error("Incorrect object size"))
      }

      Ok(Object { object_type, contents })
    }
    OffsetDelta | HashDelta => unimplemented!(),
  }
}

fn unpack_object(pack: &str, offset: u64) -> io::Result<Object> {
  let path = Path::new(PACKS_DIRECTORY)
    .join(pack.to_string() + PACK_FILE_SUFFIX);
  let mut file = File::open(path)?;
  read_pack_object(&mut file, offset)
}

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, pack, object] = <[String; 3]>::try_from(args).unwrap();
  let offset = get_pack_offset(&pack, Hash::from_str(&object).unwrap())?;
  let Object { object_type, contents } = unpack_object(pack, offset.unwrap())?;
  println!("Type: {:?}", object_type);
  println!("{}", String::from_utf8_lossy(&contents));
  Ok(())
}
```
Note that we use `size` to pre-allocate `contents` with the correct capacity.
Storing the object's size in the packfile is redundant, since zlib streams already indicate where they end.
But git frequently prefixes variable-length data with its size (we will see this again with delta objects).
This is a performance tradeoff—it makes the packfile slightly larger in exchange for not having to grow the contents `Vec` or allocate excess capacity.

Finally, we can successfully read the contents of the HEAD commit from the packfile:
```
$ cargo run pack-d851c0ab72a0034ab858061940ed04abebe20d32 4d53e91c6b2c3f5b5c7375e579a453fc5053c08b
Type: Commit
tree 93bf6ec9945e4c490227048b31659adc2f953c16
parent fe319d5fe11b9ce068f5095782c9b5c3a69caeb3
author Junio C Hamano <gitster@pobox.com> 1636585191 -0800
committer Junio C Hamano <gitster@pobox.com> 1636585281 -0800

A few hotfixes

Signed-off-by: Junio C Hamano <gitster@pobox.com>
```

### Deltified objects

So far, we've seen how to find an object in a packfile and read its compressed representation.
However, we're still missing the main motivation for packfiles: being able to save space by storing one object in terms of another.
This is where the "offset delta" and "hash delta" object types come in.

The idea of a "deltified" object is simple: the object is formed by combining chunks copied from a "base object" with new data.
Ideally the two objects are very similar, in which case only a few large chunks need to be copied and little new data needs to be specified.
The only difference between the offset delta and hash delta types is how the base object is specified: a hash delta uses the object's (20-byte) hash, whereas an offset delta specifies its position in the same packfile (using yet another variable-length int encoding).
The offset representation is shorter and makes it easier to locate the base object, but doesn't allow for base objects outside the packfile.

We'll start by decoding the "offset" of an offset delta.
It uses a variable-length integer, similar to the size encoding.
However, the bytes are in the opposite order (from most to least significant).
The encoding is also slightly more efficient because it avoids duplicate representations of the same value.
For example, `[0b0xxxxxxx]` and `[0b10000000, 0b0xxxxxxx]` would otherwise both decode to `0bxxxxxxx` since the additional 0 bits don't change the value.
So, if there is a second byte, the offset encoding always adds 2<sup>7</sup> to the value.
If there is a third byte, 2<sup>7</sup> + 2<sup>14</sup> is added, and so on.
This way, all 1-byte values are less than all 2-byte values, which are less than all 3-byte values, etc.
```rust
fn read_offset_encoding<R: Read>(stream: &mut R) -> io::Result<u64> {
  let mut value = 0;
  loop {
    let (byte_value, more_bytes) = read_varint_byte(stream)?;
    // Add the new bits at the *least* significant end of the value
    value = (value << VARINT_ENCODING_BITS) | byte_value as u64;
    if !more_bytes {
      return Ok(value)
    }

    // Increase the value if there are more bytes, to avoid redundant encodings
    value += 1;
  }
}
```
This offset is relative to the offset of the deltified object.
For example, a value of 1234 means "go back 1234 bytes to read the base object".

### Delta instructions

After the offset or hash of the base offset, both deltified representations contain a zlib-compressed stream.
The stream starts with the size of the base object (redundant) and the size of the new object (useful for preallocating it).
The rest of the compressed stream is a sequence of instructions for building the new object.
There are two types of instructions:
- `Data(bytes)`: append the specified bytes to the new object
- `Copy(offset, size)`: copy the `size` bytes starting at `offset` in the base object and append them to the new object

The instructions are distinguished by the upper bit of their first byte: a data instruction starts with a 0 bit, while a copy instruction starts with a 1.
In a data instruction, the remaining 7 bits indicate the number of data bytes that follow.
A copy instruction is followed by an offset (up to 4 bytes) and a size (up to 3 bytes) to copy in the base object.
The lower 7 bits in the instruction byte indicate which of these offset and size bytes are present.
For example, consider this copy instruction:
```
[0b1_001_0101, 0bxxxxxxxx, 0byyyyyyyy, 0bzzzzzzzz]
                                       ^ size byte 0
                           ^ offset byte 2
               ^ offset byte 0
          ^ only bytes 0 and 2 of offset are provided
       ^ only byte 0 of size is provided
   ^ copy instruction

Offset: 0b00000000yyyyyyyy00000000xxxxxxxx
Size:           0b0000000000000000zzzzzzzz
```

Here's the (lengthy) implementation.
Keep in mind that we are just repeatedly reading an `enum DeltaInstruction { Data(Vec<u8>), Copy(usize, usize) }` and executing it.
```rust
const COPY_INSTRUCTION_FLAG: u8 = 1 << 7;
const COPY_OFFSET_BYTES: u8 = 4;
const COPY_SIZE_BYTES: u8 = 3;
const COPY_ZERO_SIZE: usize = 0x10000;

// Read an integer of up to `bytes` bytes.
// `present_bytes` indicates which bytes are provided. The others are 0.
fn read_partial_int<R: Read>(
  stream: &mut R, bytes: u8, present_bytes: &mut u8
) -> io::Result<usize> {
  let mut value = 0;
  for byte_index in 0..bytes {
    // Use one bit of `present_bytes` to determine if the byte exists
    if *present_bytes & 1 != 0 {
      let [byte] = read_bytes(stream)?;
      value |= (byte as usize) << (byte_index * 8);
    }
    *present_bytes >>= 1;
  }
  Ok(value)
}

// Reads a single delta instruction from a stream
// and appends the relevant bytes to `result`.
// Returns whether the delta stream still had instructions.
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
```

The delta format seems unnecessarily complex to me.
Why does it need 3 different variable-length integer representations?!

If we ignore the details though, we can see that a delta is really a generalization of a diff.
In fact, git often uses previous versions of `blob` and `tree` objects as base objects for the next versions' deltas, just like `git diff` would do.
Instead of comparing on a line-by-line basis, though, the delta works with individual bytes.
The chunks copied from the base object also do not need to be in the same order they were in.
But the benefits are exactly same: when the changes are small, storing a diff reduces the amount of duplicated data.
So packfiles really do give git the best of both worlds: storing blobs for every file at every commit makes `git checkout` very fast, but storing them as deltas in packfiles keeps them from taking up excessive space.

## Reading an object (for real this time)

We can now fill in the remaining cases in `read_pack_object()`:
```rust
fn read_pack_object(pack_file: &mut File, offset: u64) -> io::Result<Object> {
  // ...

  match object_type {
    Base(object_type) => /* ... */,
    OffsetDelta => {
      let delta_offset = read_offset_encoding(pack_file)?;
      let base_offset = offset.checked_sub(delta_offset).ok_or_else(|| {
        make_error("Invalid OffsetDelta offset")
      })?;
      // Save and restore the offset since read_pack_offset() will change it
      let offset = get_offset(pack_file)?;
      let base_object = read_pack_object(pack_file, base_offset)?;
      seek(pack_file, offset)?;
      apply_delta(pack_file, &base_object)
    }
    HashDelta => {
      let hash = read_hash(pack_file)?;
      let base_object = read_object(hash)?; // to implement shortly
      apply_delta(pack_file, &base_object)
    }
  }
}
```

And now we can successfully read HEAD's `tree` object:
```
93bf6ec9945e4c490227048b31659adc2f953c16 is an offset delta (delta size 5417) from
cc13e418d3294ff306b8a111f08db5ee645d993c is an offset delta (delta size 6311) from
42bee03862795ea50d80bcb25ec564e2b880fd2e is undeltified (size 18464)
```
You can see that we had to compute 2 prior versions of the tree object, but overall we achieve a tradeoff between computing too many deltas and storing too many near-duplicate objects.
(Each delta skips many commits and is only about 1/3 the size of the original object.)

Finally, we can find an object regardless of whether it's packed or unpacked.
We first look where the object would be in the objects directory if it were unpacked.
If it's not there, we have to try each packfile, using the index file to tell us whether the object is in the pack.
```rust
use std::fs;

const COMMIT_OBJECT_TYPE: &[u8] = b"commit";
const TREE_OBJECT_TYPE: &[u8] = b"tree";
const BLOB_OBJECT_TYPE: &[u8] = b"blob";
const TAG_OBJECT_TYPE: &[u8] = b"tag";

impl Object {
  // Compute the hash that an object would have, given its type and contents
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

// Remove the `.idx` suffix from an index filename.
// Returns None if not an index file.
fn strip_index_file_name(file_name: &OsStr) -> Option<&str> {
  let file_name = file_name.to_str()?;
  file_name.strip_suffix(INDEX_FILE_SUFFIX)
}

// Read a packed object from the packs directory
fn read_packed_object(hash: Hash) -> io::Result<Object> {
  // Try every file in the packs directory
  for pack_or_index in fs::read_dir(PACKS_DIRECTORY)? {
    let pack_or_index = pack_or_index?;
    let file_name = pack_or_index.file_name();
    // Skip any non-index files
    let pack = match strip_index_file_name(&file_name) {
      Some(pack) => pack,
      _ => continue,
    };

    // Skip the pack if the object is not in the index
    let pack_offset = get_pack_offset(pack, hash)?;
    let pack_offset = match pack_offset {
      Some(pack_offset) => pack_offset,
      _ => continue,
    };

    // If the object is found in the index, read it from the pack
    return unpack_object(pack, pack_offset)
  }
  Err(make_error(&format!("Object {} not found", hash)))
}

// Read an unpacked object from the objects directory
fn read_unpacked_object(hash: Hash) -> io::Result<Object> {
  // Modified from read_object() and check_header() in the last post
  // ...
}

// Read an object when we don't know if it's packed or unpacked
fn read_object(hash: Hash) -> io::Result<Object> {
  let object = match read_unpacked_object(hash) {
    Ok(object) => object,
    Err(err) if err.kind() == ErrorKind::NotFound => {
      read_packed_object(hash)?
    }
    err => return err,
  };

  // Verify that the object has the SHA-1 hash we expected
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
```

That's the full story of how git stores its objects!
New object files start out unpacked in `.git/objects`.
If you push or pull new objects, they are sent in a packfile.
Received packfiles are saved in `.git/objects/pack`.
And git may occasionally decide the objects directory has gotten too big and combine the objects into a packfile.

You may have noticed that the loop over all possible packfiles can be slow if there are a large number of packfiles.
For this reason, git may choose to combine small packfiles into a single one.
Newer versions of git also support a "multi-pack-index" file ([documentation](https://github.com/calebsander/git-internals/tree/part1)) so only a single index file needs to be consulted to find a packed object in any packfile.
But git still seems to default to individual pack indices.

## Up next...

So far, we've inspected how git stores the state of a repository locally.
We've seen in gory detail how the `HEAD` file, `refs` directory, and `objects` directory represent the branches, commits, trees, and blobs that make up a repository.

In the next (maybe last) post of the series, we'll switch focus to how git *transfers* the state of a repository to and from a remote repository.
We'll look specifically at the SSH "transport", the special protocol used to perform a `git push` or `git pull` (really, `git fetch`) over SSH.
Along the way, we'll answer questions like:
- How does git know what branches are available to pull?
- How does git send repository state and only send what changed? (Spoiler alert: objects and packfiles play a central role.)
- Where do the messages like "Enumerating objects: 176, done." come from?

I think this is the most interesting part of git's implementation; hopefully you will enjoy it too!
