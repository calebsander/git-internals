This is the first of several posts exploring the how git works under the hood.
While lots of programmers are familiar with *using* git, I wanted to do a deep dive into how git is implemented.
git employs many clever ideas to optimize common version control operations.

I'm a big fan of trying to understand software by playing around with it rather than reading lots of documentation.
To that end, I've written these posts as summaries of reverse-engineering git.
The official documentation relevant to this post can be found at https://git-scm.com/book/en/v2/Git-Internals-Git-Objects.

The source code for this post can be found [here](https://github.com/calebsander/git-internals/tree/part1).
I've written it in Rust, but you can find git implementations in lots of other languages.
The canonical [git](https://github.com/git/git) is written in C.

# Git Internals part 1: The git object model

## git refresher

This series isn't meant as an introduction to git.
There are lots of good explanations online of how to use git, such as the [Pro Git book](https://git-scm.com/book).
But I do want to review a few of the core git concepts, since they are important to understanding how git works.

### Version control

git is one of many examples of "version control software", although it is currently the most popular by far.
Although VCS implementations differ in their details, they have many of the same core ideas.
The purpose of version control is to store not just the current state of a set of files, but the *history* of how those files changed over time.
This history can be browsed, updated, and shared, which makes version control a very useful tool in applications where edit histories matter, especially software development.

### Commits

git stores its history as a collection of snapshots, called "commits".
You can browse the state of the files at any commit; this operation is called "checking out" the commit.
You can think of commits as a series of backups of your code, although we will see later that git has several tricks to reduce the storage space needed for all these backups.

Each commit builds on earlier commits, which are called its "parent" commits.
In the simplest case, the commit history is "linear", where each commit has a single parent and child (except for the first and last commits).
For example, there could be three commits made in order, `A`, `B`, and `C`.
We would visualize this with a commit diagram:
```
A --- B --- C
```

However, even on small projects, commit histories are rarely perfectly linear.
git allows commit histories to "branch", where multiple commits build on top of the same parent commit.
This is useful, for example, when developers are working on features in parallel and don't want to affect each other's code until their features are finalized.
This can lead to a commit diagram like the following:
```
A --- B --- C --- D
        \
         E --- F --- G
```
Commit histories can also "merge", where one commit combines multiple parent commits.
In the example above, commit `G` might be merged into `D`, producing a new commit `H`.
```
A --- B --- C --- D --- H
        \             /
         E --- F --- G
```

### Branches and tags

Every commit is assigned an ID, called a "commit hash" (we will see where this hash comes from).
Although we can refer to any commit by its hash, it is often convenient to name commits.
Branches and tags are the two methods to do this.
Both act as references to commits.
The difference is that committing on top of a branch updates the branch to refer to the new commit, whereas tags always point to the same commit.
It is conventional to use the `main` branch to point to the latest production-ready commit and `feature/xyz`, `fix/xyz`, etc. to track progress on adding a feature or fixing a bug.
Tags are mainly used to mark commits corresponding to particular release versions.

## A sample git repository

We'll use the directory structure created by `cargo init` to create a new repository with a single commit:
```bash
$ cargo init
$ git add . # track all the newly created files with git
$ git commit -am 'Initial commit'
[main (root-commit) af64eba] Initial commit
 4 files changed, 19 insertions(+)
 create mode 100644 .gitignore
 create mode 100644 Cargo.lock
 create mode 100644 Cargo.toml
 create mode 100644 src/main.rs
```

git tells us that a new commit was created.
It refers to the commit as `af64eba`; we'll see later where this hexadecimal string comes from and how it gets used.

## Where am I?

Almost all git commands need to know what commit is currently checked out.
For example, `git commit` needs to know the current commit since it will become the parent of the new commit.
In our toy repository, we are at commit `af64eba`.
How does git know that?

You may know that `HEAD` can be used to refer to the current commit.
For example, `git show HEAD` shows the commit message of the current commit and the changes it introduced.
All of the git state is stored in the `.git` directory, and this includes the file which tells us where we currently are: `.git/HEAD`.
Let's look at its contents.

(Note: these examples use synchronous I/O in order to focus on the git internals. There are ample opportunities to perform the filesystem operations in parallel, so using asynchronous I/O could significantly improve performance.)

```rust
use std::fs;
use std::io;

const HEAD_FILE: &str = ".git/HEAD";

fn get_head() -> io::Result<String> {
  fs::read_to_string(HEAD_FILE)
}

fn main() -> io::Result<()> {
  let head = get_head()?;
  println!("Head file: {:?}", head);
  Ok(())
}
```

Running this program, we get the following output:
```
Head file: "ref: refs/heads/main\n"
```

The `.git/HEAD` file is telling us that we have the `main` branch checked out.
That's part of what we wanted to know, but we still haven't figured out how git knows what commit `main` refers to.
It turns out that `refs/heads/main` is actually the name of a file under the `.git` directory.
Let's read it:
```rust
use std::path::Path;

const BRANCH_REFS_DIRECTORY: &str = ".git/refs/heads";

fn get_branch_head(branch: &str) -> io::Result<String> {
  let ref_file = Path::new(BRANCH_REFS_DIRECTORY).join(branch);
  fs::read_to_string(ref_file)
}

fn main() -> io::Result<()> {
  let main_head = get_branch_head("main")?;
  println!("main: {:?}", main_head);
  Ok(())
}
```

We see:
```
main: "af64eba00e3cfccc058403c4a110bb49b938af2f\n"
```

If you remember, the commit we created was referred to as `af64eba`, and it's no coincidence that `.git/refs/heads/main` starts with those hexadecimal digits.
This full string of 40 hexadecimal digits (representing 20 bytes) is called a "commit hash".
We'll see how it's computed soon (and why it's called a "hash"), but for now you can think of it as a unique identifier for the commit.

It's also possible (although less common) to check out a specific commit, rather than a branch.
For example, we can run `git checkout af64eba` to check out the current commit:
```
Note: switching to 'af64eba'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at af64eba Initial commit
```

In this case, the `.git/HEAD` file specifies the commit hash directly:
```
Head file: "af64eba00e3cfccc058403c4a110bb49b938af2f\n"
```

## Implementing HEAD lookup

Now that we know how `.git/HEAD` and the files under `.git/refs/heads` work together, let's define some types:
```rust
const HASH_BYTES: usize = 20;

// A (commit) hash is a 20-byte identifier.
// We will see that git also gives hashes to other things.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hash([u8; HASH_BYTES]);

// The head is either at a specific commit or a named branch
enum Head {
  Commit(Hash),
  Branch(String),
}
```

Next, we will want to be able to convert hashes back and forth between the 40-character hexadecimal representation and the compact 20-byte representation.
I'll omit the implementation details, but you can find them in the source code for this post.
```rust
use std::fmt::{self, Display, Formatter};
use std::io::Error;
use std::str::FromStr;

impl FromStr for Hash {
  type Err = Error;

  fn from_str(hex_hash: &str) -> io::Result<Self> {
    // Parse a hexadecimal string like "af64eba00e3cfccc058403c4a110bb49b938af2f"
    // into  [0xaf, 0x64, ..., 0x2f]. Returns an error if the string is invalid.

    // ...
  }
}

impl Display for Hash {
  fn fmt(&self, f: &mut Formatter) -> fmt::Result {
    // Turn the hash back into a hexadecimal string
    for byte in self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}
```

Now we can write the core logic: reading the `.git/HEAD` file and determining what commit hash it corresponds to:
```rust
fn get_head() -> io::Result<Head> {
  use Head::*;

  let hash_contents = fs::read_to_string(HEAD_FILE)?;
  // Remove trailing newline
  let hash_contents = hash_contents.trim_end();
  // If .git/HEAD starts with `ref: refs/heads/`, it's a branch name.
  // Otherwise, it should be a commit hash.
  Ok(match hash_contents.strip_prefix(REF_PREFIX) {
    Some(branch) => Branch(branch.to_string()),
    _ => {
      let hash = Hash::from_str(hash_contents)?;
      Commit(hash)
    }
  })
}

impl Head {
  fn get_hash(&self) -> io::Result<Hash> {
    use Head::*;

    match self {
      Commit(hash) => Ok(*hash),
      Branch(branch) => {
        // Copied from get_branch_head()
        let ref_file = Path::new(BRANCH_REFS_DIRECTORY).join(branch);
        let hash_contents = fs::read_to_string(ref_file)?;
        Hash::from_str(hash_contents.trim_end())
      }
    }
  }
}

fn main() -> io::Result<()> {
  let head = get_head()?;
  let head_hash = head.get_hash()?;
  println!("Head hash: {}", head_hash);
  Ok(())
}
```

Now, whether we check out the `main` branch or the commit hash directly, this will print:
```
Head hash: af64eba00e3cfccc058403c4a110bb49b938af2f
```

We've successfully identified the hash of the current commit!
Now, how do we figure out what information that commit stores?

## What's in a commit?

When you look at a commit in a web interface like GitHub or through a command like `git show`, you'll see the *changes* ("diff") introduced by the commit.
So you might assume that git stores each commit as a diff.

Alternatively, it would be possible to store each commit like a backup, with the contents of every file at that commit.

Either of these approaches could work: you can compute a diff from two copies of files, and you can compute the contents of files by applying every diff in order (starting either with the empty repository or from a recent commit).
Which one to use depends on what you are trying to optimize.
The diff-based approach will take up less storage space; it minimizes the amount of repeated information, since it only stores what changed.
However, storing contents makes it much faster to check out the code at a particular commit, since we don't have to apply potentially thousands of diffs.
(It also makes it easy to implement `git clone --depth 1`, which speeds up `clone` by only downloading the most recent commit.)
And it's not too time-consuming to compute diffs from two commits' contents if there are few changes: diffing algorithms are pretty fast, and git can automatically skip directories/files that haven't changed, as we'll see later.

For these reasons, git has gone with the "storing the contents of every file" approach.
git's implementation manages to only store one copy of identical files, which saves a lot of storage space over the naive solution.

## Where are the commits?

A commit is one of several things ("objects") that git stores the same way.
Every object is uniquely identified by a hash.
So, in order to read a commit, we need to first read a generic object, and then interpret it as a commit.

You might not be surprised to learn that objects are stored in yet another `.git` subdirectory, `.git/objects`.
Here is what its structure looks like:
```
$ ls -R .git/objects
30   7a   82   a0   af   e7   ea   ed   info pack

.git/objects/30:
5157a396c6858705a9cb625bab219053264ee4

.git/objects/7a:
a5ac9dda7449f167dc03cc3dfb50529d2315f8

.git/objects/82:
50b5cb3a8980fd6d6ad1a29691bbb785080a90

.git/objects/a0:
4ab3c3aee930a929339c5014186cfdd64c8d84

.git/objects/af:
64eba00e3cfccc058403c4a110bb49b938af2f

.git/objects/e7:
a11a969c037e00a796aafeff6258501ec15e9a

.git/objects/ea:
8c4bf7f35f6f77f75d92ad8ce8349f6e81ddba

.git/objects/ed:
9fcacf599c2aaefd46b9c2867339727d2339c3

.git/objects/info:

.git/objects/pack:
```

We'll learn about the `pack` directory in the next post; for now, let's focus on the directories with hexadecimal names.
If you look at the filename `.git/objects/af/64eba00e3cfccc058403c4a110bb49b938af2f`, you may be able to guess where it comes from.
There are 2 hexadecimal digits in the directory name and 38 in the filename.
Together, they make up a single 40-digit hash.
In this case, it's our commit hash `af64eba00e3cfccc058403c4a110bb49b938af2f`!

In general, there are up to 256 object directories (`00` through `ff`) and each one contains all the objects whose hashes start with those 2 digits.
I'm not sure why git does this rather than store all objects in a single directory.
(Perhaps it's to reduce the number of files in each directory, since some platforms place limit directory sizes.
It may also make it faster to find an object file if the OS loops linearly through the entries in each directory, although modern file systems use sorted trees for faster lookup.)

So we've found where our commit object is stored.
Now, what's inside it?
If we inspect the bytes, the file doesn't seem to contain any readable text:
```
$ xxd -g1 .git/objects/af/64eba00e3cfccc058403c4a110bb49b938af2f
00000000: 78 01 9d 8d 41 0a 02 31 0c 45 5d f7 14 b9 80 43  x...A..1.E]....C
00000010: 62 6a a7 05 11 c1 95 6b 4f 90 49 ab 16 da 19 18  bj.....kO.I.....
00000020: eb fd ad 7a 03 97 ef c1 7f 5f 97 5a 73 03 f2 61  ...z....._.Zs..a
00000030: d3 d6 94 40 d0 ca c4 ca 92 52 60 94 b0 0b cc 41  ...@.....R`....A
00000040: f7 48 96 bc d3 5b 8c ce aa 8f de 1a 79 b5 c7 b2  .H...[......y...
00000050: c2 59 4a 9a e0 2a 73 4c 2b 1c f4 43 c3 f3 4b a7  .YJ..*sL+..C..K.
00000060: 7b 95 5c 06 5d ea 11 c8 31 13 8d e4 10 b6 38 22  {.\.]...1.....8"
00000070: 9a 6e fb 6d eb 9b 3f 03 e6 32 e7 96 a5 c0 af 64  .n.m..?..2.....d
00000080: de 12 79 3d 46                                   ..y=F
```
So it's probably in a binary format.
We can use the `file` command to guess what format this is:
```
$ file .git/objects/af/64eba00e3cfccc058403c4a110bb49b938af2f
.git/objects/af/64eba00e3cfccc058403c4a110bb49b938af2f: zlib compressed data
```
Ah, so it's a compressed file!

Let's add a library to read these compressed files.
We'll use the Rust library [`flate2`](https://github.com/rust-lang/flate2-rs), which includes the functionality we need plus much more.
```bash
$ cargo add flate2 # using cargo-edit
```

Now we can write a short script to print the decompressed contents of this object:
```rust
use std::fs::File;
use std::io::Read;
use flate2::read::ZlibDecoder;

const OBJECTS_DIRECTORY: &str = ".git/objects";

// Read the byte contents of an object
fn read_object(hash: Hash) -> io::Result<Vec<u8>> {
  // The first 2 characters of the hexadecimal hash form the directory;
  // the rest forms the filename
  let hex_hash = hash.to_string();
  let (directory_name, file_name) = hex_hash.split_at(2);
  let object_file = Path::new(OBJECTS_DIRECTORY)
    .join(directory_name)
    .join(file_name);
  let object_file = File::open(object_file)?;
  let mut contents = vec![];
  ZlibDecoder::new(object_file).read_to_end(&mut contents)?;
  Ok(contents)
}

fn main() -> io::Result<()> {
  let head = get_head()?;
  let head_hash = head.get_hash()?;
  let head_contents = read_object(head_hash)?;
  // Spoiler alert: the commit object is a text file, so print it as a string
  let head_contents = String::from_utf8(head_contents).unwrap();
  println!("Object {} contents:", head_hash);
  println!("{:?}", head_contents);
  Ok(())
}
```

This prints:
```
Object af64eba00e3cfccc058403c4a110bb49b938af2f contents:
"commit 189\u{0}tree a04ab3c3aee930a929339c5014186cfdd64c8d84\nauthor Caleb Sander <caleb.sander@gmail.com> 1633117160 -0700\ncommitter Caleb Sander <caleb.sander@gmail.com> 1633117160 -0700\n\nInitial commit\n"
```

So finally, we can see the `author`, `committer`, and commit message ("Initial commit") of the commit!
Commit objects start with a header like `"commit 189\u{0}"`.
`189` indicates that there are 189 bytes in the body of the commit (after the header).

This commit is special, since it's the first commit, but generally each commit will also have a parent commit (or multiple, for merge commits).
We can see that if we add another commit and re-run the script:
```
$ git add Cargo.toml Cargo.lock
$ git commit -m 'Add flate2 dependency'
[main b1ffae7] Add flate2 dependency
 2 files changed, 59 insertions(+)
$ cargo run
Object b1ffae7cd17860fc6688bfcabbfe0d75301a7d46 contents:
"commit 244\u{0}tree b195f77cbea5fc36ddbee3b739ce5a924893b72f\nparent af64eba00e3cfccc058403c4a110bb49b938af2f\nauthor Caleb Sander <caleb.sander@gmail.com> 1633801460 -0700\ncommitter Caleb Sander <caleb.sander@gmail.com> 1633801460 -0700\n\nAdd flate2 dependency\n"
```
Note the additional `parent` line in the output, with a hash referring to our previous commit.

Finally, we can parse the commit object into a `Commit` type.
For simplicity, we will skip parsing the `author` and `committer` lines into `(name, email, timestamp, timezone)`.
```rust
const COMMIT_HEADER: &[u8] = b"commit ";
const TREE_LINE_PREFIX: &[u8] = b"tree ";
const PARENT_LINE_PREFIX: &[u8] = b"parent ";
const AUTHOR_LINE_PREFIX: &[u8] = b"author ";
const COMMITTER_LINE_PREFIX: &[u8] = b"committer ";

// Some helper functions for parsing objects

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

// Like str::split_once(), split the slice at the next delimiter
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

fn main() -> io::Result<()> {
  let head = get_head()?;
  let head_hash = head.get_hash()?;
  let commit = read_commit(head_hash)?;
  println!("Commit {}:", head_hash);
  println!("{:x?}", commit);
  Ok(())
}
```
Here's what our commit looks like:
```
Commit b1ffae7cd17860fc6688bfcabbfe0d75301a7d46:
Commit { tree: Hash([b1, 95, f7, 7c, be, a5, fc, 36, dd, be, e3, b7, 39, ce, 5a, 92, 48, 93, b7, 2f]), parents: [Hash([af, 64, eb, a0, e, 3c, fc, cc, 5, 84, 3, c4, a1, 10, bb, 49, b9, 38, af, 2f])], author: "Caleb Sander <caleb.sander@gmail.com> 1633801460 -0700", committer: "Caleb Sander <caleb.sander@gmail.com> 1633801460 -0700", message: "Add flate2 dependency\n" }
```

## How do we check out the files at a commit?

Most of the fields in a commit object should make sense to a git user:
- `parent` is the commit (or commits) that this commit builds on top of
- `author` is the person credited for the commit contents, along with the time when they authored the commit
- `committer` is the person who actually made the commit (often the same as `author`)
- `message` is the combined commit message and description

But what does the `tree` hash mean?

Since each hash refers to an object, let's inspect the object referenced by the `tree` hash:
```rust
use std::fs;

fn main() -> io::Result<()> {
  let head = get_head()?;
  let head_hash = head.get_hash()?;
  let commit = read_commit(head_hash)?;
  let tree_contents = read_object(commit.tree)?;
  fs::write("tree", tree_contents)
}
```
Running this program creates a file called "tree" with the decompressed contents of the `tree` object.
Unfortunately, unlike commit objects, this object stores a mix of text and binary information.
We can use `xxd` to see both the byte values and the text characters:
```
$ xxd -g1 tree
00000000: 74 72 65 65 20 31 34 34 00 31 30 30 36 34 34 20  tree 144.100644
00000010: 2e 67 69 74 69 67 6e 6f 72 65 00 ea 8c 4b f7 f3  .gitignore...K..
00000020: 5f 6f 77 f7 5d 92 ad 8c e8 34 9f 6e 81 dd ba 31  _ow.]....4.n...1
00000030: 30 30 36 34 34 20 43 61 72 67 6f 2e 6c 6f 63 6b  00644 Cargo.lock
00000040: 00 85 a3 d4 da 06 7e 56 92 4f 41 99 ae 37 f2 d1  ......~V.OA..7..
00000050: a2 f0 82 2c b8 31 30 30 36 34 34 20 43 61 72 67  ...,.100644 Carg
00000060: 6f 2e 74 6f 6d 6c 00 47 82 47 98 37 bf 5a f0 bf  o.toml.G.G.7.Z..
00000070: 9b 80 92 91 14 3a ce 2f e4 a8 c3 34 30 30 30 30  .....:./...40000
00000080: 20 73 72 63 00 30 51 57 a3 96 c6 85 87 05 a9 cb   src.0QW........
00000090: 62 5b ab 21 90 53 26 4e e4                       b[.!.S&N.
```

The header should look familiar.
In this case, the type of the object is `tree` instead of `commit` and the size in bytes is `144`.

After the header, there's a number (`100644`), followed by a space, and then a filename (`.gitignore`), followed by a 0 byte.
The next 20 bytes don't look like readable text.
Then the pattern repeats for `Cargo.lock`, `Cargo.toml`, and `src`.

You may notice that `100644` is used for all the filenames that are files (`.gitignore`, `Cargo.lock`, and `Cargo.toml`), whereas `40000` is used for the directory `src`.
This is a good approximation, although there are other numbers (called "modes") corresponding to executable files, symbolic links, and git submodules.

You might guess that each of these sequences of 20 bytes represents a hash.
(Who knows why tree objects store hashes as bytes while commit objects store them as hexadecimal strings.)

We can parse tree objects using the helper functions we developed for commits:
```rust
use std::str;

const TREE_HEADER: &[u8] = b"tree ";

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
```

We've glossed over the meaning of the `hash` in each tree entry.
It turns out that it refers to a different type of object depending on the `mode` of the entry.
If the entry is a directory, then it contains files and directories of its own, forming a subtree.
So it should make sense that the `hash` of a directory entry refers to another tree object.
However, if an entry is a file, then the `hash` instead needs to give us the contents of the file.
This is accomplished with one more type of object, the "blob".
(And if the entry is a git submodule, referring to another git repository, then the `hash` refers to the checked-out commit object in that other repository.)

Thankfully, `blob` objects are the simplest of all.
They just contain a header, followed by the raw contents of a file.

Let's parse them:
```rust
const BLOB_HEADER: &[u8] = b"blob ";

struct Blob(Vec<u8>);

fn read_blob(hash: Hash) -> io::Result<Blob> {
  let object = read_object(hash)?;
  let bytes = check_header(&object, BLOB_HEADER).ok_or_else(|| {
    Error::new(ErrorKind::Other, format!("Malformed blob object: {}", hash))
  })?;
  Ok(Blob(bytes.to_vec()))
}
```

Armed with an understanding of the HEAD file, ref files, commit objects, tree objects, and blob objects, we can finally view the contents of a file (say, `src/main.rs`) at the current commit:
```rust
fn get_file_blob(tree: Hash, path: &str) -> io::Result<Blob> {
  let mut hash = tree;
  for name in path.split('/') {
    let tree = read_tree(hash)?;
    let entry = tree.0.iter().find(|entry| entry.name == name).ok_or_else(|| {
      Error::new(ErrorKind::Other, format!("No such entry: {}", name))
    })?;
    hash = entry.hash;
  }
  read_blob(hash)
}

fn main() -> io::Result<()> {
  let head = get_head()?;
  let head_hash = head.get_hash()?;
  let commit = read_commit(head_hash)?;
  let blob = get_file_blob(commit.tree, "src/main.rs")?;
  print!("{}", String::from_utf8(blob.0).unwrap()); // assume a text file
  Ok(())
}
```

This prints out the contents of `src/main.rs` that `cargo init` created:
```
fn main() {
    println!("Hello, world!");
}
```

## What is a hash?

So far, we've been treating hashes simply as object IDs.
They look like random values, 20 bytes or 40 hexadecimal characters long.
But there is actually a precise way that a hash is computed which explains why it's called a "hash".

If you're unfamiliar with hash functions (e.g. MD5, SHA-1, SHA-256), the idea is that they are functions that take inputs (typically expressed as an an array of bytes) and compute fixed-size outputs (called "hashes").
For example, MD5 computes a 128-bit hash, SHA-1 computes a 160-bit hash, and SHA-256 computes a 256-bit hash.
What's important is that these functions are "deterministic" (passing in the same input always results in the same hash), yet "chaotic" (passing in slightly different inputs results in completely different hashes).
For this reason, hashes are sometimes called "signatures" or "fingerprints": they give each input a consistent and (almost) unique label.

Since git's hashes are 20 bytes long, or 160 bits, you might have guessed that they are SHA-1 hashes.
So what input does an object's hash correspond to?
Well, the only natural thing to take the hash of when determining an object's hash is the contents of the object itself.
So this is exactly what git does.

We can check that each object we read has a correct hash.
First, we will need the `sha-1` crate to compute SHA-1 hashes:
```
cargo add sha-1
```

Then we can modify our `read_object()` function to compare the hash of an object's contents against the hash it was supposed to have:
```rust
fn read_object(hash: Hash) -> io::Result<Vec<u8>> {
  // ...
  // The entire uncompressed contents of the object, including the header
  // are the input to the hash function
  let contents_hash = Sha1::digest(&contents);
  if contents_hash.as_slice() != hash.0 {
    return Err(Error::new(
      ErrorKind::Other,
      format!("Object {} has wrong hash {:x}", hash, contents_hash),
    ))
  }

  Ok(contents)
}
```

Hash functions are often used to quickly check whether two inputs are equal.
Since they are deterministic, two identical inputs will *always* have the same hash.
Since they are chaotic, it is very unlikely that two different inputs have the same hash (a "hash collision").
SHA-1 produces 160-bit hashes, so (assuming the hashes are evenly distributed) the likelihood of two different inputs having the same hash is around 2<sup>-160</sup>, or 10<sup>-48</sup>.
This is an exceedingly small number, so git actually assumes that any objects with the same hash are identical.
In fact, it is common to refer to commits by just a 7-character hash (like the `af64eba` reported by `git commit` earlier) because even this collision probability is negligible for a small repository.

The fact that git stores every object by hash has a very useful consequence.
If two files (or the same file in multiple commits) have the same contents, git will try to create `blob` objects for both of them, and these objects will have the same hash.
git can recognize the second hash as one that it already has, and will just reuse the existing blob.

In fact, the same holds for tree objects.
Since a tree object consists of the names, modes, and hashes of the entries in the tree, a tree's hash is a hash of the names, modes, and contents of *all the files under it*.
(It is important that tree entries are sorted by name; otherwise, the representation of a tree would not be unique.)
So, if an entire directory is the same between two commits, git will reuse the same tree.

As mentioned in ["What's in a commit?"](#whats-in-a-commit), this reuse of objects is crucial to save storage space.
But keep in mind that this check only happens for whole objects.
If you change even a single character of a file, its blob will have a completely different hash, so the whole new file will be stored in a separate blob object.
(We will see in the next post how git avoids actually storing two very similar objects.)

## Implementing a git command

We've learned a lot!
We can traverse the commit history of a git repository, see files at any commit, and understand where object hashes come from.
Let's put this together to implement a real git command: `git diff COMMIT1 COMMIT2`, which shows the difference between all files at two commit hashes.

We will need to compare the blobs corresponding to the same file in two commits.
Instead of always comparing the contents of the blobs, we can skip them if their hashes are the same, since that means they are the same object.
We also need to handle the case where one of the blobs is missing, which means the file was added or removed between the commits.

We use the UNIX command-line program `diff` to compare the contents of the files.
`diff` expects two files as input, so we copy the blobs to temporary files `.git/a` and `.git/b`.

```rust
use std::process::Command;

const EMPTY_FILE: &str = "/dev/null";
const DIFF_LEFT_FILE: &str = ".git/a";
const DIFF_RIGHT_FILE: &str = ".git/b";

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
```

Now, since we will be comparing the entire trees corresponding to the two commit objects, we want a function to compare trees.
Again, we can skip the entire tree if the hashes are the same.
And either tree object might not exist, in which case we treat it as any empty tree.

Since trees list their entries in name order, we can merge these two sorted slices to process all entries in both tries in order and find all entries that exist in both trees.
Note that the same filename might correspond to a file in one tree and a directory in the other, in which case we treat it as though the file were deleted and the directory added.
```rust
use std::path::PathBuf;

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
```

And finally, we can add some basic command-line argument processing to parse the two commit hashes we pass.
```rust
use std::env;

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
```

Running the program on the two commits, we can see the changes introduced by `cargo add flate2`:
```
Cargo.lock
--- .git/a	2021-10-30 14:01:38.000000000 -0700
+++ .git/b	2021-10-30 14:01:38.000000000 -0700
@@ -3,5 +3,63 @@
 version = 3

 [[package]]
+name = "adler"
+version = "1.0.2"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "f26201604c87b1e01bd3d98f8d5d9a8fcbb815e8cedb41ffccbeb4bf593a35fe"
+
+[[package]]
+name = "autocfg"
+version = "1.0.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "cdb031dd78e28731d87d56cc8ffef4a8f36ca26c38fe2de700543e627f8a464a"
+
+[[package]]
+name = "cfg-if"
+version = "1.0.0"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd"
+
+[[package]]
+name = "crc32fast"
+version = "1.2.1"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "81156fece84ab6a9f2afdb109ce3ae577e42b1228441eded99bd77f627953b1a"
+dependencies = [
+ "cfg-if",
+]
+
+[[package]]
+name = "flate2"
+version = "1.0.22"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "1e6988e897c1c9c485f43b47a529cef42fde0547f9d8d41a7062518f1d8fc53f"
+dependencies = [
+ "cfg-if",
+ "crc32fast",
+ "libc",
+ "miniz_oxide",
+]
+
+[[package]]
 name = "git"
 version = "0.1.0"
+dependencies = [
+ "flate2",
+]
+
+[[package]]
+name = "libc"
+version = "0.2.103"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "dd8f7255a17a627354f321ef0055d63b898c6fb27eff628af4d1b66b7331edf6"
+
+[[package]]
+name = "miniz_oxide"
+version = "0.4.4"
+source = "registry+https://github.com/rust-lang/crates.io-index"
+checksum = "a92518e98c078586bc6c934028adcca4c92a53d6a958196de835170a01d84e4b"
+dependencies = [
+ "adler",
+ "autocfg",
+]
Cargo.toml
--- .git/a	2021-10-30 14:01:38.000000000 -0700
+++ .git/b	2021-10-30 14:01:38.000000000 -0700
@@ -6,3 +6,4 @@
 # See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

 [dependencies]
+flate2 = "1.0.22"
```

## Up next...

In the next post of this series, we'll see that the `.git/objects` directory is much more complicated than it looked.
We'll learn how a "pack file" compresses collections of objects, both in the `.git` directory and during a `git pull` or `git push`.
And we'll investigate git's solution to efficiently find objects within pack files.
