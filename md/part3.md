# Git Internals part 3: the SSH transport

This post is the last in the "Git Internals" series.
In [part 1](https://dev.to/calebsander/git-internals-part-1-the-git-object-model-474m), we introduced git's object storage model, and in [part 2](https://dev.to/calebsander/git-internals-part-2-packfiles-1jg8), we saw how objects are stored in "packfiles" to save space.

In this post, we'll turn our attention from local git repositories (stored on your computer) to remote ones (stored on a server, e.g. GitHub).
We'll inspect the protocol git uses to communicate with "remotes" and implement `git fetch` from the ground up.

If you use online git repositories (like those on GitHub) frequently, you may know you can `git clone` a repository using either an HTTP/HTTPS URL (e.g. `https://github.com/git/git.git`) or an "SSH" URL (e.g. `git@github.com:git/git.git`).
The difference between these URLs is the protocol that git uses to communicate with the GitHub server during a `git clone`, `git fetch`, `git pull`, or `git push`.
git implements several protocols: "dumb" HTTP/HTTPS, "smart" HTTP/HTTPS, SSH, and "git".
The dumb protocol is less efficient, so it is rarely used in practice.
The smart protocols use the same procedures, but differ in the underlying protocol used to connect to the server.
We'll focus on the SSH one because it is so common and is an interesting application of SSH.

The protocol is human-readable, so we will mostly learn how it works by observing what the client and server send each other.
If you want to look at git's documentation on the topic, here are some good resources:
- The git book [chapter on transfer protocols](https://git-scm.com/book/en/v2/Git-Internals-Transfer-Protocols) provides a high-level overview of the available transports and how they work
- The git internal ["pack protocol" documentation](https://git-scm.com/docs/pack-protocol) describes the SSH transport protocol in detail
- The git internal ["protocol capabilities" documentation](https://git-scm.com/docs/protocol-capabilities) explains each of the optional features for the SSH transport

Sorry for the delay on part 3!
My life has been busier than expected the past few months.

The source code for this post can be found [here](https://github.com/calebsander/git-internals/tree/part3).

## Where does SSH come in?

Using an SSH git URL requires you to upload your SSH public key to the server.
SSH keys are typically used to authenticate SSH connections, so you might be able to guess that your git client is communicating with the git server over an SSH connection.

If you're unfamiliar with SSH, here's a quick overview of how it's used.
(We won't worry about how SSH is *implemented*, but that's also fascinating.)
SSH allows you to run terminal commands on a remote computer.
For example, I can run `hostname` to see the name of my computer:
```
csander:~ $ hostname
csander-mac.local
```
I can also use SSH to open a terminal on the EC2 instance hosting `calebsander.com` and run `hostname` there:
```
csander:~ $ ssh ubuntu@calebsander.com # ubuntu is the user to log in as
ubuntu@ip-172-31-52-11:~ $ hostname
ip-172-31-52-11
ubuntu@ip-172-31-52-11:~ $ exit
Connection to calebsander.com closed.
```
By default, `ssh` runs a terminal process (e.g. `bash`) on the server.
You can tell `ssh` to run a different command instead:
```
csander:~ $ ssh ubuntu@calebsander.com hostname
ip-172-31-52-11
```
A key feature git will leverage is that the SSH connection is bidirectional: your local standard input is connected to the input of the remote process and the remote standard output back to the local one.
This is easiest to see when running a command like `cat` (copy standard input to standard output).
If you send type a line of text, it gets sent to the `cat` process running on the other computer, which prints the line, causing it to be sent back.
```
csander:~ $ ssh ubuntu@calebsander.com cat
abc # input sent to server
abc # output sent back
123 # input
123 # output
(enter Ctrl+D to end the standard input, terminating the process)
```

SSH provides both authentication (the server checks that the client's SSH key may access the repository) and encryption (the communication is hidden from anyone snooping on the connection), which is likely why git chose to use it.

If we run the command `git clone git@github.com:git/git.git` and use `ps aux | grep ssh` to list the SSH processes while it's running, we can see the SSH command that git used:
```
/usr/bin/ssh -o SendEnv=GIT_PROTOCOL git@github.com git-upload-pack 'git/git.git'
```
`-o SendEnv=GIT_PROTOCOL` is unnecessary, so the SSH command can be simplified to:
```
ssh git@github.com git-upload-pack git/git.git
```
There we can see all the pieces of the URL `git@github.com:git/git.git`!
The part before the `:` is the SSH login (e.g. `user@domain.name`) and the part after the `:` is the argument to the `git-upload-pack` executable, specifying the repository.
(It may be confusing that `git-upload-pack` is used for a `clone`/`fetch`/`pull` and `git-receive-pack` is used for `push`, but this is from the perspective of the server.)

If you're curious, the GitHub SSH server is restricted so you can't run other commands:
```
$ ssh git@github.com
PTY allocation request failed on channel 0
Hi calebsander! You've successfully authenticated, but GitHub does not provide shell access.
Connection to github.com closed.
$ ssh git@github.com echo Hello world
Invalid command: 'echo Hello world'
  You appear to be using ssh to clone a git:// URL.
  Make sure your core.gitProxy config option and the
  GIT_PROXY_COMMAND environment variable are NOT set.
```

Now that we know the SSH command, we can run it ourselves and see what the server sends back:
```
$ ssh git@github.com git-upload-pack git/git.git
014e74cc1aa55f30ed76424a0e7226ab519aa6265061 HEADmulti_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want symref=HEAD:refs/heads/master filter object-format=sha1 agent=git/github-g2faa647c16c3
003d74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/main
003e4c53a8c20f8984adb226293a3ffd7b88c3f4ac1a refs/heads/maint
003f74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/master
003dd65ed663a79d75fb636a4602eca466dbd258082e refs/heads/next
003d583a5781c12c1d6d557fae77552f6cee5b966f8d refs/heads/seen
003db1b3e2657f1904c7c603ea4313382a24af0fd91f refs/heads/todo
003ff0d0fd3a5985d5e588da1e1d11c85fba0ae132f8 refs/pull/10/head
0040c8198f6c2c9fc529b25988dfaf5865bae5320cb5 refs/pull/10/merge
...
003edcba104ffdcf2f27bc5058d8321e7a6c2fe8f27e refs/tags/v2.9.5
00414d4165b80d6b91a255e2847583bd4df98b5d54e1 refs/tags/v2.9.5^{}
0000(waiting for input)
```
Okay, that's a lot to unpack (pun definitely intended), so let's break it down!

## Opening an SSH connection in Rust

First, we'll see how to open this SSH connection in Rust.
We can construct the same `ssh` command we ran ourselves, using `Stdio::piped()` for the input and output streams so we get an `ssh_input` that implements `Write` and an `ssh_output` implementing `Read`.
```rust
use std::env;
use std::io;
use std::process::{ChildStdin, ChildStdout, Command, Stdio};

// Using the types and functions implemented in previous posts

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
}

fn main() -> io::Result<()> {
  let args: Vec<_> = env::args().collect();
  let [_, repository] = <[String; 2]>::try_from(args).unwrap();
  let mut transport = Transport::connect(&repository)?;
  // Print the SSH output
  io::copy(&mut transport.ssh_output, &mut io::stdout())?;
  Ok(())
}
```

Running this program gives the same result as running the SSH command directly:
```
$ cargo run git@github.com:git/git.git
014e74cc1aa55f30ed76424a0e7226ab519aa6265061 HEADmulti_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want symref=HEAD:refs/heads/master filter object-format=sha1 agent=git/github-g2faa647c16c3
003d74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/main
003e4c53a8c20f8984adb226293a3ffd7b88c3f4ac1a refs/heads/maint
003f74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/master
003dd65ed663a79d75fb636a4602eca466dbd258082e refs/heads/next
003d583a5781c12c1d6d557fae77552f6cee5b966f8d refs/heads/seen
003db1b3e2657f1904c7c603ea4313382a24af0fd91f refs/heads/todo
003ff0d0fd3a5985d5e588da1e1d11c85fba0ae132f8 refs/pull/10/head
0040c8198f6c2c9fc529b25988dfaf5865bae5320cb5 refs/pull/10/merge
...
003edcba104ffdcf2f27bc5058d8321e7a6c2fe8f27e refs/tags/v2.9.5
00414d4165b80d6b91a255e2847583bd4df98b5d54e1 refs/tags/v2.9.5^{}
(waiting)
```

## Finding the default remote URL

In the example above, we passed the desired repository URL to our program.
But when using git, it is common to run `git fetch`/`pull`/`push` without specifying a repository.
By default, git uses the URL specified during the initial `git clone`, so it must be stored somewhere.
Exploring the `.git` directory, we see:
```
$ git clone git@github.com:git/git.git
Cloning into 'git'...
remote: Enumerating objects: 325167, done.
remote: Total 325167 (delta 0), reused 0 (delta 0), pack-reused 325167
Receiving objects: 100% (325167/325167), 185.01 MiB | 7.77 MiB/s, done.
Resolving deltas: 100% (242985/242985), done.
Updating files: 100% (4084/4084), done.
$ cd git
$ cat .git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
[remote "origin"]
	url = git@github.com:git/git.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

There is a `[remote ...]` section for each remote repository.
By default, the repository used in the `git clone` command is called `origin`.
The `url` parameter gives us the URL for that remote.

There is also a `[branch ...]` section for each branch, e.g. `master`, indicating which remote and remote ref name to `push` and `pull` the branch from by default.

For example, consider running `git pull` with `master` checked out.
The `[branch "master"]` and `[remote "origin"]` config sections translate this into fetching `git@github.com:git/git.git` and merging `origin/master` into `master`.

We can find the URL for `origin` by parsing the config file and then extracting the `url` parameter from the `[remote "origin"]` section:
```rust
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

const CONFIG_FILE: &str = ".git/config";
// `r#` is handy for string literals with quotes
const REMOTE_ORIGIN_SECTION: &str = r#"[remote "origin"]"#;
const URL_PARAMETER: &str = "url";

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

fn main() -> io::Result<()> {
  let config = ConfigFile::read()?;
  println!("Config file: {:#?}", config);
  let origin_url = config.get_origin_url().ok_or_else(|| {
    make_error("Missing remote 'origin'")
  })?;
  println!("Remote 'origin' URL: {}", origin_url);
  Ok(())
}
```

Running this prints:
```
Config file: ConfigFile(
    {
        "[remote \"origin\"]": {
            "url": "git@github.com:git/git.git",
            "fetch": "+refs/heads/*:refs/remotes/origin/*",
        },
        "[core]": {
            "repositoryformatversion": "0",
            "bare": "false",
            "ignorecase": "true",
            "filemode": "true",
            "logallrefupdates": "true",
            "precomposeunicode": "true",
        },
        "[branch \"master\"]": {
            "remote": "origin",
            "merge": "refs/heads/master",
        },
    },
)
Remote 'origin' URL: git@github.com:git/git.git
```

## The SSH transport protocol

### Chunks

Let's try to understand [what the server sent](#opening-an-ssh-connection-in-rust) over the SSH connection.
It looks like a series of lines, each starting with a hexadecimal string.
These look like hashes, and in fact they almost are, except they're 44 characters long instead of 40.
You may notice that the first 4 hexadecimal characters mostly follow the pattern of "003x" or "004x", and the last (empty) line has "0000" as its first 4 characters.
You can check that these 4 characters encode the length of each line (including the 4 characters at the start and the newline character at the end) in hexadecimal.
The "0000" line is special; it indicates the end of the lines being sent.
git documentation calls prefixing each line with its length in hexadecimal the ["pkt-line" format](https://git-scm.com/docs/protocol-common#_pkt_line_format).
I'll refer to these lines as "**chunks**".

We'll see chunks later with binary data instead of text, so we'll start with a method to read a chunk as bytes:
```rust
const CHUNK_LENGTH_DIGITS: usize = 4;

impl Transport {
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
}
```

Then we can read a text chunk by converting the bytes to a string and removing the `\n` at the end:
```rust
impl Transport {
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
}

fn main() -> io::Result<()> {
  // ...

  let mut transport = Transport::connect(origin_url)?;
  // Print each text chunk the server sends back
  while let Some(chunk) = transport.read_text_chunk()? {
    println!("{:?}", chunk);
  }
  Ok(())
}
```

This program shows every parsed text chunk until the `0000` line which indicates the end of chunks.
The chunks look identical to the SSH output with the 4 hexadecimal characters removed from the start of each line.
We can also see a 0 byte (`\u{0}`) in the first text chunk that was hidden by my terminal.
```
"74cc1aa55f30ed76424a0e7226ab519aa6265061 HEAD\u{0}multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want symref=HEAD:refs/heads/master filter object-format=sha1 agent=git/github-g2faa647c16c3"
"74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/main"
"4c53a8c20f8984adb226293a3ffd7b88c3f4ac1a refs/heads/maint"
"74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/master"
"d65ed663a79d75fb636a4602eca466dbd258082e refs/heads/next"
"583a5781c12c1d6d557fae77552f6cee5b966f8d refs/heads/seen"
"b1b3e2657f1904c7c603ea4313382a24af0fd91f refs/heads/todo"
"f0d0fd3a5985d5e588da1e1d11c85fba0ae132f8 refs/pull/10/head"
"c8198f6c2c9fc529b25988dfaf5865bae5320cb5 refs/pull/10/merge"
...
"dcba104ffdcf2f27bc5058d8321e7a6c2fe8f27e refs/tags/v2.9.5"
"4d4165b80d6b91a255e2847583bd4df98b5d54e1 refs/tags/v2.9.5^{}"
```

### Refs

Looking at the lines sent by the server, we can see that each one lists a commit hash and a name (`HEAD`, `refs/heads/main`, etc.).
The first line also has an additional string of capabilities, which we'll discuss shortly.
These commit-name combinations are called "refs" (short for "references") and tell the client which commits it can fetch.
They fall into several categories:
- `HEAD`: this is the default commit to check out when doing a `git clone` (it's identical to `refs/heads/main`)
- `refs/heads/BRANCH_NAME`: these are the branches on the remote repository
- `refs/tags/TAG_NAME`: these are the tags on the remote (not fetched by default)
- `refs/pull/PULL_REQUEST_NUMBER/head` and `/merge`: these are GitHub-specific, indicating the current commit of each pull request and the commit that merged it into the repository (if applicable)

Here's code to read the refs and capabilities returned by the server:
```rust
use std::collections::HashSet;

struct Refs {
  capabilities: HashSet<String>,
  // Map of ref name (e.g. "refs/heads/main") to commit hashes
  refs: HashMap<String, Hash>,
}

impl Transport {
  fn receive_refs(&mut self) -> io::Result<Refs> {
    // The first chunk contains the HEAD ref and a list of capabilities.
    // Even if the repository is empty, capabilities are still needed,
    // so a hash of all 0s is sent.
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
      // Each subsequent chunk contains a ref (a commit hash and a name)
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
}

fn main() -> io::Result<()> {
  // ...

  let Refs { capabilities, refs } = transport.receive_refs()?;
  println!("Capabilities: {:?}", capabilities);
  for (ref_name, hash) in refs {
    println!("Ref {} has hash {}", ref_name, hash);
  }
  Ok(())
}
```

Running this program prints the capabilities and refs the server sent back.
Note that the order is randomized since we are iterating over a `HashSet` and a `HashMap`.
```
Capabilities: {"deepen-since", "symref=HEAD:refs/heads/master", "object-format=sha1", "allow-reachable-sha1-in-want", "include-tag", "shallow", "thin-pack", "allow-tip-sha1-in-want", "side-band-64k", "deepen-not", "filter", "agent=git/github-g2faa647c16c3", "side-band", "multi_ack_detailed", "deepen-relative", "ofs-delta", "no-progress", "multi_ack"}
Ref refs/pull/531/head has hash 1572444361982199fdab9c6f6b7e94383717b6c9
Ref refs/pull/983/merge has hash d217f9ec363d5ed88a37ab15a72fad6b4d90acf1
Ref refs/pull/891/head has hash 7d7e794ab7286db0aea88c6e1eab881fc5d188f7
Ref refs/tags/v2.14.1^{} has hash 4d7268b888d7bb6d675340ec676e4239739d0f6d
...
Ref refs/tags/v1.2.3 has hash 51f2164fdc92913c3d1c6d199409b43cb9b6649f
```

### Capabilities

Both the server and client communicate "capabilities" they support.
This allows them each to implement new git features while remaining backwards-compatible with older clients and servers.
For example, the `ofs-delta` capability means that the server can send (or the client can understand) "offset delta" objects in packfiles.

The server sends the list of its capabilities and the client requests a subset of them to enable.
This way, both the server and client support all the enabled capabilities.

git also uses the capabilities to send miscellaneous information (e.g. `symref=HEAD:refs/heads/master` indicates that `master` is the default branch).

For now, we will only request the `ofs-delta` capability (if the server supports it).
The last post (part 2) has an in-depth discussion of offset deltas, but the gist is that they make for smaller packfiles than hash deltas (which are always supported).
Just as the server sends its capabilities in its first ref chunk, the client requests capabilities in its first "want" chunk, which we'll discuss next.

### Wants

Once the server has advertised the available refs, the client chooses which ones it wants by responding with their hashes.
For example, running `git pull origin main`, the client would only request the commit for ref `refs/heads/main`.
The server sends only the requested commit objects and the commit, tree, and blob objects it (indirectly) references.

Wanted refs are sent as text chunks starting with `want`.
The same format (prefixed by hexadecimal length) is used when sending chunks to the server as when receiving chunks.
The only difference is that they are written to the SSH *input* rather than read from the SSH *output*.

Here's a Rust implementation.
Note that we can send an empty chunk (`transport.write_text_chunk(None)`) just like we receive an empty chunk at the end of the refs.
```rust
// git reserves chunk lengths 65521 to 65535
const MAX_CHUNK_LENGTH: usize = 65520;

impl Transport {
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
}
```

To request a hash, we send a text chunk starting with `want`.
The first want, like the first ref chunk, can also include capabilities that the client requests.
```rust
impl Transport {
  fn send_wants(&mut self, hashes: &[Hash], capabilities: &[&str])
    -> io::Result<()>
  {
    let mut first_want = true;
    for hash in hashes {
      println!("Requesting {}", hash);
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
}
```

Putting this all together, we can now tell the server which refs to send.
We'll fetch all the branches (i.e. refs starting with `refs/heads/`).
```rust
const BRANCH_REF_PREFIX: &str = "refs/heads/";
const REQUESTED_CAPABILITIES: &[&str] = &["ofs-delta"];

impl Transport {
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

    // TODO: there's another negotiation with the server about which objects
    // the client already has, but for now we'll pretend it has none.
    // We'll implement this later (see "Haves").
    self.write_text_chunk(Some("done"))?;
    self.read_text_chunk()?;

    // TODO: receive the objects the server sends back
    Ok(())
  }
}

fn main() -> io::Result<()> {
  // ...

  transport.fetch()
}
```

Running this program shows that 6 branches (`main`, `maint`, `master`, `next`, `seen`, and `todo`) were requested.
Since `main` and `master` are interchangeable, one of the commits is requested twice (this is unnecessary but allowed).
```
Requesting b1b3e2657f1904c7c603ea4313382a24af0fd91f
Requesting 583a5781c12c1d6d557fae77552f6cee5b966f8d
Requesting 74cc1aa55f30ed76424a0e7226ab519aa6265061
Requesting 74cc1aa55f30ed76424a0e7226ab519aa6265061
Requesting d65ed663a79d75fb636a4602eca466dbd258082e
Requesting 4c53a8c20f8984adb226293a3ffd7b88c3f4ac1a
```

## Packfiles make a triumphant return

Once the server knows what objects the client needs, it must send them.
There are potentially thousands of commits, trees, and blobs, so it's important to encode them compactly.
If you read the last post (part 2), you'll see this is a primary use case for packfiles.

So the server builds a packfile containing all the objects and sends it to the client over the SSH connection.
git could unpack the objects from this packfile, but as we saw in the last post, it leaves them packed by default to save storage space.

We'll do the same, creating a `temp.pack` file in the packfile directory.
Since the packfile contents are sent to the SSH output, we can simply copy the output to a file:
```rust
const TEMP_PACK_FILE: &str = ".git/objects/pack/temp.pack";

impl Transport {
  fn fetch(&mut self) -> io::Result<()> {
    // ...

    let mut pack_file = File::create(TEMP_PACK_FILE)?;
    io::copy(&mut self.ssh_output, &mut pack_file)?;
    Ok(())
  }
}

fn main() -> io::Result<()> {
  // ...

  transport.fetch()
}
```

Running this program successfully downloads the pack file!
```
$ mkdir git
$ cd git
$ git init # create an empty git repository to test fetching all the objects
Initialized empty Git repository
$ git remote add origin git@github.com:git/git.git
$ cargo run
$ file .git/objects/pack/temp.pack
.git/objects/pack/temp.pack: Git pack, version 2, 324311 objects
```

## Saving refs

Now we have all the objects we need, but unfortunately trying to use them in a git command still doesn't work:
```
$ git log origin/main
fatal: ambiguous argument 'origin/main': unknown revision or path not in the working tree.
Use '--' to separate paths from revisions, like this:
'git <command> [<revision>...] -- [<file>...]'
```
This is because we haven't updated the "remote refs" that we received from the server.
For example, the server told us that `main` is currently at commit `74cc1aa55f30ed76424a0e7226ab519aa6265061`:
```
74cc1aa55f30ed76424a0e7226ab519aa6265061 refs/heads/main
```
So we need to store this remote ref in the local repository.

Back in post 1, we saw that the local branches (and refs in general) are stored in the `.git/refs` directory.
Each remote (e.g. `origin`) has its own subdirectory in `.git/refs` with all the refs fetched from the remote.

Here is code to create the ref files during the fetch:
```rust
use std::fs;
use std::path::Path;

const REMOTE_ORIGIN_REFS_DIRECTORY: &str = ".git/refs/remotes/origin";

fn save_remote_ref(branch: &str, hash: Hash) -> io::Result<()> {
  let origin_ref_path = Path::new(REMOTE_ORIGIN_REFS_DIRECTORY).join(branch);
  // Create .git/refs/remotes and .../origin if they don't exist.
  // Also, if the branch includes '/' (e.g. "feature/abc"), the path will be
  // .../feature/abc, so the "feature" directory must also be created.
  fs::create_dir_all(origin_ref_path.parent().unwrap())?;
  let mut origin_ref_file = File::create(origin_ref_path)?;
  write!(origin_ref_file, "{}\n", hash)
}

impl Transport {
  fn fetch(&mut self) -> io::Result<()> {
    // ...

    for (branch, hash) in branch_refs {
      save_remote_ref(branch, hash)?;
    }
    Ok(())
  }
}
```

Now, running our program records the remote refs:
```
$ ls -R .git/refs/remotes
origin

.git/refs/remotes/origin:
main   maint  master next   seen   todo
```

Let's try running the `git log` again.
This time, it fails with a different error: it knows that `origin/main` is commit `74cc1aa55f30ed76424a0e7226ab519aa6265061`, but it can't read that object.
```
$ git log origin/main
fatal: bad object origin/main
```
git can't find the object because we're missing a `.idx` file for the `temp.pack` file we created.
We'll fix this next.

## Building an index file

As we saw in the last post, scanning through a packfile is slow, so git depends on a corresponding "pack index" file to locate objects in the packfile.
The index file acts like a `HashMap<Hash, u64>`, making it fast to look up where an object is located in the corresponding packfile.
It can be generated from the packfile by decompressing (and un-deltifying, if necessary) each object in the pack and computing its hash.
The server doesn't send it because it doesn't contain any additional information, so we need to build it ourselves.

We'll use the code we wrote last time to read objects out of packfiles, with one main modification.
Before, we only wanted to unpack a single object, so if the object was a `HashDelta` or `OffsetDelta`, we had to unpack its base object, and its base object's base object, etc. until we found an undeltified object.
If we use this approach for all the objects in the packfile, we may recompute each base object many times.
For example, if both objects `B` and `C` are deltified with base object `A`, then unpacking the objects will unpack `A` 3 times (when computing each of `A`, `B`, and `C`).
And for `HashDelta`s that refer to base objects within the packfile, we can't even find the base object by hash because we haven't created a pack index yet!
So I've modified the code to remember the objects unpacked from the packfile so far by both hash and offset.
See the source code for the full details.

First we'll read the temporary packfile (see the last post for a detailed discussion of the packfile format):
```rust
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
  // Cache the unpacked objects by offset and hash
  let mut object_cache = PackObjectCache::default();
  // Count how many objects have a hash starting with each byte
  let mut first_byte_objects = [0u32; 1 << u8::BITS];
  // Store where each hash is located in the packfile
  // (the sorted version of this is the index)
  let mut object_offsets = Vec::with_capacity(total_objects as usize);
  // Unpack each object
  for _ in 0..total_objects {
    let offset = get_offset(&mut pack_file)?;
    let object = read_pack_object(&mut pack_file, offset, &mut object_cache)?;
    let object_hash = object.hash();
    first_byte_objects[object_hash.0[0] as usize] += 1;
    let offset = u32::try_from(offset).map_err(|_| {
      make_error("Packfile is too large")
    })?;
    object_offsets.push((object_hash, offset));
  }
  let pack_checksum = read_hash(&mut pack_file)?;
  assert!(at_end_of_stream(&mut pack_file)?);

  // TODO: produce index file

  Ok(pack_checksum)
}
```

Although the last post discussed version-2 index files, we will make a version-1 one for simplicity.
git can still understand them; the only restriction is that they can only represent offsets that fit in a `u32` (hence the check above).
Here's the implementation:
```rust
const TEMP_INDEX_FILE: &str = ".git/objects/pack/idx.pack";

fn build_pack_index() -> io::Result<Hash> {
  // ...

  let mut index_file = File::create(TEMP_INDEX_FILE)?;
  let mut cumulative_objects = 0;
  for objects in first_byte_objects {
    cumulative_objects += objects;
    // The number (u32) of hashes with first byte <= 0, 1, ..., 255
    index_file.write_all(&cumulative_objects.to_be_bytes())?;
  }
  // Each hash and its offset (u32) in the pack file,
  // sorted for efficient lookup
  object_offsets.sort();
  for (hash, offset) in object_offsets {
    index_file.write_all(&offset.to_be_bytes())?;
    index_file.write_all(&hash.0)?;
  }
  // A SHA-1 checksum of the pack file
  index_file.write_all(&pack_checksum.0)?;
  // TODO: this should be a SHA-1 hash of the contents of the index file.
  // But git doesn't check it when reading the index file, so we'll skip it.
  index_file.write_all(&[0; HASH_BYTES])?;
  Ok(pack_checksum)
}
```

And finally, we rename the temporary pack and index files with the pack checksum, like git does:
```rust
impl Transport {
  fn fetch(&mut self) -> io::Result<()> {
    // ...

    let pack_hash = build_pack_index()?;
    // Rename the packfile to, e.g.
    // pack-bda11b853cfa9131a39b2e3e55f15bb7f7485450.pack
    let pack_file_name = Path::new(PACKS_DIRECTORY)
      .join(format!("pack-{}{}", pack_hash, PACK_FILE_SUFFIX));
    fs::rename(TEMP_PACK_FILE, pack_file_name)?;
    // Rename the index file to, e.g.
    // pack-bda11b853cfa9131a39b2e3e55f15bb7f7485450.idx
    let index_file_name = Path::new(PACKS_DIRECTORY)
      .join(format!("pack-{}{}", pack_hash, INDEX_FILE_SUFFIX));
    fs::rename(TEMP_INDEX_FILE, index_file_name)?;

    // ...
  }
}
```

If we do another fetch, we generate an index file and our `git log` finally works!
If you're trying this at home, make sure to run in release mode, or otherwise it will be much too slow!
(The code could probably be sped up significantly by using `BufReader`s and `BufWriter`s with these files and the SSH output.)
```
$ ls -lh .git/objects/pack
total 394896
-rw-r--r--  1 csander  staff   7.4M Mar 19 15:56 pack-bda11b853cfa9131a39b2e3e55f15bb7f7485450.idx
-rw-r--r--  1 csander  staff   185M Mar 19 15:56 pack-bda11b853cfa9131a39b2e3e55f15bb7f7485450.pack
$ git log origin/main
commit 74cc1aa55f30ed76424a0e7226ab519aa6265061 (origin/master, origin/main)
Author: Junio C Hamano <gitster@pobox.com>
Date:   Wed Mar 16 17:45:59 2022 -0700

    The twelfth batch

    Signed-off-by: Junio C Hamano <gitster@pobox.com>
...
```
We can even use `git show` to show the diff of this commit, which requires reading commit, tree, and blob objects from the packfile:
```
$ git show origin/main
commit 74cc1aa55f30ed76424a0e7226ab519aa6265061
Author: Junio C Hamano <gitster@pobox.com>
Date:   Wed Mar 16 17:45:59 2022 -0700

    The twelfth batch

    Signed-off-by: Junio C Hamano <gitster@pobox.com>

diff --git a/Documentation/RelNotes/2.36.0.txt b/Documentation/RelNotes/2.36.0.txt
index 6b2c6bfcc7..d67727baa1 100644
--- a/Documentation/RelNotes/2.36.0.txt
+++ b/Documentation/RelNotes/2.36.0.txt
@@ -70,6 +70,10 @@ UI, Workflows & Features
  * The level of verbose output from the ort backend during inner merge
    has been aligned to that of the recursive backend.

+ * "git remote rename A B", depending on the number of remote-tracking
+   refs involved, takes long time renaming them.  The command has been
+   taught to show progress bar while making the user wait.
+

 Performance, Internal Implementation, Development Support etc.

@@ -122,6 +126,12 @@ Performance, Internal Implementation, Development Support etc.
  * Makefile refactoring with a bit of suffixes rule stripping to
    optimize the runtime overhead.

+ * "git stash drop" is reimplemented as an internal call to
+   reflog_delete() function, instead of invoking "git reflog delete"
+   via run_command() API.
+
+ * Count string_list items in size_t, not "unsigned int".
+

 Fixes since v2.35
 -----------------
@@ -299,6 +309,17 @@ Fixes since v2.35
    Adjustments have been made to accommodate these changes.
    (merge b0b70d54c4 fs/gpgsm-update later to maint).

+ * The untracked cache newly computed weren't written back to the
+   on-disk index file when there is no other change to the index,
+   which has been corrected.
+
+ * "git config -h" did not describe the "--type" option correctly.
+   (merge 5445124fad mf/fix-type-in-config-h later to maint).
+
+ * The way generation number v2 in the commit-graph files are
+   (not) handled has been corrected.
+   (merge 6dbf4b8172 ds/commit-graph-gen-v2-fixes later to maint).
+
  * Other code cleanup, docfix, build fix, etc.
    (merge cfc5cf428b jc/find-header later to maint).
    (merge 40e7cfdd46 jh/p4-fix-use-of-process-error-exception later to maint).
```

## Haves

Great, we can clone a real repository!

Now let's imagine there is a slight change to the repository (e.g. one commit is pushed to `main`).
If we do `Transport::fetch()` again, we'll download a new packfile with all the objects now in the remote repository.
This would work, but unfortunately we would end up with two copies of each object that was already in the repository!

We would definitely like to avoid wasting space storing duplicate objects.
We could do this by identifying the duplicate objects and making a new packfile without them.
But ideally the server wouldn't have sent them in the first place, as this makes the fetch unnecessarily slow.

In order for the server to know exactly which objects the packfile needs, the client needs to tell the server which ones it already has.
After the `want` chunks are sent in the transport protocol, the client informs the server of objects it already has by sending `have` chunks.
The haves are terminated by a `"done"` chunk.
The server responds with an `ACK` chunk if it recognizes any of the client's `have`s, or a `NAK` chunk otherwise.
(See the [`multi_ack` documentation](https://git-scm.com/docs/protocol-capabilities#_multi_ack) for the more complicated negotiation that git uses in practice.)

The client could tell the server every object it has, but there can easily be hundreds of thousands, and so this would still take a lot of space even at 20 bytes each.
git makes use of the fact that when the client receives objects from the server, it always gets exactly those that are referenced by one or more commits.
For example, suppose there are commits `C1`, `C2`, and `C3` with trees `T1`, `T2`, and `T3`, respectively, and a few blobs:
```
C1 <-- C2 <-- C3
|      |      |
v      v      v
T1     T2     T3
| \   /  \   /| \
v   v      v  v  v
B1  B2     B3 B4 B5
```
When the client sent `want C2` before, it received `C1`, `C2`, `T1`, `T2`, `B1`, `B2`, and `B3` because they `C2` (indirectly) references them.
So if the client tells the server it has `C2`, the server knows it has all these objects, but not `C3`, `T3`, `B4`, or `B5`.

Therefore, the client can just say the latest commit it has fetched on each remote branch and the server will know exactly which of its objects the client already has.
(git's implementation also checks for commits from the client that are on the remote without the client's knowledge.
For example, the client pushed to remote A and someone else then fetched and pushed to remote B.
But we won't worry about optimizing for that situation.)

We will send a `have` for the commit hash we have recorded for each remote branch:
```rust
use std::path::PathBuf;

impl Transport {
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

  fn fetch(&mut self) -> io::Result<()> {
    // ...

    self.send_wants(&wants, &use_capabilities)?;

    self.send_haves()?;

    // ...
  }
}
```

If we fetch the git repository again with no new commits, the server sends an empty packfile because the client already has all the required objects:
```
$ cargo run
$ ls -lh .git/objects/pack
total 410624
-rw-r--r--  1 csander  staff   1.0K Mar 19 17:29 pack-029d08823bd8a8eab510ad6ac75c823cfd3ed31e.idx
-rw-r--r--  1 csander  staff    32B Mar 19 17:29 pack-029d08823bd8a8eab510ad6ac75c823cfd3ed31e.pack
-rw-r--r--  1 csander  staff   7.4M Mar 19 16:38 pack-8641e8298f69b5dc78c3eb224dc508757f59a13f.idx
-rw-r--r--  1 csander  staff   185M Mar 19 16:37 pack-8641e8298f69b5dc78c3eb224dc508757f59a13f.pack
$ file .git/objects/pack/pack-029d08823bd8a8eab510ad6ac75c823cfd3ed31e.pack
.git/objects/pack/pack-029d08823bd8a8eab510ad6ac75c823cfd3ed31e.pack: Git pack, version 2, 0 objects
```

## Side-band progress updates

It may take a while for the server to prepare and transmit a packfile, so it's helpful to provide the user some progress updates.
The protocol we've seen so far doesn't allow for this, but there is yet another capability, [`side-band-64k`](https://git-scm.com/docs/protocol-capabilities#_side_band_side_band_64k), to enable it.

Instead of sending the packfile directly on the SSH connection, the server breaks it up and sends each piece inside a chunk.
Between packfile chunks, the server can send progress or error message chunks.
The first byte of each chunk indicates the type of chunk (1 for packfile data, 2 for progress message, or 3 for fatal error message).
The remainder of the chunk is either the next piece of the packfile or a message to print.
An empty chunk is sent to terminate the side-band chunks.

Here is the implementation:
```rust
const SIDE_BAND_CAPABILITY: &str = "side-band-64k";
const REQUESTED_CAPABILITIES: &[&str] = &["ofs-delta", SIDE_BAND_CAPABILITY];

impl Transport {
  fn receive_side_band_pack(&mut self, pack_file: &mut File) -> io::Result<()> {
    while let Some(chunk) = self.read_chunk()? {
      let (&chunk_type, chunk) = chunk.split_first().ok_or_else(|| {
        make_error("Missing side-band chunk type")
      })?;
      match chunk_type {
        // Packfile data
        1 => pack_file.write_all(chunk)?,
        // Progress message; print to stderr
        2 => io::stderr().write_all(chunk)?,
        // Fatal fetch error message
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
    // ...

    let mut pack_file = File::create(TEMP_PACK_FILE)?;
    // Check whether we were able to enable side-band-64k
    if capabilities.contains(SIDE_BAND_CAPABILITY) {
      // The packfile is wrapped in side-band chunks
      self.receive_side_band_pack(&mut pack_file)?;
    }
    else {
      // The SSH stream has the packfile contents
      io::copy(&mut self.ssh_output, &mut pack_file)?;
    }

    // ...
  }
}
```

If we now call `Transport::fetch()`, we see the server's progress indicators:
```
Enumerating objects: 324311, done.
Total 324311 (delta 0), reused 0 (delta 0), pack-reused 324311
```
Here, the server had already created a packfile with the required objects and is simply sending it to us.
If the git server needs to generate a new packfile, we will see additional status indicators, for example:
```
Enumerating objects: 7605, done.
Counting objects: 100% (630/630), done.
Compressing objects: 100% (292/292), done.
Total 7605 (delta 421), reused 448 (delta 333), pack-reused 6975
```
In the "Counting objects" phase, git is determining which objects it doesn't already have in packfiles (630 = 7605 - 6975).
In the "Compressing objects" phase, git is creating deltified representations for some of these new objects.

For long fetches, you may have noticed that these progress indicators update periodically.
If you're wondering how that works, it's by printing the `\r` (carriage return) character followed by the new contents of the line.
`\r` this resets the terminal's printing location to the start of the current line, but unlike `\n`, doesn't advance to the next line.

## push protocol

We've covered all of the major parts of a `git fetch` over the SSH transport.
But how does a `git push` work?
Perhaps unsurprisingly, git reuses much of the SSH protocol for pushes.
So much is the same that I don't think there's much to learn by implementing `git push` too.

The major differences between `fetch` and `push` are:
- The SSH command invokes `git-receive-pack` instead of `git-upload-pack`
- No `have` negotiation is required because the client already knows which of its commits the server has (since it pushed them)
- After receiving the list of refs from the server, the client indicates which ones it wants to create (e.g. new branch), update (e.g. new commit on branch), or delete (e.g. remove branch)
- The *client* sends the packfile of new objects to the *server*

## The end

And that's a wrap on the git internals series!
We learned how a large portion of git works under the hood, from the `.git` directory to how repository history is stored in objects, from how packfiles combine and compress objects to how a git client and server communicate to share a repository.
Hopefully the next time you run a git command you'll have a newfound understanding and appreciation for how it does its task.

Sorry these posts ended up being so long; there are just so many interesting pieces in the git puzzle!
Please let me know if there are any other git topics you'd like me to cover.
I have several other (hopefully shorter!) posts I'd like to write on a variety of topics, so stay tuned.
