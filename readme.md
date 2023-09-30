# rdfind2

[![](https://img.shields.io/pypi/v/rdfind2.svg)](https://pypi.python.org/pypi/rdfind2)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/rdfind2)](https://pypi.org/project/rdfind2/)
![](https://img.shields.io/badge/License-MIT-blue.svg)

find duplicated files (in one fs) very fast.

rdfind2 will filter files by size, head, tail and inode.

Only hash full files content when it's necessary.

## Install

with pipx:

```shell
pipx install rdfind2
```

with pip:

```shell
pip install rdfind2
```

## Usage:

```text
Usage: rdfind2 [OPTIONS] LOCATION...

Options:
  --hardlink               make hardlink between duplicate.
  --delete                 delete duplicated files, keep only one file.
  --delete-from PATH       when using --delete flags, only delete files in
                           specific directory.
  --delete-ignore-inode    when using --delete, ignore file's inode attribute.
                           This means rdfind2 will keep only 1 file of already
                           hardlink-ed files.
  --min-file-size INTEGER
  --unsafe INTEGER RANGE   unsafe partial fast checksum, check only 1/N
                           content of this file. If pass --unsafe=1, it will
                           behave like safe hash  [x>=1]
  --ext TEXT               included files by extensions
  --ignore-ext TEXT        exclude files by extensions
  -v, --verbose            increase output level
  --dry-run
  --help                   Show this message and exit.
```
