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

```shell
rdfind2 [--make-hardlink --delete] ./dir1 ./dir2 ...directory 
```
