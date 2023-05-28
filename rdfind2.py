import contextlib
import dataclasses
import hashlib
import io
import os
import pathlib
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

import click
from tqdm import tqdm


PROGRESS_SIZE = 128 * 1024 * 1024  # 512M
CHUNK_SIZE = 16 * 1024  # 16k
PARTIAL_SIZE = 16
SMALL_FILE_THRESHOLD = 256 * 1024 * 1024  # 256 mb


@dataclasses.dataclass
class Entry:
    path: pathlib.Path
    size: int
    inode: int

    head_middle_and_tail: Tuple[bytes, bytes, bytes] = None

    b2sum: Optional[str] = None

    @property
    def head(self):
        if self.head_middle_and_tail:
            return self.head_middle_and_tail[0]
        self.head_middle_and_tail = self.read_partial(self.path, self.size)
        return self.head_middle_and_tail[0]

    @property
    def middle(self):
        if self.head_middle_and_tail:
            return self.head_middle_and_tail[1]
        self.head_middle_and_tail = self.read_partial(self.path, self.size)
        return self.head_middle_and_tail[1]

    @property
    def tail(self):
        if self.head_middle_and_tail:
            return self.head_middle_and_tail[2]
        self.head_middle_and_tail = self.read_partial(self.path, self.size)
        return self.head_middle_and_tail[2]

    def calculate_b2sum(self):
        h = hashlib.blake2b()

        with self.open() as f:
            while data := f.read(CHUNK_SIZE):
                h.update(data)

        self.b2sum = h.hexdigest()

        return self.b2sum

    @contextlib.contextmanager
    def open(self) -> io.BytesIO:
        if self.size > PROGRESS_SIZE:
            with self.path.open("rb") as f:
                with tqdm.wrapattr(
                        f,
                        "read",
                        total=self.size,
                        ascii=True,
                        leave=False,
                        position=1,
                ) as reader:
                    yield reader
            return
        with self.path.open("rb") as f:
            yield f

    @property
    def check_key(self) -> tuple:
        return self.size, self.head, self.middle, self.tail

    @staticmethod
    def read_partial(p: pathlib.Path, size: int) -> Tuple[bytes, bytes, bytes]:
        with p.open("rb", buffering=0) as f:
            head = f.read(PARTIAL_SIZE)
            f.seek(size // 2, io.SEEK_SET)
            middle = f.read(PARTIAL_SIZE)
            f.seek(-min(PARTIAL_SIZE, size), io.SEEK_END)
            tail = f.read(PARTIAL_SIZE)
        return head, middle, tail


@click.command()
@click.argument(
    "location",
    required=True,
    nargs=-1,
    type=click.Path(exists=True, file_okay=False, readable=True, resolve_path=True),
)
@click.option("--make-hardlink", "hardlink", is_flag=True, default=False,
              help='used when you search duplicate files in same device')
@click.option("--delete", "delete", is_flag=True, default=False)
@click.option('--file-size-threshold', 'threshold', default=SMALL_FILE_THRESHOLD, type=int)
def rdfind2(location: Tuple[str], threshold: int, hardlink=False, delete=False):
    if hardlink and delete:
        click.secho("can't use '--make-hardlink' with '--delete'", fg="green", err=True)
    group_by_size = dedupe_by_size(location)

    if threshold:
        group_by_size = {key: value for key, value in group_by_size.items() if key >= threshold}

    groups: Dict[tuple, List[Entry]] = dedupe_by_head_tail(group_by_size)

    entry_groups: List[List[Entry]] = []

    for _, headGroups in sorted(groups.items(), reverse=True):
        if len(headGroups) == 1:
            continue

        entry_groups.append(headGroups)

    click.secho("check file hashed", fg='cyan')
    for entry_group in tqdm(entry_groups, ascii=True, position=0):
        entry_grouped = compare_groups(entry_group)
        for g in entry_grouped:
            if len(g) == 1:
                continue

            if hardlink:
                tqdm.write("link files:")

                link_src = g.pop()
                tqdm.write(click.style(f"hard link target file {link_src.path!s}", fg="green"))
                for file in g:
                    tqdm.write(click.style(f"{file.path!s}", fg="red"))

                for file in g:
                    if link_src.inode == file.inode:
                        continue
                    if file.path.name.endswith(".rdfind2.old"):
                        tqdm.write(click.style(f"find internal temp file {file.path!s}", fg="red"))
                        continue
                    temp_file_path = pathlib.Path(
                        file.path.with_name(file.path.name + ".rdfind2.old")
                    )
                    file.path.rename(temp_file_path)
                    os.link(src=link_src.path, dst=file.path)
                    temp_file_path.unlink()

            elif delete:
                link_src = g.pop()
                tqdm.write(click.style(f"keep file {link_src.path}", fg="green"))
                for file in g:
                    Stat.deleted += file.size
                    tqdm.write(click.style(f"remove file {file.path}", fg="red"))
                    os.unlink(file.path)
            else:
                tqdm.write(tqdm.format_sizeof(g[0].size, suffix="B", divisor=1024))
                for entry in sorted(g, key=lambda x: x.path):
                    tqdm.write(str(entry.path))

    print("hashed file size:", format_size(Stat.hashed))
    if delete:
        print("deleted file size:", format_size(Stat.deleted))


def dedupe_by_size(locations: Iterable[str]) -> Dict[int, List[Entry]]:
    group_by_size: Dict[int, List[Entry]] = defaultdict(list)

    with tqdm(desc="get all files", ascii=True) as bar:
        for locate in locations:
            for top, _, files in os.walk(locate):
                t = pathlib.Path(top).absolute()
                for file in files:
                    bar.update()
                    p = t.joinpath(file)
                    stat = p.stat()
                    size = stat.st_size
                    group_by_size[size].append(
                        Entry(path=p, size=size, inode=stat.st_ino)
                    )

    return {key: value for key, value in group_by_size.items() if len(value) > 1}


def dedupe_by_head_tail(
        group_by_size: Dict[Tuple[int], List[Entry]]
) -> Dict[Tuple[int, bytes, bytes], List[Entry]]:
    groups: Dict[Tuple[int, bytes, bytes], List[Entry]] = defaultdict(list)
    total = sum(len(x) for x in group_by_size.values())

    with tqdm(
            total=total,
            desc="dedupe by file head/tail",
            ascii=True,
    ) as bar:
        for _, sizeGroups in sorted(group_by_size.items()):
            for e in sizeGroups:
                bar.update()
                groups[e.check_key].append(e)

    return groups


class Stat:
    hashed = 0
    deleted = 0


def compare_groups(group: List[Entry]) -> List[List[Entry]]:
    inode_group: Dict[int, List[Entry]] = defaultdict(list)
    for e in group:
        inode_group[e.inode].append(e)

    if len(inode_group) == 1:
        return []

    hash_map: Dict[int, str] = {}
    for inode, files in inode_group.items():
        Stat.hashed += files[0].size
        hash_map[inode] = files[0].calculate_b2sum()

    result = defaultdict(list)
    for e in group:
        hash = hash_map[e.inode]
        result[hash].append(e)

    return list(result.values())


def format_size(n: int):
    return tqdm.format_sizeof(n, "B", divisor=1024)


if __name__ == "__main__":
    rdfind2()
