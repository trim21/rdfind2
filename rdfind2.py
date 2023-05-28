import contextlib
import dataclasses
import hashlib
import io
import os
import pathlib
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Tuple

import click
import tqdm

PROGRESS_SIZE = 128 * 1024 * 1024  # 512M
CHUNK_SIZE = 16 * 1024  # 16k
PARTIAL_SIZE = 16


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
                with tqdm.tqdm.wrapattr(
                        f,
                        "read",
                        total=self.size,
                        bar_format="{desc}: {percentage:3.0f}% {r_bar}",
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
            f.seek(int(size / 2), io.SEEK_SET)
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
@click.option("--make-hardlink", "hardlink", is_flag=True, default=False,help='used when you search duplicate files in same device')
@click.option("--delete", "delete", is_flag=True, default=False)
def rdfind2(location: Tuple[str], hardlink=False, delete=False):
    if hardlink and delete:
        click.secho("can't use '--make-hardlink' with '--delete'", fg="green", err=True)
    group_by_size = dedupe_by_size(location)

    groups: Dict[tuple, List[Entry]] = dedupe_by_head_tail(group_by_size)

    entry_groups: List[List[Entry]] = []

    for _, headGroups in sorted(groups.items(), reverse=True):
        if len(headGroups) == 1:
            continue

        entry_groups.append(headGroups)

    total = len(entry_groups)
    for i, entry_group in enumerate(entry_groups):
        click.secho(f"{i + 1}/{total}", fg="green")
        entry_grouped = compare_groups(entry_group)
        for g in entry_grouped:
            if len(g) == 1:
                continue

            if hardlink:
                print("link files:")
                for file in g:
                    click.secho(f"{file.path!s}", fg="red")

                link_src = g.pop()

                for file in g:
                    if link_src.inode == file.inode:
                        continue
                    if file.path.name.endswith(".rdfind2.old"):
                        click.secho(f"find internal temp file {file.path}", fg="red")
                        continue
                    temp_file_path = pathlib.Path(
                        file.path.with_name(file.path.name + ".rdfind2.old")
                    )
                    file.path.rename(temp_file_path)
                    os.link(src=link_src.path, dst=file.path)
                    temp_file_path.unlink()

            elif delete:
                g.pop()
                for file in g:
                    Stat.deleted += file.size
                    click.secho(f"remove file {file.path}", fg="red")
                    os.unlink(file.path)
            else:
                print("")
                print(tqdm.tqdm.format_sizeof(g[0].size, suffix="B", divisor=1024))
                for entry in sorted(g, key=lambda x: x.path):
                    print(entry.path)

    print(format_size(Stat.hashed))


def dedupe_by_size(locations: Iterable[str]):
    group_by_size: Dict[Tuple[int], List[Entry]] = defaultdict(list)

    with tqdm.tqdm(desc="get all files", ascii=True) as bar:
        for locate in locations:
            for top, _, files in os.walk(locate):
                t = pathlib.Path(top).absolute()
                for file in files:
                    bar.update()
                    p = t.joinpath(file)
                    stat = p.stat()
                    size = stat.st_size
                    group_by_size[(size,)].append(
                        Entry(path=p, size=size, inode=stat.st_ino)
                    )

    return {key: value for key, value in group_by_size.items() if len(value) > 1}


def dedupe_by_head_tail(
        group_by_size: Dict[Tuple[int], List[Entry]]
) -> Dict[Tuple[int, bytes, bytes], List[Entry]]:
    groups: Dict[Tuple[int, bytes, bytes], List[Entry]] = defaultdict(list)
    total = sum(len(x) for x in group_by_size.values())

    with tqdm.tqdm(
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
    return tqdm.tqdm.format_sizeof(n, "B", divisor=1024)


if __name__ == "__main__":
    rdfind2()
    print("hashed file size:", format_size(Stat.hashed))
    print("deleted file size:", format_size(Stat.deleted))
