"""Bounded streaming extraction of maximal printable ASCII and UTF-16LE runs.

Each continuous run is emitted once at its first byte offset, even when it spans
multiple input chunks. Values are capped; scanning continues to establish the
actual end of each run and the correct truncated flag. No sample is executed.
"""
from pathlib import Path

from .file_utils import secure_open_file

CHUNK = 1024 * 1024
MAX_RESULTS = 1000
MAX_STRING_BYTES = 4096


class _Run:
    """Incremental candidate: bounded prefix and unbounded integer length only."""

    def __init__(self, offset: int, encoding: str):
        self.offset = offset
        self.encoding = encoding
        self.length = 0
        self.prefix = bytearray()

    def add(self, value: int) -> None:
        self.length += 1
        cap = MAX_STRING_BYTES if self.encoding == "ASCII" else MAX_STRING_BYTES // 2
        if len(self.prefix) < cap:
            self.prefix.append(value)

    def result(self, min_length: int) -> dict | None:
        if self.length < min_length:
            return None
        return {
            "offset": self.offset,
            "encoding": self.encoding,
            "value": self.prefix.decode("ascii"),
            "truncated": self.length > (
                MAX_STRING_BYTES if self.encoding == "ASCII" else MAX_STRING_BYTES // 2
            ),
        }


def extract_strings(path: str | Path, min_length: int = 5, max_results: int = 200) -> list[dict]:
    """Return bounded, sorted maximal runs with exact absolute starting offsets.

    A run that exceeds MAX_STRING_BYTES is returned once, with a capped preview
    and truncated=True. UTF-16LE scans both byte alignments and stores only
    printable ASCII-range UTF-16LE code units (two bytes each). A long run is
    not split into artificial findings at chunk boundaries.
    """
    if type(min_length) is not int or not 4 <= min_length <= 128:
        raise ValueError("min_length debe estar entre 4 y 128.")
    if type(max_results) is not int or not 1 <= max_results <= MAX_RESULTS:
        raise ValueError("max_results debe estar entre 1 y 1000.")

    results: list[dict] = []
    ascii_run: _Run | None = None
    wide_runs: list[_Run | None] = [None, None]
    previous: int | None = None
    position = 0

    def emit(run: _Run | None) -> None:
        if run is None:
            return
        item = run.result(min_length)
        if item is not None:
            results.append(item)
            if len(results) > max_results:
                results.sort(key=lambda value: (value["offset"], value["encoding"]))
                results.pop()

    with secure_open_file(Path(path), purpose="string extraction") as stream:
        while block := stream.read(CHUNK):
            for byte in block:
                printable = 0x20 <= byte <= 0x7E
                if printable:
                    if ascii_run is None:
                        ascii_run = _Run(position, "ASCII")
                    ascii_run.add(byte)
                else:
                    emit(ascii_run)
                    ascii_run = None

                # Every adjacent pair has exactly one of two possible UTF-16LE
                # alignments. Feed each alignment its non-overlapping pairs.
                if previous is not None:
                    alignment = (position - 1) & 1
                    if 0x20 <= previous <= 0x7E and byte == 0:
                        if wide_runs[alignment] is None:
                            wide_runs[alignment] = _Run(position - 1, "UTF-16LE")
                        wide_runs[alignment].add(previous)
                    else:
                        emit(wide_runs[alignment])
                        wide_runs[alignment] = None
                previous = byte
                position += 1

            # Do not flush at CHUNK boundaries: runs continue into next block.

    emit(ascii_run)
    for run in wide_runs:
        emit(run)
    results.sort(key=lambda item: (item["offset"], item["encoding"]))
    return results[:max_results]
