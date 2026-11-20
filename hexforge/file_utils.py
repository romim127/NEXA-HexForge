"""Secure file handling utilities for NEXA-HexForge.

This module provides secure file opening mechanisms that mitigate TOCTOU race conditions
and prevent symlink-based attacks. File validation is performed both before and after
opening to establish chain of custody for forensic analysis.

Limitations by platform:
- Linux/Unix: O_NOFOLLOW available via os.open(); fstat validation confirms file type
- Windows: No native O_NOFOLLOW equivalent; os.stat() used for pre-check, fstat() post-check
- Both platforms: Race conditions between open() and fstat() remain possible but are
  minimized by validating the descriptor immediately after opening
"""
from __future__ import annotations
import os
import stat
from pathlib import Path
from typing import BinaryIO


def secure_open_file(
    path: str | Path,
    max_size: int | None = None,
    purpose: str = "read"
) -> BinaryIO:
    """Open a file securely for reading, mitigating symlink attacks.

    This function validates that:
    1. The path exists and is accessible
    2. The path points to a regular file (not a symlink, device, pipe, etc.)
    3. The file size is within acceptable limits
    4. The file is opened without following symlinks (where supported)
    5. The descriptor points to a regular file (post-open validation)

    Security considerations:
    - On Linux/Unix: Uses O_NOFOLLOW flag to prevent symlink traversal
    - On Windows: Relies on os.stat() checks; O_NOFOLLOW not available
    - Race conditions: Minimized but not eliminated; fstat() immediately after open()
      confirms the opened file matches pre-open checks
    - For multi-read scenarios: Reuse the same descriptor to maintain consistency

    Args:
        path: File path (str or Path)
        max_size: Optional maximum file size (bytes) to allow. If None, no limit enforced.
        purpose: Descriptive purpose for error messages (e.g., "read", "export", "custody")

    Returns:
        Open file object in binary read mode

    Raises:
        FileNotFoundError: Path does not exist
        IsADirectoryError: Path points to a directory
        ValueError: Path is a symlink, not a regular file, exceeds max_size, or other validation error
        OSError: System-level file operation failures
    """
    source = Path(path)

    if not source.exists():
        raise FileNotFoundError(f"File not found: {source}")

    if source.is_symlink():
        raise ValueError(
            f"Symlink not allowed ({purpose}): {source} -> {source.resolve()}. "
            "Provide the target file path directly."
        )

    if source.is_dir():
        raise IsADirectoryError(f"Directory not allowed ({purpose}): {source}")

    if not source.is_file():
        raise ValueError(
            f"Not a regular file ({purpose}): {source}. "
            "Device files, pipes, sockets, etc. are not supported."
        )

    file_stat = source.stat()
    file_size = file_stat.st_size

    if max_size is not None and file_size > max_size:
        raise ValueError(
            f"File exceeds size limit ({purpose}): {source} is {file_size} bytes, "
            f"limit is {max_size} bytes."
        )

    flags = os.O_RDONLY | os.O_BINARY if hasattr(os, 'O_BINARY') else os.O_RDONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(source), flags)
    except OSError as e:
        raise OSError(f"Failed to open file ({purpose}): {source}: {e}") from e

    try:
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            raise ValueError(
                f"Post-open validation failed ({purpose}): {source} is not a regular file. "
                "File may have been replaced after initial check (race condition)."
            )

        if file_size != stat_result.st_size:
            raise ValueError(
                f"File size changed ({purpose}): {source} was {file_size} bytes, "
                f"now {stat_result.st_size} bytes. File may have been modified."
            )

        return os.fdopen(fd, 'rb', closefd=True)
    except (OSError, ValueError) as e:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def validate_file_path(
    path: str | Path,
    must_exist: bool = True,
    max_size: int | None = None,
    purpose: str = "general"
) -> Path:
    """Validate a file path without opening it.

    This function performs comprehensive validation checks without opening the file,
    suitable for path validation before passing to other functions.

    Args:
        path: File path to validate
        must_exist: If True, path must exist; if False, path must not exist
        max_size: Optional maximum file size limit
        purpose: Descriptive purpose for error messages

    Returns:
        Validated Path object

    Raises:
        FileNotFoundError: Path does not exist (if must_exist=True)
        FileExistsError: Path already exists (if must_exist=False)
        IsADirectoryError: Path is a directory
        ValueError: Path is a symlink, not a regular file, exceeds size limit, etc.
    """
    source = Path(path)

    if must_exist:
        if not source.exists():
            raise FileNotFoundError(f"File not found ({purpose}): {source}")

        if source.is_symlink():
            raise ValueError(
                f"Symlink not allowed ({purpose}): {source} -> {source.resolve()}"
            )

        if source.is_dir():
            raise IsADirectoryError(f"Directory not allowed ({purpose}): {source}")

        if not source.is_file():
            raise ValueError(
                f"Not a regular file ({purpose}): {source}"
            )

        if max_size is not None:
            file_size = source.stat().st_size
            if file_size > max_size:
                raise ValueError(
                    f"File exceeds size limit ({purpose}): {file_size} bytes > {max_size} bytes"
                )
    else:
        if source.exists():
            raise FileExistsError(f"File already exists ({purpose}): {source}")

    return source
