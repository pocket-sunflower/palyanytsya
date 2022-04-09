from pathlib import Path
from typing import List

import requests
import validators


DEFAULT_MHDDOS_FILES_DIR = Path(Path(__file__).parent.parent / "files/")


def read_configuration_file_text(file_path_or_url: str) -> str | None:
    """
    Loads text content from the given file or URL.
    If given URL, will read text from it and return it.
    If given a relative path, will return the contents of the file at this path.
        If the file doesn't exist relative to workdir, will look for this file in default MHDDoS/files folder.
    If the file could not be located/read, will return None.

    Args:
        file_path_or_url: Absolute path, relative path or URL of the file.

    Returns:
        Text content of the file if it was located, None otherwise.
    """
    # if URL, load with a request
    if validators.url(file_path_or_url):
        response = requests.get(file_path_or_url, timeout=30)
        return response.text

    # if not URL, try to look locally
    path = Path(file_path_or_url)
    if path.is_file():
        return path.read_text()
    elif not path.is_absolute():
        # if not found relative to the workdir, look relative to 'MHDDoS/files'
        path = Path(DEFAULT_MHDDOS_FILES_DIR / path)
        if path.is_file():
            return path.read_text()

    return None


def read_configuration_file_lines(file_path_or_url: str, include_unique_only: bool = True) -> List[str]:
    """
    Reads lines from the provided local file or URL.
    Exits the program if the file is empty or could not be read.

    Args:
        file_path_or_url: Absolute path, relative path or URL of the file.
        include_unique_only: Ensures that the returned strings list contains only unique entries.

    Returns:
        List of lines read from the file.
    """

    file_text = read_configuration_file_text(file_path_or_url)
    if file_text is None:
        exit(f"Requested configuration file doesn't exist ('{file_path_or_url}').")
    if not file_text:
        exit(f"Requested configuration file is empty ('{file_path_or_url}').")

    lines = [s.strip() for s in file_text.split("\n")]

    if include_unique_only:
        lines = get_unique_entries_from_list(lines)

    return lines


def get_unique_entries_from_list(lines: List[str]) -> List[str]:
    unique_lines = set()
    for line in lines:
        if line not in unique_lines:
            unique_lines.add(line)

    return list(unique_lines)
