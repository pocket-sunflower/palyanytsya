import os
import shlex
import subprocess
import sys
from typing import List


def print_blue(message: str):
    print(f"\033[94m{message}\033[0m")


def print_green(message: str):
    print(f"\033[92m{message}\033[0m")


def print_fail(message: str):
    print(f"\033[91m{message}\033[0m")


def build(output_folder_name: str,
          target_platform_name: str,
          python_platform_check_string: str,
          spec_files: List[str]):
    print_blue(f"Preparing to build for {target_platform_name}...\n")

    if sys.platform != python_platform_check_string:
        print_fail(f"This build script must be run in {target_platform_name} to build the app correctly. Current platform is {sys.platform}.\n"
                   f"\n"
                   f"Build cancelled.")
        return

    def call_and_wait(command: str):
        print(f"\n> {command}\n")
        args = shlex.split(command)
        process = subprocess.Popen(args, stdout=subprocess.PIPE)
        return_code = process.wait()
        if return_code != 0:
            sys.exit(1)

    # Installs requirements, PyInstaller and packs the apps into single executables for Linux
    spec_root, _ = os.path.split(os.path.abspath(__file__))

    print_blue("Installing requirements...")

    call_and_wait(f'pip install -r "{spec_root}/../requirements.txt"')
    call_and_wait(f'pip install pyinstaller')

    print_green("Requirements installed successfully.")

    for spec_file in spec_files:
        print_blue(f"\nBuilding {spec_file}...")
        call_and_wait(f'pyinstaller --clean --noconfirm --distpath "{spec_root}/../executables/{output_folder_name}" --workpath "{spec_root}/../build" "{spec_root}/{spec_file}"')
        print_blue(f"\nBuilding {spec_file} complete.")

    print_green("\nBuild was completed successfully.")
