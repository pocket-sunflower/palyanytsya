import os
import subprocess
import sys


def build(output_folder_name: str, target_platform_name: str, python_platform_check_string: str):
    if sys.platform != python_platform_check_string:
        print(f"This build script must be run in {target_platform_name} to build the app correctly. Current platform is {sys.platform}.\n"
              f"\n"
              f"Build cancelled.")
        return

    # Installs PyInstaller and packs the apps into single executables for Linux
    spec_root, _ = os.path.split(os.path.abspath(__file__))
    subprocess.call(r"pip install pyinstaller")
    subprocess.call(f'pyinstaller --distpath "{spec_root}/../executables/{output_folder_name}" --workpath "{spec_root}/../build" "{spec_root}/palyanytsya.spec"')
    subprocess.call(f'pyinstaller --distpath "{spec_root}/../executables/{output_folder_name}" --workpath "{spec_root}/../build" "{spec_root}/pyrizhok.spec"')
