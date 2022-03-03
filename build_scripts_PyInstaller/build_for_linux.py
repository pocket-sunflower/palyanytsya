from build_scripts_PyInstaller.build_base import build

if __name__ == '__main__':
    build(
        output_folder_name="Linux",
        target_platform_name="Linux",
        python_platform_check_string="linux"
    )
