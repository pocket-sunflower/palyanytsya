from build_base import build

if __name__ == '__main__':
    build(output_folder_name="Windows",
          target_platform_name="Windows",
          python_platform_check_string="win32",
          spec_files=[
              "palyanytsya.spec",
              "pyrizhok.spec"
          ])
