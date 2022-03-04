from build_base import build

if __name__ == '__main__':
    build(output_folder_name="Mac (M1)",
          target_platform_name="macOS",
          python_platform_check_string="darwin",
          spec_files=[
              "palyanytsya.spec",
              "pyrizhok.spec"
          ])

