from build_base import build

if __name__ == '__main__':
    build(output_folder_name="Linux",
          target_platform_name="Linux",
          python_platform_check_string="linux",
          spec_files=[
              "palyanytsya.spec",
              "pyrizhok.spec"
          ])

