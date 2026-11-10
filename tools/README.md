# Maintenance tools

## `compare_section_versions.py`

Compare code-section counts from the current checkout with ethutils 0.1.3.

```text
usage: compare_section_versions.py [-h] [-j PROCESSES]
                                   [--log-directory LOG_DIRECTORY]
                                   folder

Compare current ethutils code-section counts with version 0.1.3.

positional arguments:
  folder                folder recursively searched for *.hex files

options:
  -h, --help            show this help message and exit
  -j PROCESSES, --processes PROCESSES
                        worker processes (default: all available processors)
  --log-directory LOG_DIRECTORY
                        directory for new_more.txt and new_less.txt (default:
                        current directory)
```

Run it from the repository root, for example:

```console
python tools/compare_section_versions.py --processes 8 path/to/bytecodes
```

The script writes one filename per line to `new_more.txt` and `new_less.txt`,
overwriting both logs at the start of each run. Use `--log-directory` to place
these files somewhere other than the current directory.
