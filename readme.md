# Utility to view binary files

Compiled with WebAssembly.

## Building

- Open a command-prompt and change to the root of the project.
- Run `\src\github\emsdk\emsdk_env` to setup the development environment.
- Build with the `build` command in the root (or `build opt`).
- Launch the server with `python serve.py` and open <http://localhost:8000>

You can also run `build msvc` to create a test program at `bin\tests.exe`.

## TODO

- Write some tests
- Extract the exports from a DLL
- Extract the symbols from an object file
- Handle LIB files (https://www.codeproject.com/Articles/1253835/The-structure-of-import-library-file-lib)


## Notes

- If random errors start occurring, run `emcc --clear-cache` and try again.
