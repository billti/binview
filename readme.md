# Utility to view binary files

Compiled with WebAssembly.

## Building

- Open a command-prompt and change to the root of the project.
- Run `\src\github\emsdk\emsdk_env` to setup the development environment.
- Build with the `build` command in the root (or `build opt`).
- Launch the server with `python serve.py` and open <http://localhost:8000>

## TODO

- Instantiate and call the Wasm export to return the first byte value.

## Notes

- embind docs: https://emscripten.org/docs/porting/connecting_cpp_and_javascript/embind.html
