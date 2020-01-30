@ECHO OFF
SETLOCAL
:: Run 'build' for a dev build, or 'build opt' for an optimized build.

IF DEFINED EMSDK GOTO build
ECHO Set up the EMSDK environment before running (e.g. run emsdk_env)
EXIT /B 1

:build
SET MY_CFLAGS=-o app.js -g4 -std=c++14 -fno-exceptions -fno-rtti -s ALLOW_MEMORY_GROWTH=1 -s FILESYSTEM=0
SET MY_CFLAGS=%MY_CFLAGS% --bind --pre-js pre.js -DEMSCRIPTEN_HAS_UNBOUND_TYPE_NAMES=0 --source-map-base "http://localhost:8000/"
:: SET EMCC_EXPORT='_int_sqrt', '_getFileSize', '_readFile'
IF "%1"=="opt" SET MY_CFLAGS=-O2 %MY_CFLAGS%

::emcc main.cpp -s "EXPORTED_FUNCTIONS=[%EMCC_EXPORT%]" -s "EXTRA_EXPORTED_RUNTIME_METHODS=['cwrap']"
em++ main.cpp %MY_CFLAGS%
