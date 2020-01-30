@ECHO OFF
SETLOCAL
:: Run 'build' for a dev build, or 'build opt' for an optimized build.

IF DEFINED EMSDK GOTO build
ECHO Set up the EMSDK environment before running (e.g. run emsdk_env)
EXIT /B 1

:build
SET EMCC_CFLAGS=-o app.js -g4 -fno-exceptions -fno-rtti -s ALLOW_MEMORY_GROWTH=1 -s FILESYSTEM=0
SET EMCC_CFLAGS=%EMCC_CFLAGS% --pre-js pre.js --source-map-base "http://localhost:8000/"
SET EMCC_EXPORT='_int_sqrt', '_getFileSize', '_readFile'
IF "%1"=="opt" SET EMCC_CFLAGS=-O2 %EMCC_CFLAGS%

emcc main.cpp -s "EXPORTED_FUNCTIONS=[%EMCC_EXPORT%]" -s "EXTRA_EXPORTED_RUNTIME_METHODS=['cwrap']"
