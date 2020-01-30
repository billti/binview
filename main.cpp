// Copyright 2020, Bill Ticehurst
#include <emscripten.h>
#include <emscripten/bind.h>

#include <math.h>
#include <stdio.h>

using namespace emscripten;

int int_sqrt(int x) {
  emscripten_log(1, "Trying this... %d", x);
  return sqrt(x);
}

int getFileSize(char* path) {
  FILE* file = fopen(path, "rb");
  if (!file) {
    return -1;
  }
  emscripten_log(1, "Opened the file successfully");
  fclose(file);
  return 0;
}

void readFile(int offset, int size) {
  if (size < 80) return;
  char* buf = (char*)offset;
  buf[79] = '\0';
  emscripten_log(1, "File starts with: %s...", buf);
}

EMSCRIPTEN_BINDINGS(my_module) {
  function("int_sqrt", &int_sqrt);
  function("getFileSize", &getFileSize, allow_raw_pointers());
  function("readFile", &readFile);
}
