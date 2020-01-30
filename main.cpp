// Copyright 2020, Bill Ticehurst
#include <emscripten.h>

#include <math.h>
#include <stdio.h>

extern "C" {
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
    if (size < 10) return;
    char* buf = (char*)offset;
    buf[9] = '\0';
    emscripten_log(1, "File starts with: %s...", buf);
  }
}
