// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#include <iostream>
#include <fstream>
#include <string>

#include "main.h"

using namespace std;

string FileType(const string& path) {
  std::cout << "Reading file at: " << path << std::endl;
  ifstream file(path);
  file.seekg(0, ios::end);
  size_t size = file.tellg();

  char* buffer = new char[size];
  file.seekg(0, ios::beg);
  file.read(buffer, size);
  file.close();

  string file_type = GetFileType((uintptr_t)buffer, size);
  delete[] buffer;
  std::cout << "File type returned: " << file_type << std::endl;
  return file_type;
}

int main() {
  string path = "./assets/v8_libbase.dll";
  FileType(path);

  path = "./assets/arm64_chkstk.obj";
  FileType(path);

  path = "./assets/x86_delayimp.lib";
  FileType(path);

  return 0;
}
