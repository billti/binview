// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#include <map>
#include <string>
#include <vector>

#include "win.h"

using std::string, std::vector, std::map;

void readFile(uintptr_t offset, int size) {
  // Windows binaries start with "MZ"
  if(size > sizeof(IMAGE_DOS_HEADER)) {
    IMAGE_DOS_HEADER* pHeader = (IMAGE_DOS_HEADER*)offset;
    if (pHeader->e_magic == IMAGE_DOS_SIGNATURE) {
      LOG("File appears to be a DOS/Windows binary");

      // The actual PE data is at the offset in the field below.
      int pe_offset = pHeader->e_lfanew;
      // IMAGE_NT_HEADERS32 & 64 start with the same signature, and have whether
      // they are 32 or 64 bit indicated by OptionalHeader.Magic (which is the
      // same offset for either bitness).
      IMAGE_NT_HEADERS32 *pe_header = (IMAGE_NT_HEADERS32*)(offset + pe_offset);

      if (pe_header->Signature == IMAGE_NT_SIGNATURE) {
        LOG("File appears to be a Windows NT binary");
        if (pe_header->FileHeader.SizeOfOptionalHeader == 0) {
          LOG("No optional header. Not an executable image");
        } else {
          IMAGE_SECTION_HEADER* first_section = GetFirstSection(pe_header);
          if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            LOG("Optional header indicates a 32-bit binary");
          } else if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            LOG("Optional header indicates a 64-bit binary");
            IMAGE_NT_HEADERS64 *pe_header64 = (IMAGE_NT_HEADERS64*)(offset + pe_offset);
          }
        }
      }
    } else {
      // Could be an .obj file
      IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)offset;
      if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
        LOG("Image appears to be an AMD64 COFF object file");
      } else if (file_header->Machine == IMAGE_FILE_MACHINE_I386) {
        LOG("Image appears to be an x86 COFF object file");
      } else {
        LOG("Unknown file type");
      }
    }
  }
  if (size < 80) return;
  char* buf = (char*)offset;
  buf[79] = '\0';
  LOG("File starts with: %s...", buf);
}

/* See PR at https://github.com/emscripten-core/emscripten/pull/9348
map<string, string> getFileProperties() {
  return {{"first", "a value"}, {"second", "next value"}};
}
*/

vector<string> getSectionNames() {
  return {".text", ".data", ".bss", ".const"};
}

struct Section {
  string name;
  int size;
  bool executable;
  bool writable;
};

vector<Section> getSections() {
  return {
    {".text", 4096, true, false},
    {".data", 8192, false, true}
  };
}

#if defined(__EMSCRIPTEN__)
using namespace emscripten;
EMSCRIPTEN_BINDINGS(my_module) {
  register_vector<std::string>("vector<string>");
  register_vector<Section>("vector<Section>");
  // register_map<std::string, std::string>("map<string, string>");

  value_object<Section>("Section")
    .field("name", &Section::name)
    .field("size", &Section::size)
    .field("executable", &Section::executable)
    .field("writable", &Section::writable);
  function("getSections", &getSections);
  // Allows for JS such as `Module.getSections.get(0)`, which will return a JS
  // object with properties {name: string, size: number, executable: boolean, writable: boolean}.

  function("readFile", &readFile);
  // function("getFileProperties", getFileProperties);
  function("getSectionNames", &getSectionNames);
}
#endif
