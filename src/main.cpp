// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#include <map>
#include <string>
#include <vector>

#include "win.h"
#include "main.h"

using std::string, std::vector, std::map;

string GetFileType(uintptr_t file_addr, size_t size) {
  // Windows binaries start with "MZ"
  if(size > sizeof(IMAGE_DOS_HEADER)) {
    IMAGE_DOS_HEADER* pHeader = (IMAGE_DOS_HEADER*)file_addr;
    if (pHeader->e_magic == IMAGE_DOS_SIGNATURE) {
      LOG("File appears to be a DOS/Windows binary");

      // The actual PE data is at the offset in the field below.
      int pe_offset = pHeader->e_lfanew;
      // IMAGE_NT_HEADERS32 & 64 start with the same signature, and have whether
      // they are 32 or 64 bit indicated by OptionalHeader.Magic (which is the
      // same offset for either bitness).
      IMAGE_NT_HEADERS32 *pe_header = (IMAGE_NT_HEADERS32*)(file_addr + pe_offset);
      if ((uintptr_t)pe_header + sizeof(IMAGE_NT_HEADERS64) > file_addr + size) {
        // Appears to start with the DOS stub, but not big enough for a PE/PE+
        return string{};
      }

      if (pe_header->Signature != IMAGE_NT_SIGNATURE) {
        LOG("File is not a Windows NT binary (missing signature)");
        return string{};
      }

      LOG("File appears to be a Windows NT binary");
      if (pe_header->FileHeader.SizeOfOptionalHeader == 0) {
        LOG("No optional header. Not an executable image");
        return string{};
      }
      // IMAGE_SECTION_HEADER* first_section = GetFirstSection(pe_header);
      if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        switch (pe_header->FileHeader.Machine) {
          case IMAGE_FILE_MACHINE_I386:
            LOG("Optional header indicates a 32-bit I386 binary");
            return string{PE_X86};
          default:
            LOG("Header indicates an unrecognized 32-bit binary");
            return string{};
        }
      } else if (pe_header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        LOG("Optional header indicates a 64-bit binary");
        switch (pe_header->FileHeader.Machine) {
          case IMAGE_FILE_MACHINE_AMD64:
            LOG("Optional header indicates AMD64 binary");
            return string{PE_AMD64};
          case IMAGE_FILE_MACHINE_ARM64:
            LOG("Optional header indicates a ARM64 binary");
            return string{PE_ARM64};
          default:
            LOG("Header indicates an unrecognized 64-bit binary");
            return string{};
        }
      } else {
        LOG("OptionalHeader magic valid not recognized");
        return string{};
      }
    }
  }

  // Could be an .obj file
  if (size >= sizeof(IMAGE_FILE_HEADER)) {
    IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)file_addr;
    if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
      LOG("Image appears to be an AMD64 COFF object file");
      return string{COFF_AMD64};
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_I386) {
      LOG("Image appears to be an x86 COFF object file");
      return string{COFF_X86};
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_ARM64) {
      LOG("Image appears to be an ARM64 COFF object file");
      return string{COFF_ARM64};
    }
  }

  if (size >= 8 && strncmp((char*)file_addr, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) == 0) {
    LOG("Image appears to be an archive (.lib) file");
    return string{LIB};
  }

  LOG("Unknown file type.");
  return string{};
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

  function("GetFileType", &GetFileType);
  // function("getFileProperties", getFileProperties);
  function("getSectionNames", &getSectionNames);
}
#endif
