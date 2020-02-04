// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#include <map>
#include <string>
#include <vector>

#include "win.h"
#include "main.h"

using std::string, std::vector, std::map;

void LogSectionNames(IMAGE_NT_HEADERS *pe_header) {
  IMAGE_SECTION_HEADER* section = GetFirstSection(pe_header);
  WORD section_count = pe_header->FileHeader.NumberOfSections;
  char section_name[9];
  for(WORD i = 0; i < section_count; ++i, ++section) {
    // TODO: Handle '/' followed by address of section name.
    // See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
    memset(section_name, 0, 9);
    memcpy(section_name, section->Name, 8);
    LOG("Section %d: %s\n", i, section_name);
    LOG("  VirtualAddress: 0x%08X @ fileOffset: 0x%08X\n\n", section->VirtualAddress, section->PointerToRawData);
  }
}

IMAGE_SECTION_HEADER* GetSectionContainingRva(IMAGE_NT_HEADERS *pe_header, DWORD rva) {
  if (pe_header->FileHeader.NumberOfSections == 0) return nullptr;
  IMAGE_SECTION_HEADER* section = GetFirstSection(pe_header);
  WORD section_count = pe_header->FileHeader.NumberOfSections;
  for(WORD i = 0; i < section_count; ++i, ++section) {
    if (section->VirtualAddress <= rva &&
        (section->VirtualAddress + section->SizeOfRawData) > rva) {
      LOG("RVA 0x%08X found in section %d\n", rva, i);
      return section;
    }
  }
  LOG("RVA 0x%08X not found in any section\n", rva);
  return nullptr;
}

DWORD GetFileOffsetForRva(IMAGE_NT_HEADERS *pe_header, DWORD rva) {
  IMAGE_SECTION_HEADER* section = GetSectionContainingRva(pe_header, rva);
  if (section == nullptr) return 0;

  DWORD offset = section->PointerToRawData + (rva - section->VirtualAddress);
  LOG("RVA: 0x%08X at file offset: 0x%08X. (Section at VirtualAddress 0x%08X starts at file offset 0x%08X)\n",
      rva, offset, section->VirtualAddress, section->PointerToRawData);
  return offset;
}

void GetExports(uintptr_t file_addr) {
  IMAGE_DOS_HEADER* pHeader = (IMAGE_DOS_HEADER*)file_addr;
  if (pHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
  IMAGE_NT_HEADERS *pe_header = (IMAGE_NT_HEADERS*)(file_addr + pHeader->e_lfanew);
  if (pe_header->Signature != IMAGE_NT_SIGNATURE) return;
  IMAGE_DATA_DIRECTORY exports = GetDataDirectory(pe_header, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if (exports.Size == 0) {
    LOG("No exports present\n");
    return;
  }

  IMAGE_SECTION_HEADER *export_section = GetSectionContainingRva(pe_header, exports.VirtualAddress);

  // Give an RVA within the section, what is the offset from the file start
  int rva_to_offset = -(export_section->VirtualAddress) + export_section->PointerToRawData;
  DWORD export_dir_offset = exports.VirtualAddress + rva_to_offset;

  IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)(file_addr + export_dir_offset);
  char* filename = (char*)(export_dir->Name + rva_to_offset + file_addr);
  LOG("Exports file name: %s\n", filename);


  DWORD rvaFunctions = export_dir->AddressOfFunctions;
  DWORD* functions = (DWORD*)(file_addr + rvaFunctions + rva_to_offset);
  DWORD rvaNames = export_dir->AddressOfNames;
  DWORD* names = (DWORD*)(file_addr + rvaNames + rva_to_offset);
  DWORD rvaOrdinals = export_dir->AddressOfNameOrdinals;
  WORD* ordinals = (WORD*)(file_addr + rvaOrdinals + rva_to_offset);
  DWORD ordinalBase = export_dir->Base;
  DWORD functionCount = export_dir->NumberOfFunctions;
  DWORD nameCount = export_dir->NumberOfNames;

  // functions are in ordinal order (indexed from ordinalBase)
  for (int i = 0; i < functionCount; ++i) {
    DWORD fn_addr_rva = functions[i];
    if (fn_addr_rva == 0) continue; // May be empty entries for skipped ordinals

    // See if the function ordinal has an associated name. Search the ordinals array
    char* fn_name = nullptr;
    for(int j = 0; j < nameCount; ++j) {
      if (ordinals[j] == i) {
        DWORD fn_name_rva = names[j];
        fn_name = (char*)(file_addr + fn_name_rva + rva_to_offset);
      }
    }
    if (fn_name == nullptr) {
      LOG("Ordinal %d at RVA 0x%08X. No name\n", i + ordinalBase, fn_addr_rva);
    } else {
      LOG("Ordinal %d at RVA 0x%08X: %s\n", i + ordinalBase, fn_addr_rva, fn_name);
    }

    // It may point to another entry (a forwarder), not a function
    if (fn_addr_rva >= exports.VirtualAddress && fn_addr_rva < (exports.VirtualAddress + exports.Size)) {
      char* forwarded_to = (char*)(file_addr + fn_addr_rva + rva_to_offset);
      LOG("  Forwarded to: %s\n", forwarded_to);
    }
  }
}

string GetFileType(uintptr_t file_addr, size_t size) {
  // Windows binaries start with "MZ"
  if(size > sizeof(IMAGE_DOS_HEADER)) {
    IMAGE_DOS_HEADER* pHeader = (IMAGE_DOS_HEADER*)file_addr;
    if (pHeader->e_magic == IMAGE_DOS_SIGNATURE) {
      LOG("File appears to be a DOS/Windows binary\n");

      // The actual PE data is at the offset in the field below.
      int pe_offset = pHeader->e_lfanew;
      LOG("IMAGE_NT_HEADER offset is %d\n", pe_offset);
      // IMAGE_NT_HEADERS32 & 64 start with the same signature, and have whether
      // they are 32 or 64 bit indicated by OptionalHeader.Magic (which is the
      // same offset for either bitness).
      IMAGE_NT_HEADERS *pe_header = (IMAGE_NT_HEADERS*)(file_addr + pe_offset);
      if ((uintptr_t)pe_header + sizeof(IMAGE_NT_HEADERS64) > file_addr + size) {
        // Appears to start with the DOS stub, but not big enough for a PE/PE+
        return string{};
      }

      if (pe_header->Signature != IMAGE_NT_SIGNATURE) {
        LOG("File is not a Windows NT binary (missing signature)\n");
        return string{};
      }

      LOG("File appears to be a Windows NT binary\n");
      if (pe_header->FileHeader.SizeOfOptionalHeader == 0) {
        LOG("No optional header. Not an executable image\n");
        return string{};
      }
      if (pe_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        if (pe_header->FileHeader.Characteristics & IMAGE_FILE_DLL) {
          LOG("Image is a DLL\n");
        } else {
          LOG("Image is an executable (e.g. .exe");
        }
        GetExports(file_addr);
      }
      // pe_header->OptionalHeader.AddressOfEntryPoint == main or DllMain, or _crtMain or NULL (/noentry) etc.
      // IMAGE_SECTION_HEADER* first_section = GetFirstSection(pe_header);
      if (pe_header->OptionalHeader._32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        // if an exe, pe_header->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_{GUI,CUI} etc..
        LogSectionNames(pe_header);
        switch (pe_header->FileHeader.Machine) {
          case IMAGE_FILE_MACHINE_I386:
            LOG("Optional header indicates a 32-bit I386 binary\n");
            return string{PE_X86};
          default:
            LOG("Header indicates an unrecognized 32-bit binary\n");
            return string{};
        }
      } else if (pe_header->OptionalHeader._64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        LOG("Optional header indicates a 64-bit binary\n");
        LogSectionNames(pe_header);
        switch (pe_header->FileHeader.Machine) {
          case IMAGE_FILE_MACHINE_AMD64:
            LOG("Optional header indicates AMD64 binary\n");
            return string{PE_AMD64};
          case IMAGE_FILE_MACHINE_ARM64:
            LOG("Optional header indicates a ARM64 binary\n");
            return string{PE_ARM64};
          default:
            LOG("Header indicates an unrecognized 64-bit binary\n");
            return string{};
        }
      } else {
        LOG("OptionalHeader magic valid not recognized\n");
        return string{};
      }
    }
  }

  // Could be an .obj file
  if (size >= sizeof(IMAGE_FILE_HEADER)) {
    IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)file_addr;
    if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
      LOG("Image appears to be an AMD64 COFF object file\n");
      return string{COFF_AMD64};
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_I386) {
      LOG("Image appears to be an x86 COFF object file\n");
      return string{COFF_X86};
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_ARM64) {
      LOG("Image appears to be an ARM64 COFF object file\n");
      return string{COFF_ARM64};
    }
  }

  if (size >= 8 && strncmp((char*)file_addr, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) == 0) {
    LOG("Image appears to be an archive (.lib) file\n");
    return string{LIB};
  }

  LOG("Unknown file type.\n");
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
