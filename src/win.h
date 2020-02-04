// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

// See https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
// Also https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
#pragma once

#include "common.h"
#include "win-constants.h"

using BOOL      = int;
using BYTE      = unsigned char;
using CHAR      = char;
using DWORD     = unsigned int;
using LONG      = int;
using PVOID     = void*;
using SHORT     = short;
using ULONGLONG = unsigned long long;
using VOID      = void;
using WCHAR     = unsigned short;
using WORD      = unsigned short;

#define NTAPI
#define UNALIGNED

struct GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
};
static_assert(sizeof(GUID) == 16);
using CLSID = GUID;

struct IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD e_magic;              // Magic number
    WORD e_cblp;               // Bytes on last page of file
    WORD e_cp;                 // Pages in file
    WORD e_crlc;               // Relocations
    WORD e_cparhdr;            // Size of header in paragraphs
    WORD e_minalloc;           // Minimum extra paragraphs needed
    WORD e_maxalloc;           // Maximum extra paragraphs needed
    WORD e_ss;                 // Initial (relative) SS value
    WORD e_sp;                 // Initial SP value
    WORD e_csum;               // Checksum
    WORD e_ip;                 // Initial IP value
    WORD e_cs;                 // Initial (relative) CS value
    WORD e_lfarlc;             // File address of relocation table
    WORD e_ovno;               // Overlay number
    WORD e_res[4];             // Reserved words
    WORD e_oemid;              // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;            // OEM information; e_oemid specific
    WORD e_res2[10];           // Reserved words
    LONG e_lfanew;             // File address of new exe header
};
static_assert(sizeof(IMAGE_DOS_HEADER) == 64);

struct IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
};
static_assert(sizeof(IMAGE_FILE_HEADER) == 20);

struct IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
};
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

struct IMAGE_OPTIONAL_HEADER32 {
    //
    // Standard fields.
    //
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    //
    // NT additional fields.
    //
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 224);

struct IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
static_assert(sizeof(IMAGE_OPTIONAL_HEADER64) == 240);

struct IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS {
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  union {
    IMAGE_OPTIONAL_HEADER32 _32;
    IMAGE_OPTIONAL_HEADER64 _64;
  } OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    BYTE    Name[8];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;         // Size of data for the section in the file
    DWORD   PointerToRawData;      // File offset where data for the section starts
    DWORD   PointerToRelocations;  // File offset to an array of IMAGE_RELOCATION structures if not 0. (.obj files only)
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;   // Number of structures pointed to by PointerToRelocations
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
};
static_assert(sizeof(IMAGE_SECTION_HEADER) == 40);

inline bool Is32Bit(IMAGE_NT_HEADERS* pe_header) {
    return pe_header->OptionalHeader._32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
}

inline IMAGE_DATA_DIRECTORY GetDataDirectory(IMAGE_NT_HEADERS* pe_header, int index) {
  if (Is32Bit(pe_header)) {
    return pe_header->OptionalHeader._32.DataDirectory[index];
  } else {
    return pe_header->OptionalHeader._64.DataDirectory[index];
  }
}

inline IMAGE_SECTION_HEADER* GetFirstSection(IMAGE_NT_HEADERS* nt_header) {
    // nt_header->FileHeader.NumberOfSections -> How many total sections
    uintptr_t result =
        (uintptr_t)nt_header + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
        + nt_header->FileHeader.SizeOfOptionalHeader;
    return (IMAGE_SECTION_HEADER*)result;
}

//
// DLL support.
//

// Export Format
struct IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;                   // RVA to the ASCII string for the DLL name
    DWORD   Base;
    DWORD   NumberOfFunctions;      // # of entries in the Export Address Table (EAT)
    DWORD   NumberOfNames;          // # of entries in the Export Names Table (ENT)
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
};

// Import Format
struct IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
};

// #include "pshpack8.h"                       // Use align 8 for the 64-bit IAT.

struct IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
};
// #include "poppack.h"                        // Back to 4 byte packing

struct IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
};

//
// New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
//
struct IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    NumberOfModuleForwarderRefs;
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
};

struct IMAGE_BOUND_FORWARDER_REF {
    DWORD   TimeDateStamp;
    WORD    OffsetModuleName;
    WORD    Reserved;
};
// #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
// #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
// #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
// #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

////////////////// Checked up to here. Below is a copy and maybe unnecessary.

// typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
//     WORD   Magic;
//     BYTE   MajorLinkerVersion;
//     BYTE   MinorLinkerVersion;
//     DWORD  SizeOfCode;
//     DWORD  SizeOfInitializedData;
//     DWORD  SizeOfUninitializedData;
//     DWORD  AddressOfEntryPoint;
//     DWORD  BaseOfCode;
//     DWORD  BaseOfData;
//     DWORD  BaseOfBss;
//     DWORD  GprMask;
//     DWORD  CprMask[4];
//     DWORD  GpValue;
// } IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;


// #ifdef _WIN64
// typedef IMAGE_OPTIONAL_HEADER64             IMAGE_OPTIONAL_HEADER;
// typedef PIMAGE_OPTIONAL_HEADER64            PIMAGE_OPTIONAL_HEADER;
// #define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR64_MAGIC
// #else
// typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
// typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;
// #define IMAGE_NT_OPTIONAL_HDR_MAGIC         IMAGE_NT_OPTIONAL_HDR32_MAGIC
// #endif


// typedef struct _IMAGE_ROM_HEADERS {
//     IMAGE_FILE_HEADER FileHeader;
//     IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
// } IMAGE_ROM_HEADERS, *PIMAGE_ROM_HEADERS;

// #ifdef _WIN64
// typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
// typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
// #else
// typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
// typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
// #endif


// //
// // Non-COFF Object file header
// //

// typedef struct ANON_OBJECT_HEADER {
//     WORD    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
//     WORD    Sig2;            // Must be 0xffff
//     WORD    Version;         // >= 1 (implies the CLSID field is present)
//     WORD    Machine;
//     DWORD   TimeDateStamp;
//     CLSID   ClassID;         // Used to invoke CoCreateInstance
//     DWORD   SizeOfData;      // Size of data that follows the header
// } ANON_OBJECT_HEADER;

// typedef struct ANON_OBJECT_HEADER_V2 {
//     WORD    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
//     WORD    Sig2;            // Must be 0xffff
//     WORD    Version;         // >= 2 (implies the Flags field is present - otherwise V1)
//     WORD    Machine;
//     DWORD   TimeDateStamp;
//     CLSID   ClassID;         // Used to invoke CoCreateInstance
//     DWORD   SizeOfData;      // Size of data that follows the header
//     DWORD   Flags;           // 0x1 -> contains metadata
//     DWORD   MetaDataSize;    // Size of CLR metadata
//     DWORD   MetaDataOffset;  // Offset of CLR metadata
// } ANON_OBJECT_HEADER_V2;

// typedef struct ANON_OBJECT_HEADER_BIGOBJ {
//    /* same as ANON_OBJECT_HEADER_V2 */
//     WORD    Sig1;            // Must be IMAGE_FILE_MACHINE_UNKNOWN
//     WORD    Sig2;            // Must be 0xffff
//     WORD    Version;         // >= 2 (implies the Flags field is present)
//     WORD    Machine;         // Actual machine - IMAGE_FILE_MACHINE_xxx
//     DWORD   TimeDateStamp;
//     CLSID   ClassID;         // {D1BAA1C7-BAEE-4ba9-AF20-FAF66AA4DCB8}
//     DWORD   SizeOfData;      // Size of data that follows the header
//     DWORD   Flags;           // 0x1 -> contains metadata
//     DWORD   MetaDataSize;    // Size of CLR metadata
//     DWORD   MetaDataOffset;  // Offset of CLR metadata

//     /* bigobj specifics */
//     DWORD   NumberOfSections; // extended from WORD
//     DWORD   PointerToSymbolTable;
//     DWORD   NumberOfSymbols;
// } ANON_OBJECT_HEADER_BIGOBJ;


// //
// // Symbol format.
// //

// typedef struct _IMAGE_SYMBOL {
//     union {
//         BYTE    ShortName[8];
//         struct {
//             DWORD   Short;     // if 0, use LongName
//             DWORD   Long;      // offset into string table
//         } Name;
//         DWORD   LongName[2];    // PBYTE [2]
//     } N;
//     DWORD   Value;
//     SHORT   SectionNumber;
//     WORD    Type;
//     BYTE    StorageClass;
//     BYTE    NumberOfAuxSymbols;
// } IMAGE_SYMBOL;
// typedef IMAGE_SYMBOL UNALIGNED *PIMAGE_SYMBOL;

// #define IMAGE_SIZEOF_SYMBOL                  18

// typedef struct _IMAGE_SYMBOL_EX {
//     union {
//         BYTE     ShortName[8];
//         struct {
//             DWORD   Short;     // if 0, use LongName
//             DWORD   Long;      // offset into string table
//         } Name;
//         DWORD   LongName[2];    // PBYTE  [2]
//     } N;
//     DWORD   Value;
//     LONG    SectionNumber;
//     WORD    Type;
//     BYTE    StorageClass;
//     BYTE    NumberOfAuxSymbols;
// } IMAGE_SYMBOL_EX;
// typedef IMAGE_SYMBOL_EX UNALIGNED *PIMAGE_SYMBOL_EX;

// // MACROS

// // Basic Type of  x
// #define BTYPE(x) ((x) & N_BTMASK)

// // Is x a pointer?
// #ifndef ISPTR
// #define ISPTR(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_POINTER << N_BTSHFT))
// #endif

// // Is x a function?
// #ifndef ISFCN
// #define ISFCN(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_FUNCTION << N_BTSHFT))
// #endif

// // Is x an array?

// #ifndef ISARY
// #define ISARY(x) (((x) & N_TMASK) == (IMAGE_SYM_DTYPE_ARRAY << N_BTSHFT))
// #endif

// // Is x a structure, union, or enumeration TAG?
// #ifndef ISTAG
// #define ISTAG(x) ((x)==IMAGE_SYM_CLASS_STRUCT_TAG || (x)==IMAGE_SYM_CLASS_UNION_TAG || (x)==IMAGE_SYM_CLASS_ENUM_TAG)
// #endif

// #ifndef INCREF
// #define INCREF(x) ((((x)&~N_BTMASK)<<N_TSHIFT)|(IMAGE_SYM_DTYPE_POINTER<<N_BTSHFT)|((x)&N_BTMASK))
// #endif
// #ifndef DECREF
// #define DECREF(x) ((((x)>>N_TSHIFT)&~N_BTMASK)|((x)&N_BTMASK))
// #endif

// // #include <pshpack2.h>

// typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
//     BYTE  bAuxType;                  // IMAGE_AUX_SYMBOL_TYPE
//     BYTE  bReserved;                 // Must be 0
//     DWORD SymbolTableIndex;
//     BYTE  rgbReserved[12];           // Must be 0
// } IMAGE_AUX_SYMBOL_TOKEN_DEF;

// typedef IMAGE_AUX_SYMBOL_TOKEN_DEF UNALIGNED *PIMAGE_AUX_SYMBOL_TOKEN_DEF;

// // #include <poppack.h>

// //
// // Auxiliary entry format.
// //

// typedef union _IMAGE_AUX_SYMBOL {
//     struct {
//         DWORD    TagIndex;                      // struct, union, or enum tag index
//         union {
//             struct {
//                 WORD    Linenumber;             // declaration line number
//                 WORD    Size;                   // size of struct, union, or enum
//             } LnSz;
//            DWORD    TotalSize;
//         } Misc;
//         union {
//             struct {                            // if ISFCN, tag, or .bb
//                 DWORD    PointerToLinenumber;
//                 DWORD    PointerToNextFunction;
//             } Function;
//             struct {                            // if ISARY, up to 4 dimen.
//                 WORD     Dimension[4];
//             } Array;
//         } FcnAry;
//         WORD    TvIndex;                        // tv index
//     } Sym;
//     struct {
//         BYTE    Name[IMAGE_SIZEOF_SYMBOL];
//     } File;
//     struct {
//         DWORD   Length;                         // section length
//         WORD    NumberOfRelocations;            // number of relocation entries
//         WORD    NumberOfLinenumbers;            // number of line numbers
//         DWORD   CheckSum;                       // checksum for communal
//         SHORT   Number;                         // section number to associate with
//         BYTE    Selection;                      // communal selection type
// 	BYTE    bReserved;
// 	SHORT   HighNumber;                     // high bits of the section number
//     } Section;
//     IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
//     struct {
//         DWORD crc;
//         BYTE  rgbReserved[14];
//     } CRC;
// } IMAGE_AUX_SYMBOL;
// typedef IMAGE_AUX_SYMBOL UNALIGNED *PIMAGE_AUX_SYMBOL;

// typedef union _IMAGE_AUX_SYMBOL_EX {
//     struct {
//         DWORD   WeakDefaultSymIndex;                       // the weak extern default symbol index
//         DWORD   WeakSearchType;
//         BYTE    rgbReserved[12];
//     } Sym;
//     struct {
//         BYTE    Name[sizeof(IMAGE_SYMBOL_EX)];
//     } File;
//     struct {
//         DWORD   Length;                         // section length
//         WORD    NumberOfRelocations;            // number of relocation entries
//         WORD    NumberOfLinenumbers;            // number of line numbers
//         DWORD   CheckSum;                       // checksum for communal
//         SHORT   Number;                         // section number to associate with
//         BYTE    Selection;                      // communal selection type
//         BYTE    bReserved;
//         SHORT   HighNumber;                     // high bits of the section number
//         BYTE    rgbReserved[2];
//     } Section;
//     struct{
//         IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
//         BYTE  rgbReserved[2];
//     } DUMMYSTRUCTNAME;
//     struct {
//         DWORD crc;
//         BYTE  rgbReserved[16];
//     } CRC;
// } IMAGE_AUX_SYMBOL_EX;
// typedef IMAGE_AUX_SYMBOL_EX UNALIGNED *PIMAGE_AUX_SYMBOL_EX;

// typedef enum IMAGE_AUX_SYMBOL_TYPE {
//     IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
// } IMAGE_AUX_SYMBOL_TYPE;

// //
// // Relocation format.
// //

// typedef struct _IMAGE_RELOCATION {
//     union {
//         DWORD   VirtualAddress;
//         DWORD   RelocCount;             // Set to the real count when IMAGE_SCN_LNK_NRELOC_OVFL is set
//     } DUMMYUNIONNAME;
//     DWORD   SymbolTableIndex;
//     WORD    Type;
// } IMAGE_RELOCATION;
// typedef IMAGE_RELOCATION UNALIGNED *PIMAGE_RELOCATION;

// //
// // Line number format.
// //

// typedef struct _IMAGE_LINENUMBER {
//     union {
//         DWORD   SymbolTableIndex;               // Symbol table index of function name if Linenumber is 0.
//         DWORD   VirtualAddress;                 // Virtual address of line number.
//     } Type;
//     WORD    Linenumber;                         // Line number.
// } IMAGE_LINENUMBER;
// typedef IMAGE_LINENUMBER UNALIGNED *PIMAGE_LINENUMBER;

// #ifndef _MAC
// // #include "poppack.h"                        // Back to 4 byte packing
// #endif

// //
// // Based relocation format.
// //

// //@[comment("MVI_tracked")]
// typedef struct _IMAGE_BASE_RELOCATION {
//     DWORD   VirtualAddress;
//     DWORD   SizeOfBlock;
// //  WORD    TypeOffset[1];
// } IMAGE_BASE_RELOCATION;
// typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

// typedef struct _IMAGE_ARCHIVE_MEMBER_HEADER {
//     BYTE     Name[16];                          // File member name - `/' terminated.
//     BYTE     Date[12];                          // File member date - decimal.
//     BYTE     UserID[6];                         // File member user id - decimal.
//     BYTE     GroupID[6];                        // File member group id - decimal.
//     BYTE     Mode[8];                           // File member mode - octal.
//     BYTE     Size[10];                          // File member size - decimal.
//     BYTE     EndHeader[2];                      // String to end header.
// } IMAGE_ARCHIVE_MEMBER_HEADER, *PIMAGE_ARCHIVE_MEMBER_HEADER;

// #define IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR      60

// //
// // Thread Local Storage
// //

// typedef VOID
// (NTAPI *PIMAGE_TLS_CALLBACK) (
//     PVOID DllHandle,
//     DWORD Reason,
//     PVOID Reserved
//     );

// typedef struct _IMAGE_TLS_DIRECTORY64 {
//     ULONGLONG StartAddressOfRawData;
//     ULONGLONG EndAddressOfRawData;
//     ULONGLONG AddressOfIndex;         // PDWORD
//     ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
//     DWORD SizeOfZeroFill;
//     union {
//         DWORD Characteristics;
//         struct {
//             DWORD Reserved0 : 20;
//             DWORD Alignment : 4;
//             DWORD Reserved1 : 8;
//         } DUMMYSTRUCTNAME;
//     } DUMMYUNIONNAME;

// } IMAGE_TLS_DIRECTORY64;

// typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

// typedef struct _IMAGE_TLS_DIRECTORY32 {
//     DWORD   StartAddressOfRawData;
//     DWORD   EndAddressOfRawData;
//     DWORD   AddressOfIndex;             // PDWORD
//     DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
//     DWORD   SizeOfZeroFill;
//     union {
//         DWORD Characteristics;
//         struct {
//             DWORD Reserved0 : 20;
//             DWORD Alignment : 4;
//             DWORD Reserved1 : 8;
//         } DUMMYSTRUCTNAME;
//     } DUMMYUNIONNAME;

// } IMAGE_TLS_DIRECTORY32;
// typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;

// #ifdef _WIN64
// #define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG64
// #define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL64(Ordinal)
// typedef IMAGE_THUNK_DATA64              IMAGE_THUNK_DATA;
// typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;
// #define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL64(Ordinal)
// typedef IMAGE_TLS_DIRECTORY64           IMAGE_TLS_DIRECTORY;
// typedef PIMAGE_TLS_DIRECTORY64          PIMAGE_TLS_DIRECTORY;
// #else
// #define IMAGE_ORDINAL_FLAG              IMAGE_ORDINAL_FLAG32
// #define IMAGE_ORDINAL(Ordinal)          IMAGE_ORDINAL32(Ordinal)
// typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
// typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;
// #define IMAGE_SNAP_BY_ORDINAL(Ordinal)  IMAGE_SNAP_BY_ORDINAL32(Ordinal)
// typedef IMAGE_TLS_DIRECTORY32           IMAGE_TLS_DIRECTORY;
// typedef PIMAGE_TLS_DIRECTORY32          PIMAGE_TLS_DIRECTORY;
// #endif


// typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
//     union {
//         DWORD AllAttributes;
//         struct {
//             DWORD RvaBased : 1;             // Delay load version 2
//             DWORD ReservedAttributes : 31;
//         } DUMMYSTRUCTNAME;
//     } Attributes;

//     DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
//     DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
//     DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
//     DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
//     DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
//     DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
//     DWORD TimeDateStamp;                    // 0 if not bound,
//                                             // Otherwise, date/time of the target DLL

// } IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;

// typedef const IMAGE_DELAYLOAD_DESCRIPTOR *PCIMAGE_DELAYLOAD_DESCRIPTOR;

// //
// // Resource Format.
// //

// //
// // Resource directory consists of two counts, following by a variable length
// // array of directory entries.  The first count is the number of entries at
// // beginning of the array that have actual names associated with each entry.
// // The entries are in ascending order, case insensitive strings.  The second
// // count is the number of entries that immediately follow the named entries.
// // This second count identifies the number of entries that have 16-bit integer
// // Ids as their name.  These entries are also sorted in ascending order.
// //
// // This structure allows fast lookup by either name or number, but for any
// // given resource entry only one form of lookup is supported, not both.
// // This is consistant with the syntax of the .RC file and the .RES file.
// //

// typedef struct _IMAGE_RESOURCE_DIRECTORY {
//     DWORD   Characteristics;
//     DWORD   TimeDateStamp;
//     WORD    MajorVersion;
//     WORD    MinorVersion;
//     WORD    NumberOfNamedEntries;
//     WORD    NumberOfIdEntries;
// //  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
// } IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

// #define IMAGE_RESOURCE_NAME_IS_STRING        0x80000000
// #define IMAGE_RESOURCE_DATA_IS_DIRECTORY     0x80000000
// //
// // Each directory contains the 32-bit Name of the entry and an offset,
// // relative to the beginning of the resource directory of the data associated
// // with this directory entry.  If the name of the entry is an actual text
// // string instead of an integer Id, then the high order bit of the name field
// // is set to one and the low order 31-bits are an offset, relative to the
// // beginning of the resource directory of the string, which is of type
// // IMAGE_RESOURCE_DIRECTORY_STRING.  Otherwise the high bit is clear and the
// // low-order 16-bits are the integer Id that identify this resource directory
// // entry. If the directory entry is yet another resource directory (i.e. a
// // subdirectory), then the high order bit of the offset field will be
// // set to indicate this.  Otherwise the high bit is clear and the offset
// // field points to a resource data entry.
// //

// ////@[comment("MVI_tracked")]
// typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
//     union {
//         struct {
//             DWORD NameOffset:31;
//             DWORD NameIsString:1;
//         } DUMMYSTRUCTNAME;
//         DWORD   Name;
//         WORD    Id;
//     } DUMMYUNIONNAME;
//     union {
//         DWORD   OffsetToData;
//         struct {
//             DWORD   OffsetToDirectory:31;
//             DWORD   DataIsDirectory:1;
//         } DUMMYSTRUCTNAME2;
//     } DUMMYUNIONNAME2;
// } IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

// //
// // For resource directory entries that have actual string names, the Name
// // field of the directory entry points to an object of the following type.
// // All of these string objects are stored together after the last resource
// // directory entry and before the first resource data object.  This minimizes
// // the impact of these variable length objects on the alignment of the fixed
// // size directory entry objects.
// //

// typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
//     WORD    Length;
//     CHAR    NameString[ 1 ];
// } IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


// typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
//     WORD    Length;
//     WCHAR   NameString[ 1 ];
// } IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;


// //
// // Each resource data entry describes a leaf node in the resource directory
// // tree.  It contains an offset, relative to the beginning of the resource
// // directory of the data for the resource, a size field that gives the number
// // of bytes of data at that offset, a CodePage that should be used when
// // decoding code point values within the resource data.  Typically for new
// // applications the code page would be the unicode code page.
// //

// //@[comment("MVI_tracked")]
// typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
//     DWORD   OffsetToData;
//     DWORD   Size;
//     DWORD   CodePage;
//     DWORD   Reserved;
// } IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

// // begin_ntoshvp

// //
// // Code Integrity in loadconfig (CI)
// //

// typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
//     WORD    Flags;          // Flags to indicate if CI information is available, etc.
//     WORD    Catalog;        // 0xFFFF means not available
//     DWORD   CatalogOffset;
//     DWORD   Reserved;       // Additional bitmask to be defined later
// } IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

// //
// // Dynamic value relocation table in loadconfig
// //

// typedef struct _IMAGE_DYNAMIC_RELOCATION_TABLE {
//     DWORD Version;
//     DWORD Size;
// //  IMAGE_DYNAMIC_RELOCATION DynamicRelocations[0];
// } IMAGE_DYNAMIC_RELOCATION_TABLE, *PIMAGE_DYNAMIC_RELOCATION_TABLE;

// //
// // Dynamic value relocation entries following IMAGE_DYNAMIC_RELOCATION_TABLE
// //

// // #include "pshpack1.h"

// typedef struct _IMAGE_DYNAMIC_RELOCATION32 {
//     DWORD      Symbol;
//     DWORD      BaseRelocSize;
// //  IMAGE_BASE_RELOCATION BaseRelocations[0];
// } IMAGE_DYNAMIC_RELOCATION32, *PIMAGE_DYNAMIC_RELOCATION32;

// typedef struct _IMAGE_DYNAMIC_RELOCATION64 {
//     ULONGLONG  Symbol;
//     DWORD      BaseRelocSize;
// //  IMAGE_BASE_RELOCATION BaseRelocations[0];
// } IMAGE_DYNAMIC_RELOCATION64, *PIMAGE_DYNAMIC_RELOCATION64;

// typedef struct _IMAGE_DYNAMIC_RELOCATION32_V2 {
//     DWORD      HeaderSize;
//     DWORD      FixupInfoSize;
//     DWORD      Symbol;
//     DWORD      SymbolGroup;
//     DWORD      Flags;
//     // ...     variable length header fields
//     // BYTE    FixupInfo[FixupInfoSize]
// } IMAGE_DYNAMIC_RELOCATION32_V2, *PIMAGE_DYNAMIC_RELOCATION32_V2;

// typedef struct _IMAGE_DYNAMIC_RELOCATION64_V2 {
//     DWORD      HeaderSize;
//     DWORD      FixupInfoSize;
//     ULONGLONG  Symbol;
//     DWORD      SymbolGroup;
//     DWORD      Flags;
//     // ...     variable length header fields
//     // BYTE    FixupInfo[FixupInfoSize]
// } IMAGE_DYNAMIC_RELOCATION64_V2, *PIMAGE_DYNAMIC_RELOCATION64_V2;

// // #include "poppack.h"                    // Back to 4 byte packing

// #ifdef _WIN64
// typedef IMAGE_DYNAMIC_RELOCATION64          IMAGE_DYNAMIC_RELOCATION;
// typedef PIMAGE_DYNAMIC_RELOCATION64         PIMAGE_DYNAMIC_RELOCATION;
// typedef IMAGE_DYNAMIC_RELOCATION64_V2       IMAGE_DYNAMIC_RELOCATION_V2;
// typedef PIMAGE_DYNAMIC_RELOCATION64_V2      PIMAGE_DYNAMIC_RELOCATION_V2;
// #else
// typedef IMAGE_DYNAMIC_RELOCATION32          IMAGE_DYNAMIC_RELOCATION;
// typedef PIMAGE_DYNAMIC_RELOCATION32         PIMAGE_DYNAMIC_RELOCATION;
// typedef IMAGE_DYNAMIC_RELOCATION32_V2       IMAGE_DYNAMIC_RELOCATION_V2;
// typedef PIMAGE_DYNAMIC_RELOCATION32_V2      PIMAGE_DYNAMIC_RELOCATION_V2;
// #endif
