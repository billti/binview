// See https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
// Also https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

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

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

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

#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved external references).
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Aggressively trim working set
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
#define IMAGE_FILE_SYSTEM                    0x1000  // System File.
#define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_TARGET_HOST       0x0001  // Useful for indicating we want to interact with the host and not a WoW guest.
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM Thumb/Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2 Little-Endian
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
#define IMAGE_FILE_MACHINE_ARM64             0xAA64  // ARM64 Little-Endian
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

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

// #define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

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

// // IMAGE_FIRST_SECTION doesn't need 32/64 versions since the file header is the same either way.

// #define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
//     ((ULONG_PTR)(ntheader) +                                            \
//      FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
//      ((ntheader))->FileHeader.SizeOfOptionalHeader   \
//     ))

// // Subsystem Values

// #define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
// #define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
// #define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
// #define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
// #define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
// #define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
// #define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
// #define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
// #define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
// #define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
// #define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
// #define IMAGE_SUBSYSTEM_EFI_ROM              13
// #define IMAGE_SUBSYSTEM_XBOX                 14
// #define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
// #define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG    17

// // DllCharacteristics Entries

// //      IMAGE_LIBRARY_PROCESS_INIT            0x0001     // Reserved.
// //      IMAGE_LIBRARY_PROCESS_TERM            0x0002     // Reserved.
// //      IMAGE_LIBRARY_THREAD_INIT             0x0004     // Reserved.
// //      IMAGE_LIBRARY_THREAD_TERM             0x0008     // Reserved.
// #define IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA    0x0020  // Image can handle a high entropy 64-bit virtual address space.
// #define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040     // DLL can move.
// #define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    0x0080     // Code Integrity Image
// #define IMAGE_DLLCHARACTERISTICS_NX_COMPAT    0x0100     // Image is NX compatible
// #define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200     // Image understands isolation and doesn't want it
// #define IMAGE_DLLCHARACTERISTICS_NO_SEH       0x0400     // Image does not use SEH.  No SE handler may reside in this image
// #define IMAGE_DLLCHARACTERISTICS_NO_BIND      0x0800     // Do not bind this image.
// #define IMAGE_DLLCHARACTERISTICS_APPCONTAINER 0x1000     // Image should execute in an AppContainer
// #define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER   0x2000     // Driver uses WDM model
// #define IMAGE_DLLCHARACTERISTICS_GUARD_CF     0x4000     // Image supports Control Flow Guard.
// #define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE     0x8000

// // Directory Entries

// #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
// #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
// #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
// #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
// #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
// #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
// #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
// //      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
// #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
// #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
// #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
// #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
// #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
// #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
// #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
// #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

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
// // Section header format.
// //

// #define IMAGE_SIZEOF_SHORT_NAME              8

// typedef struct _IMAGE_SECTION_HEADER {
//     BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
//     union {
//             DWORD   PhysicalAddress;
//             DWORD   VirtualSize;
//     } Misc;
//     DWORD   VirtualAddress;
//     DWORD   SizeOfRawData;
//     DWORD   PointerToRawData;
//     DWORD   PointerToRelocations;
//     DWORD   PointerToLinenumbers;
//     WORD    NumberOfRelocations;
//     WORD    NumberOfLinenumbers;
//     DWORD   Characteristics;
// } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// #define IMAGE_SIZEOF_SECTION_HEADER          40

// //
// // Section characteristics.
// //
// //      IMAGE_SCN_TYPE_REG                   0x00000000  // Reserved.
// //      IMAGE_SCN_TYPE_DSECT                 0x00000001  // Reserved.
// //      IMAGE_SCN_TYPE_NOLOAD                0x00000002  // Reserved.
// //      IMAGE_SCN_TYPE_GROUP                 0x00000004  // Reserved.
// #define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // Reserved.
// //      IMAGE_SCN_TYPE_COPY                  0x00000010  // Reserved.

// #define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.
// #define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.
// #define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.

// #define IMAGE_SCN_LNK_OTHER                  0x00000100  // Reserved.
// #define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
// //      IMAGE_SCN_TYPE_OVER                  0x00000400  // Reserved.
// #define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
// #define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
// //                                           0x00002000  // Reserved.
// //      IMAGE_SCN_MEM_PROTECTED - Obsolete   0x00004000
// #define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
// #define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
// #define IMAGE_SCN_MEM_FARDATA                0x00008000
// //      IMAGE_SCN_MEM_SYSHEAP  - Obsolete    0x00010000
// #define IMAGE_SCN_MEM_PURGEABLE              0x00020000
// #define IMAGE_SCN_MEM_16BIT                  0x00020000
// #define IMAGE_SCN_MEM_LOCKED                 0x00040000
// #define IMAGE_SCN_MEM_PRELOAD                0x00080000

// #define IMAGE_SCN_ALIGN_1BYTES               0x00100000  //
// #define IMAGE_SCN_ALIGN_2BYTES               0x00200000  //
// #define IMAGE_SCN_ALIGN_4BYTES               0x00300000  //
// #define IMAGE_SCN_ALIGN_8BYTES               0x00400000  //
// #define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
// #define IMAGE_SCN_ALIGN_32BYTES              0x00600000  //
// #define IMAGE_SCN_ALIGN_64BYTES              0x00700000  //
// #define IMAGE_SCN_ALIGN_128BYTES             0x00800000  //
// #define IMAGE_SCN_ALIGN_256BYTES             0x00900000  //
// #define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  //
// #define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  //
// #define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  //
// #define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  //
// #define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  //
// // Unused                                    0x00F00000
// #define IMAGE_SCN_ALIGN_MASK                 0x00F00000

// #define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
// #define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
// #define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
// #define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
// #define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.
// #define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.
// #define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.
// #define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.


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

// //
// // Section values.
// //
// // Symbols have a section number of the section in which they are
// // defined. Otherwise, section numbers have the following meanings:
// //

// #define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
// #define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
// #define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.
// #define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special
// #define IMAGE_SYM_SECTION_MAX_EX      MAXLONG

// //
// // Type (fundamental) values.
// //

// #define IMAGE_SYM_TYPE_NULL                 0x0000  // no type.
// #define IMAGE_SYM_TYPE_VOID                 0x0001  //
// #define IMAGE_SYM_TYPE_CHAR                 0x0002  // type character.
// #define IMAGE_SYM_TYPE_SHORT                0x0003  // type short integer.
// #define IMAGE_SYM_TYPE_INT                  0x0004  //
// #define IMAGE_SYM_TYPE_LONG                 0x0005  //
// #define IMAGE_SYM_TYPE_FLOAT                0x0006  //
// #define IMAGE_SYM_TYPE_DOUBLE               0x0007  //
// #define IMAGE_SYM_TYPE_STRUCT               0x0008  //
// #define IMAGE_SYM_TYPE_UNION                0x0009  //
// #define IMAGE_SYM_TYPE_ENUM                 0x000A  // enumeration.
// #define IMAGE_SYM_TYPE_MOE                  0x000B  // member of enumeration.
// #define IMAGE_SYM_TYPE_BYTE                 0x000C  //
// #define IMAGE_SYM_TYPE_WORD                 0x000D  //
// #define IMAGE_SYM_TYPE_UINT                 0x000E  //
// #define IMAGE_SYM_TYPE_DWORD                0x000F  //
// #define IMAGE_SYM_TYPE_PCODE                0x8000  //
// //
// // Type (derived) values.
// //

// #define IMAGE_SYM_DTYPE_NULL                0       // no derived type.
// #define IMAGE_SYM_DTYPE_POINTER             1       // pointer.
// #define IMAGE_SYM_DTYPE_FUNCTION            2       // function.
// #define IMAGE_SYM_DTYPE_ARRAY               3       // array.

// //
// // Storage classes.
// //
// #define IMAGE_SYM_CLASS_END_OF_FUNCTION     (BYTE )-1
// #define IMAGE_SYM_CLASS_NULL                0x0000
// #define IMAGE_SYM_CLASS_AUTOMATIC           0x0001
// #define IMAGE_SYM_CLASS_EXTERNAL            0x0002
// #define IMAGE_SYM_CLASS_STATIC              0x0003
// #define IMAGE_SYM_CLASS_REGISTER            0x0004
// #define IMAGE_SYM_CLASS_EXTERNAL_DEF        0x0005
// #define IMAGE_SYM_CLASS_LABEL               0x0006
// #define IMAGE_SYM_CLASS_UNDEFINED_LABEL     0x0007
// #define IMAGE_SYM_CLASS_MEMBER_OF_STRUCT    0x0008
// #define IMAGE_SYM_CLASS_ARGUMENT            0x0009
// #define IMAGE_SYM_CLASS_STRUCT_TAG          0x000A
// #define IMAGE_SYM_CLASS_MEMBER_OF_UNION     0x000B
// #define IMAGE_SYM_CLASS_UNION_TAG           0x000C
// #define IMAGE_SYM_CLASS_TYPE_DEFINITION     0x000D
// #define IMAGE_SYM_CLASS_UNDEFINED_STATIC    0x000E
// #define IMAGE_SYM_CLASS_ENUM_TAG            0x000F
// #define IMAGE_SYM_CLASS_MEMBER_OF_ENUM      0x0010
// #define IMAGE_SYM_CLASS_REGISTER_PARAM      0x0011
// #define IMAGE_SYM_CLASS_BIT_FIELD           0x0012

// #define IMAGE_SYM_CLASS_FAR_EXTERNAL        0x0044  //

// #define IMAGE_SYM_CLASS_BLOCK               0x0064
// #define IMAGE_SYM_CLASS_FUNCTION            0x0065
// #define IMAGE_SYM_CLASS_END_OF_STRUCT       0x0066
// #define IMAGE_SYM_CLASS_FILE                0x0067
// // new
// #define IMAGE_SYM_CLASS_SECTION             0x0068
// #define IMAGE_SYM_CLASS_WEAK_EXTERNAL       0x0069

// #define IMAGE_SYM_CLASS_CLR_TOKEN           0x006B

// // type packing constants

// #define N_BTMASK                            0x000F
// #define N_TMASK                             0x0030
// #define N_TMASK1                            0x00C0
// #define N_TMASK2                            0x00F0
// #define N_BTSHFT                            4
// #define N_TSHIFT                            2
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
// // Communal selection types.
// //

// #define IMAGE_COMDAT_SELECT_NODUPLICATES    1
// #define IMAGE_COMDAT_SELECT_ANY             2
// #define IMAGE_COMDAT_SELECT_SAME_SIZE       3
// #define IMAGE_COMDAT_SELECT_EXACT_MATCH     4
// #define IMAGE_COMDAT_SELECT_ASSOCIATIVE     5
// #define IMAGE_COMDAT_SELECT_LARGEST         6
// #define IMAGE_COMDAT_SELECT_NEWEST          7

// #define IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY  1
// #define IMAGE_WEAK_EXTERN_SEARCH_LIBRARY    2
// #define IMAGE_WEAK_EXTERN_SEARCH_ALIAS      3
// #define IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY   4

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
// // I386 relocation types.
// //
// #define IMAGE_REL_I386_ABSOLUTE         0x0000  // Reference is absolute, no relocation is necessary
// #define IMAGE_REL_I386_DIR16            0x0001  // Direct 16-bit reference to the symbols virtual address
// #define IMAGE_REL_I386_REL16            0x0002  // PC-relative 16-bit reference to the symbols virtual address
// #define IMAGE_REL_I386_DIR32            0x0006  // Direct 32-bit reference to the symbols virtual address
// #define IMAGE_REL_I386_DIR32NB          0x0007  // Direct 32-bit reference to the symbols virtual address, base not included
// #define IMAGE_REL_I386_SEG12            0x0009  // Direct 16-bit reference to the segment-selector bits of a 32-bit virtual address
// #define IMAGE_REL_I386_SECTION          0x000A
// #define IMAGE_REL_I386_SECREL           0x000B
// #define IMAGE_REL_I386_TOKEN            0x000C  // clr token
// #define IMAGE_REL_I386_SECREL7          0x000D  // 7 bit offset from base of section containing target
// #define IMAGE_REL_I386_REL32            0x0014  // PC-relative 32-bit reference to the symbols virtual address

// // Flag bits in IMAGE_RELOCATION.TYPE

// #define IMAGE_REL_PPC_NEG               0x0100  // subtract reloc value rather than adding it
// #define IMAGE_REL_PPC_BRTAKEN           0x0200  // fix branch prediction bit to predict branch taken
// #define IMAGE_REL_PPC_BRNTAKEN          0x0400  // fix branch prediction bit to predict branch not taken
// #define IMAGE_REL_PPC_TOCDEFN           0x0800  // toc slot defined in file (or, data in toc)


// #define IMAGE_REL_ARM_ABSOLUTE          0x0000  // No relocation required
// #define IMAGE_REL_ARM_ADDR32            0x0001  // 32 bit address
// #define IMAGE_REL_ARM_ADDR32NB          0x0002  // 32 bit address w/o image base
// #define IMAGE_REL_ARM_BRANCH24          0x0003  // 24 bit offset << 2 & sign ext.
// #define IMAGE_REL_ARM_BRANCH11          0x0004  // Thumb: 2 11 bit offsets
// #define IMAGE_REL_ARM_TOKEN             0x0005  // clr token
// #define IMAGE_REL_ARM_GPREL12           0x0006  // GP-relative addressing (ARM)
// #define IMAGE_REL_ARM_GPREL7            0x0007  // GP-relative addressing (Thumb)
// #define IMAGE_REL_ARM_BLX24             0x0008
// #define IMAGE_REL_ARM_BLX11             0x0009
// #define IMAGE_REL_ARM_SECTION           0x000E  // Section table index
// #define IMAGE_REL_ARM_SECREL            0x000F  // Offset within section
// #define IMAGE_REL_ARM_MOV32A            0x0010  // ARM: MOVW/MOVT
// #define IMAGE_REL_ARM_MOV32             0x0010  // ARM: MOVW/MOVT (deprecated)
// #define IMAGE_REL_ARM_MOV32T            0x0011  // Thumb: MOVW/MOVT
// #define IMAGE_REL_THUMB_MOV32           0x0011  // Thumb: MOVW/MOVT (deprecated)
// #define IMAGE_REL_ARM_BRANCH20T         0x0012  // Thumb: 32-bit conditional B
// #define IMAGE_REL_THUMB_BRANCH20        0x0012  // Thumb: 32-bit conditional B (deprecated)
// #define IMAGE_REL_ARM_BRANCH24T         0x0014  // Thumb: 32-bit B or BL
// #define IMAGE_REL_THUMB_BRANCH24        0x0014  // Thumb: 32-bit B or BL (deprecated)
// #define IMAGE_REL_ARM_BLX23T            0x0015  // Thumb: BLX immediate
// #define IMAGE_REL_THUMB_BLX23           0x0015  // Thumb: BLX immediate (deprecated)

// //
// // ARM64 relocations types.
// //

// #define IMAGE_REL_ARM64_ABSOLUTE        0x0000  // No relocation required
// #define IMAGE_REL_ARM64_ADDR32          0x0001  // 32 bit address. Review! do we need it?
// #define IMAGE_REL_ARM64_ADDR32NB        0x0002  // 32 bit address w/o image base (RVA: for Data/PData/XData)
// #define IMAGE_REL_ARM64_BRANCH26        0x0003  // 26 bit offset << 2 & sign ext. for B & BL
// #define IMAGE_REL_ARM64_PAGEBASE_REL21  0x0004  // ADRP
// #define IMAGE_REL_ARM64_REL21           0x0005  // ADR
// #define IMAGE_REL_ARM64_PAGEOFFSET_12A  0x0006  // ADD/ADDS (immediate) with zero shift, for page offset
// #define IMAGE_REL_ARM64_PAGEOFFSET_12L  0x0007  // LDR (indexed, unsigned immediate), for page offset
// #define IMAGE_REL_ARM64_SECREL          0x0008  // Offset within section
// #define IMAGE_REL_ARM64_SECREL_LOW12A   0x0009  // ADD/ADDS (immediate) with zero shift, for bit 0:11 of section offset
// #define IMAGE_REL_ARM64_SECREL_HIGH12A  0x000A  // ADD/ADDS (immediate) with zero shift, for bit 12:23 of section offset
// #define IMAGE_REL_ARM64_SECREL_LOW12L   0x000B  // LDR (indexed, unsigned immediate), for bit 0:11 of section offset
// #define IMAGE_REL_ARM64_TOKEN           0x000C
// #define IMAGE_REL_ARM64_SECTION         0x000D  // Section table index
// #define IMAGE_REL_ARM64_ADDR64          0x000E  // 64 bit address
// #define IMAGE_REL_ARM64_BRANCH19        0x000F  // 19 bit offset << 2 & sign ext. for conditional B

// //
// // x64 relocations
// //
// #define IMAGE_REL_AMD64_ABSOLUTE        0x0000  // Reference is absolute, no relocation is necessary
// #define IMAGE_REL_AMD64_ADDR64          0x0001  // 64-bit address (VA).
// #define IMAGE_REL_AMD64_ADDR32          0x0002  // 32-bit address (VA).
// #define IMAGE_REL_AMD64_ADDR32NB        0x0003  // 32-bit address w/o image base (RVA).
// #define IMAGE_REL_AMD64_REL32           0x0004  // 32-bit relative address from byte following reloc
// #define IMAGE_REL_AMD64_REL32_1         0x0005  // 32-bit relative address from byte distance 1 from reloc
// #define IMAGE_REL_AMD64_REL32_2         0x0006  // 32-bit relative address from byte distance 2 from reloc
// #define IMAGE_REL_AMD64_REL32_3         0x0007  // 32-bit relative address from byte distance 3 from reloc
// #define IMAGE_REL_AMD64_REL32_4         0x0008  // 32-bit relative address from byte distance 4 from reloc
// #define IMAGE_REL_AMD64_REL32_5         0x0009  // 32-bit relative address from byte distance 5 from reloc
// #define IMAGE_REL_AMD64_SECTION         0x000A  // Section index
// #define IMAGE_REL_AMD64_SECREL          0x000B  // 32 bit offset from base of section containing target
// #define IMAGE_REL_AMD64_SECREL7         0x000C  // 7 bit unsigned offset from base of section containing target
// #define IMAGE_REL_AMD64_TOKEN           0x000D  // 32 bit metadata token
// #define IMAGE_REL_AMD64_SREL32          0x000E  // 32 bit signed span-dependent value emitted into object
// #define IMAGE_REL_AMD64_PAIR            0x000F
// #define IMAGE_REL_AMD64_SSPAN32         0x0010  // 32 bit signed span-dependent value applied at link time
// #define IMAGE_REL_AMD64_EHANDLER        0x0011
// #define IMAGE_REL_AMD64_IMPORT_BR       0x0012  // Indirect branch to an import
// #define IMAGE_REL_AMD64_IMPORT_CALL     0x0013  // Indirect call to an import
// #define IMAGE_REL_AMD64_CFG_BR          0x0014  // Indirect branch to a CFG check
// #define IMAGE_REL_AMD64_CFG_BR_REX      0x0015  // Indirect branch to a CFG check, with REX.W prefix
// #define IMAGE_REL_AMD64_CFG_CALL        0x0016  // Indirect call to a CFG check
// #define IMAGE_REL_AMD64_INDIR_BR        0x0017  // Indirect branch to a target in RAX (no CFG)
// #define IMAGE_REL_AMD64_INDIR_BR_REX    0x0018  // Indirect branch to a target in RAX, with REX.W prefix (no CFG)
// #define IMAGE_REL_AMD64_INDIR_CALL      0x0019  // Indirect call to a target in RAX (no CFG)
// #define IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_FIRST  0x0020 // Indirect branch for a switch table using Reg 0 (RAX)
// #define IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_LAST   0x002F // Indirect branch for a switch table using Reg 15 (R15)

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

// //
// // Based relocation types.
// //

// #define IMAGE_REL_BASED_ABSOLUTE              0
// #define IMAGE_REL_BASED_HIGH                  1
// #define IMAGE_REL_BASED_LOW                   2
// #define IMAGE_REL_BASED_HIGHLOW               3
// #define IMAGE_REL_BASED_HIGHADJ               4
// #define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
// #define IMAGE_REL_BASED_RESERVED              6
// #define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
// #define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
// #define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
// #define IMAGE_REL_BASED_DIR64                 10

// //
// // Platform-specific based relocation types.
// //

// #define IMAGE_REL_BASED_IA64_IMM64            9

// #define IMAGE_REL_BASED_MIPS_JMPADDR          5
// #define IMAGE_REL_BASED_MIPS_JMPADDR16        9

// #define IMAGE_REL_BASED_ARM_MOV32             5
// #define IMAGE_REL_BASED_THUMB_MOV32           7


// //
// // Archive format.
// //

// #define IMAGE_ARCHIVE_START_SIZE             8
// #define IMAGE_ARCHIVE_START                  "!<arch>\n"
// #define IMAGE_ARCHIVE_END                    "`\n"
// #define IMAGE_ARCHIVE_PAD                    "\n"
// #define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
// #define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "
// #define IMAGE_ARCHIVE_HYBRIDMAP_MEMBER       "/<HYBRIDMAP>/   "


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
// // DLL support.
// //

// //
// // Export Format
// //

// //@[comment("MVI_tracked")]
// typedef struct _IMAGE_EXPORT_DIRECTORY {
//     DWORD   Characteristics;
//     DWORD   TimeDateStamp;
//     WORD    MajorVersion;
//     WORD    MinorVersion;
//     DWORD   Name;
//     DWORD   Base;
//     DWORD   NumberOfFunctions;
//     DWORD   NumberOfNames;
//     DWORD   AddressOfFunctions;     // RVA from base of image
//     DWORD   AddressOfNames;         // RVA from base of image
//     DWORD   AddressOfNameOrdinals;  // RVA from base of image
// } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// //
// // Import Format
// //

// //@[comment("MVI_tracked")]
// typedef struct _IMAGE_IMPORT_BY_NAME {
//     WORD    Hint;
//     CHAR   Name[1];
// } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

// // #include "pshpack8.h"                       // Use align 8 for the 64-bit IAT.

// typedef struct _IMAGE_THUNK_DATA64 {
//     union {
//         ULONGLONG ForwarderString;  // PBYTE
//         ULONGLONG Function;         // PDWORD
//         ULONGLONG Ordinal;
//         ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
//     } u1;
// } IMAGE_THUNK_DATA64;
// typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;

// // #include "poppack.h"                        // Back to 4 byte packing

// typedef struct _IMAGE_THUNK_DATA32 {
//     union {
//         DWORD ForwarderString;      // PBYTE
//         DWORD Function;             // PDWORD
//         DWORD Ordinal;
//         DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
//     } u1;
// } IMAGE_THUNK_DATA32;
// typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

// #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
// #define IMAGE_ORDINAL_FLAG32 0x80000000
// #define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
// #define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
// #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
// #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

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

// ////@[comment("MVI_tracked")]
// typedef struct _IMAGE_IMPORT_DESCRIPTOR {
//     union {
//         DWORD   Characteristics;            // 0 for terminating null import descriptor
//         DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
//     } DUMMYUNIONNAME;
//     DWORD   TimeDateStamp;                  // 0 if not bound,
//                                             // -1 if bound, and real date\time stamp
//                                             //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
//                                             // O.W. date/time stamp of DLL bound to (Old BIND)

//     DWORD   ForwarderChain;                 // -1 if no forwarders
//     DWORD   Name;
//     DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
// } IMAGE_IMPORT_DESCRIPTOR;
// typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

// //
// // New format import descriptors pointed to by DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]
// //

// typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
//     DWORD   TimeDateStamp;
//     WORD    OffsetModuleName;
//     WORD    NumberOfModuleForwarderRefs;
// // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
// } IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

// typedef struct _IMAGE_BOUND_FORWARDER_REF {
//     DWORD   TimeDateStamp;
//     WORD    OffsetModuleName;
//     WORD    Reserved;
// } IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

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
