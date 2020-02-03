// Copyright 2020 Bill Ticehurst. All rights reserved.
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file

#pragma once

#define IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC       0x107

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

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

#define IMAGE_ARCHIVE_START_SIZE             8
#define IMAGE_ARCHIVE_START                  "!<arch>\n"

// Subsystem Values

#define IMAGE_SUBSYSTEM_UNKNOWN              0   // Unknown subsystem.
#define IMAGE_SUBSYSTEM_NATIVE               1   // Image doesn't require a subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_GUI          2   // Image runs in the Windows GUI subsystem.
#define IMAGE_SUBSYSTEM_WINDOWS_CUI          3   // Image runs in the Windows character subsystem.
#define IMAGE_SUBSYSTEM_OS2_CUI              5   // image runs in the OS/2 character subsystem.
#define IMAGE_SUBSYSTEM_POSIX_CUI            7   // image runs in the Posix character subsystem.
#define IMAGE_SUBSYSTEM_NATIVE_WINDOWS       8   // image is a native Win9x driver.
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI       9   // Image runs in the Windows CE subsystem.
#define IMAGE_SUBSYSTEM_EFI_APPLICATION      10  //
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  11   //
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER   12  //
#define IMAGE_SUBSYSTEM_EFI_ROM              13
#define IMAGE_SUBSYSTEM_XBOX                 14
#define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#define IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG    17

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

// #define IMAGE_ARCHIVE_END                    "`\n"
// #define IMAGE_ARCHIVE_PAD                    "\n"
// #define IMAGE_ARCHIVE_LINKER_MEMBER          "/               "
// #define IMAGE_ARCHIVE_LONGNAMES_MEMBER       "//              "
// #define IMAGE_ARCHIVE_HYBRIDMAP_MEMBER       "/<HYBRIDMAP>/   "

// #define IMAGE_ORDINAL_FLAG64 0x8000000000000000
// #define IMAGE_ORDINAL_FLAG32 0x80000000
