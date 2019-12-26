/*
MIT License

Copyright (c) 2019 BingoZou

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Runtime.InteropServices;

namespace MemoryLoader
{
    internal enum IMAGE_DIRECTORY_ENTRY
    {
        IMAGE_DIRECTORY_ENTRY_EXPORT = 0,           //  Export Directory
        IMAGE_DIRECTORY_ENTRY_IMPORT = 1,           //  Import Directory
        IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,         //  Resource Directory
        IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,        //  Exception Directory
        IMAGE_DIRECTORY_ENTRY_SECURITY = 4,         //  Security Directory
        IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,        //  Base Relocation Table
        IMAGE_DIRECTORY_ENTRY_DEBUG = 6,            //  Debug Directory
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,     //  Architecture Specific Data
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,        //  RVA of GP
        IMAGE_DIRECTORY_ENTRY_TLS = 9,              //  TLS Directory
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,     //  Load Configuration Directory
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,    //  Bound Import Directory in headers
        IMAGE_DIRECTORY_ENTRY_IAT = 12,             //  Import Address Table
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,    //  Delay Load Import Descriptors
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14   //  COM Runtime descriptor
    }

    internal unsafe struct IMAGE_FILE_HEADER
    {
        public UInt16 Machine { get; set; }
        public UInt16 NumberOfSections { get; set; }
        public UInt32 TimeDateStamp { get; set; }
        public UInt32 PointerToSymbolTable { get; set; }
        public UInt32 NumberOfSymbols { get; set; }
        public UInt16 SizeOfOptionalHeader { get; set; }
        public UInt16 Characteristics { get; set; }
    }

    internal unsafe struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress { get; set; }
        public UInt32 Size { get; set; }
    }

    internal unsafe struct IMAGE_IMPORT_DESCRIPTOR
    {
        public UInt32 OriginalFirstThunk { get; set; }
        public UInt32 TimeDateStamp { get; set; }
        public UInt32 ForwarderChain { get; set; }
        public UInt32 Name { get; set; }
        public UInt32 FirstThunk { get; set; }
    }

    internal unsafe struct IMAGE_EXPORT_DIRECTORY
    {
        public UInt32 Characteristics { get; set; }
        public UInt32 TimeDateStamp { get; set; }
        public UInt16 MajorVersion { get; set; }
        public UInt16 MinorVersion { get; set; }
        public UInt32 pName { get; set; }
        public UInt32 Base { get; set; }
        public UInt32 NumberOfFunctions { get; set; }
        public UInt32 NumberOfNames { get; set; }
        public UInt32 AddressOfFunctions { get; set; }
        public UInt32 AddressOfNames { get; set; }
        public UInt32 AddressOfNameOrdinals { get; set; }
    }

    internal unsafe struct IMAGE_DOS_HEADER
    {
        public UInt16 e_magic { get; set; }
        public UInt16 e_cblp { get; set; }
        public UInt16 e_cp { get; set; }
        public UInt16 e_crlc { get; set; }
        public UInt16 e_cparhdr { get; set; }
        public UInt16 e_minalloc { get; set; }
        public UInt16 e_maxalloc { get; set; }
        public UInt16 e_ss { get; set; }
        public UInt16 e_sp { get; set; }
        public UInt16 e_csum { get; set; }
        public UInt16 e_ip { get; set; }
        public UInt16 e_cs { get; set; }
        public UInt16 e_lfarlc { get; set; }
        public UInt16 e_ovno { get; set; }
        public fixed UInt16 e_res[4];
        public UInt16 e_oemid { get; set; }
        public UInt16 e_oeminfo { get; set; }
        public fixed UInt16 e_res2[10];
        public Int32 e_lfanew { get; set; }
    }

    internal unsafe struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic { get; set; }
        public Byte MajorLinkerVersion { get; set; }
        public Byte MinorLinkerVersion { get; set; }
        public UInt32 SizeOfCode { get; set; }
        public UInt32 SizeOfInitializedData { get; set; }
        public UInt32 SizeOfUninitializedData { get; set; }
        public UInt32 AddressOfEntryPoint { get; set; }
        public UInt32 BaseOfCode { get; set; }
#if _WIN64
        public UInt64 ImageBase { get; set; }
#else
        public UInt32 BaseOfData { get; set; }
        public UInt32 ImageBase { get; set; }
#endif
        public UInt32 SectionAlignment { get; set; }
        public UInt32 FileAlignment { get; set; }
        public UInt16 MajorOperatingSystemVersion { get; set; }
        public UInt16 MinorOperatingSystemVersion { get; set; }
        public UInt16 MajorImageVersion { get; set; }
        public UInt16 MinorImageVersion { get; set; }
        public UInt16 MajorSubsystemVersion { get; set; }
        public UInt16 MinorSubsystemVersion { get; set; }
        public UInt32 Win32VersionValue { get; set; }
        public UInt32 SizeOfImage { get; set; }
        public UInt32 SizeOfHeaders { get; set; }
        public UInt32 CheckSum { get; set; }
        public UInt16 Subsystem { get; set; }
        public UInt16 DllCharacteristics { get; set; }
#if _WIN64
        public UInt64 SizeOfStackReserve { get; set; }
        public UInt64 SizeOfStackCommit { get; set; }
        public UInt64 SizeOfHeapReserve { get; set; }
        public UInt64 SizeOfHeapCommit { get; set; }
#else
        public UInt32 SizeOfStackReserve { get; set; }
        public UInt32 SizeOfStackCommit { get; set; }
        public UInt32 SizeOfHeapReserve { get; set; }
        public UInt32 SizeOfHeapCommit { get; set; }
#endif
        public UInt32 LoaderFlags { get; set; }
        public UInt32 NumberOfRvaAndSizes { get; set; }
        public fixed Int32 DataDirectory[32];

        /// <summary>
        /// 获取数据目录
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public IMAGE_DATA_DIRECTORY GetDirectory(IMAGE_DIRECTORY_ENTRY eEntryIndex)
        {
            fixed (int* pTemp = this.DataDirectory)
            {
                IMAGE_DATA_DIRECTORY* pDataDirectory = (IMAGE_DATA_DIRECTORY*)pTemp;
                pDataDirectory += (Int32)eEntryIndex;
                return *pDataDirectory;
            }
        }
    }

    internal unsafe struct IMAGE_NT_HEADERS
    {
        public UInt32 Signature { get; set; }
        public IMAGE_FILE_HEADER FileHeader { get; set; }
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader { get; set; }
    }

    internal unsafe struct IMAGE_SECTION_HEADER
    {
        public fixed Byte Name_[8];
        public UInt32 VirtualSize { get; set; }         // 该区块表对应的区块加载到内存后的大小，这是区块的数据在没有进行SectionAlignment对齐处理前的实际大小
        public UInt32 VirtualAddress { get; set; }      // 节区的 RVA 地址
        public UInt32 SizeOfRawData { get; set; }       // 在文件中对齐后的尺寸
        public UInt32 PointerToRawData { get; set; }    // 在文件中的偏移量
        public UInt32 PointerToRelocations { get; set; }
        public UInt32 PointerToLinenumbers { get; set; }
        public UInt16 NumberOfRelocations { get; set; }
        public UInt16 NumberOfLinenumbers { get; set; }
        public UInt32 Characteristics { get; set; }
    }

    internal unsafe struct IMAGE_BASE_RELOCATION
    {
        public UInt32 VirtualAddress { get; set; }
        public UInt32 SizeOfBlock { get; set; }
    }

    internal class Win32API
    {
        public const Int32 MEM_COMMIT = 0x1000;
        public const Int32 MEM_RESERVE = 0x2000;
        public const Int32 MEM_RELEASE = 0x8000;
        public const Int32 IMAGE_NT_SIGNATURE = 0x4550;
        public const Int32 IMAGE_FILE_DLL = 0x2000;
        public const Int32 PAGE_EXECUTE_READWRITE = 0x40;
        public const Int32 IMAGE_REL_BASED_HIGHLOW = 3;
        public const Int32 IMAGE_REL_BASED_DIR64 = 10;
        public const Int32 DLL_PROCESS_ATTACH = 1;
        public const Int32 DLL_THREAD_ATTACH = 2;
        public const Int32 DLL_THREAD_DETACH = 3;
        public const Int32 DLL_PROCESS_DETACH = 0;
#if _WIN64
        public const UInt64 IMAGE_ORDINAL_FLAG = 0x8000000000000000;
#else
        public const UInt32 IMAGE_ORDINAL_FLAG = 0x80000000;
#endif

        //((PIMAGE_SECTION_HEADER)((ULONG_PTR)(ntheader) + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + ((ntheader))->FileHeader.SizeOfOptionalHeader))

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName);

        [DllImport("kernel32.dll")]
        public static extern void CopyMemory(IntPtr Destination, IntPtr Source, uint Length);
    }
}
