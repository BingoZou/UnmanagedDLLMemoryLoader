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
    /// <summary>
    /// 动态链接库内存加载器
    /// </summary>
    internal class UnmanagedDLLMemoryLoader : IDisposable
    {
        ~UnmanagedDLLMemoryLoader()
        {
            this.Dispose();
        }

        /// <summary>
        /// DllMain函数委托
        /// </summary>
        /// <param name="hModule"></param>
        /// <param name="ul_reason_for_call"></param>
        /// <param name="lpReserved"></param>
        /// <returns></returns>
        private delegate Boolean DllMainHandle(IntPtr hModule, UInt32 ul_reason_for_call, IntPtr lpReserved);

        /// <summary>
        /// 从Byte数组加载Dll
        /// </summary>
        /// <param name="managedMemoryData"></param>
        /// <returns></returns>
        public Boolean LoadLibrary(Byte[] managedMemoryData)
        {
            if(managedMemoryData == null || managedMemoryData.Length == 0)
            {
                throw new Exception("Data is empty");
            }

            IntPtr pUnmanagedBuffer = IntPtr.Zero;
            try
            {
                int iDataLength = managedMemoryData.Length;
                pUnmanagedBuffer = Marshal.AllocHGlobal(iDataLength);
                Marshal.Copy(managedMemoryData, 0, pUnmanagedBuffer, iDataLength);
                return this.LoadDLLFromMemory(pUnmanagedBuffer, iDataLength);
            }
            catch (Exception ex)
            {
                if (this.mModuleHandle != IntPtr.Zero)
                {
                    Win32API.VirtualFree(this.mModuleHandle, 0, Win32API.MEM_RELEASE);
                    this.mModuleHandle = IntPtr.Zero;
                }
                throw ex;
            }
            finally
            {
                Marshal.FreeHGlobal(pUnmanagedBuffer);
            }
        }

        /// <summary>
        /// 加载dLL
        /// </summary>
        /// <param name="pUnmanagedBuffer"></param>
        /// <param name="iBufferLength"></param>
        /// <returns></returns>
        private unsafe Boolean LoadDLLFromMemory(IntPtr pUnmanagedBuffer, Int32 iBufferLength)
        {
            try
            {
                if (iBufferLength < sizeof(IMAGE_DOS_HEADER))
                {
                    throw new Exception("Data is too short");
                }
                IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pUnmanagedBuffer;
                if (pDosHeader->e_magic != 0x5A4D)
                {
                    throw new Exception("DOS file format error");
                }

                if (iBufferLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
                {
                    throw new Exception("Data is short");
                }
                IMAGE_NT_HEADERS* pPEHeader = (IMAGE_NT_HEADERS*)(pUnmanagedBuffer + pDosHeader->e_lfanew);
                if (pPEHeader->Signature != Win32API.IMAGE_NT_SIGNATURE)
                {
                    throw new Exception("windows file Signature error");
                }
                if ((pPEHeader->FileHeader.Characteristics & Win32API.IMAGE_FILE_DLL) != Win32API.IMAGE_FILE_DLL)
                {
                    throw new Exception("Dll Not dynamic library");
                }

                IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)(pUnmanagedBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
                for (Int32 i = 0; i < pPEHeader->FileHeader.NumberOfSections; i++)
                {
                    if (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > iBufferLength)
                    {
                        throw new Exception("Section data error");
                    }
                }
                //计算空间
                this.mModuleSize = this.CalcTotalImageSize(pPEHeader, pSectionHeader);
                if (this.mModuleSize == 0 || this.mModuleSize > iBufferLength * 10)
                {
                    throw new Exception("unknown error");
                }
#if _WIN64
                this.mModuleHandle = Win32API.VirtualAlloc((IntPtr)((Int64)pPEHeader->OptionalHeader.ImageBase), this.mModuleSize, Win32API.MEM_COMMIT | Win32API.MEM_RESERVE, Win32API.PAGE_EXECUTE_READWRITE);
#else
                this.mModuleHandle = Win32API.VirtualAlloc((IntPtr)((Int32)pPEHeader->OptionalHeader.ImageBase), this.mModuleSize, Win32API.MEM_COMMIT | Win32API.MEM_RESERVE, Win32API.PAGE_EXECUTE_READWRITE);
#endif
                if (this.mModuleHandle == IntPtr.Zero)
                {
                    Int32 iLastError = Marshal.GetLastWin32Error();
                    this.mModuleHandle = Win32API.VirtualAlloc(IntPtr.Zero, this.mModuleSize, Win32API.MEM_COMMIT | Win32API.MEM_RESERVE, Win32API.PAGE_EXECUTE_READWRITE);
                }

                if (this.mModuleHandle == IntPtr.Zero)
                {
                    throw new Exception("run out of memory?");
                }

                this.CopyDllDatas(pUnmanagedBuffer, pPEHeader, pSectionHeader);
                pDosHeader = (IMAGE_DOS_HEADER*)this.mModuleHandle;
                pPEHeader = (IMAGE_NT_HEADERS*)(this.mModuleHandle + pDosHeader->e_lfanew);
                pSectionHeader = (IMAGE_SECTION_HEADER*)(this.mModuleHandle + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
                if (pDosHeader->e_magic != 0x5A4D)
                {
                    throw new Exception("DOS file format error");
                }
                if (iBufferLength < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
                {
                    throw new Exception("DOS file header data error");
                }
                if (pPEHeader->Signature != Win32API.IMAGE_NT_SIGNATURE)
                {
                    throw new Exception("windows file Signature error");
                }
                if ((pPEHeader->FileHeader.Characteristics & Win32API.IMAGE_FILE_DLL) != Win32API.IMAGE_FILE_DLL)
                {
                    throw new Exception("Dll Not dynamic library");
                }
                for (Int32 i = 0; i < pPEHeader->FileHeader.NumberOfSections; i++)
                {
                    if (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData > iBufferLength)
                    {
                        throw new Exception("Section data error");
                    }
                }

                //重定位
                var baseRelocDirEntry = pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_BASERELOC);
                if (baseRelocDirEntry.VirtualAddress > 0 && baseRelocDirEntry.Size > 0)
                {
                    this.ReLocation(pPEHeader);
                }
                this.FillImportTable(pPEHeader);
#if _WIN64
                this.mDllMain = (DllMainHandle)Marshal.GetDelegateForFunctionPointer((IntPtr)((Int64)this.mModuleHandle + (Int64)pPEHeader->OptionalHeader.AddressOfEntryPoint), typeof(DllMainHandle));
#else
                this.mDllMain = (DllMainHandle)Marshal.GetDelegateForFunctionPointer(this.mModuleHandle + (Int32)pPEHeader->OptionalHeader.AddressOfEntryPoint, typeof(DllMainHandle));
#endif
                return this.mDllMain.Invoke(this.mModuleHandle, Win32API.DLL_PROCESS_ATTACH, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                throw (ex);
            }
        }

        /// <summary>
        /// 填充导入表
        /// </summary>
        /// <param name="pPEHeader"></param>
        private unsafe void FillImportTable(IMAGE_NT_HEADERS* pPEHeader)
        {
#if _WIN64
            var iOffset = pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress;
            if (iOffset == 0)
            {
                return;
            }

            if(pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_IMPORT).Size == 0)
            {
                return;
            }

            IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((IntPtr)((Int64)this.mModuleHandle + (Int64)iOffset));
            while (pImportDescriptor->Name != 0)
            {
                UInt64* pRealIAT = (UInt64*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pImportDescriptor->FirstThunk));
                UInt64* pOriginalIAT = (UInt64*)((IntPtr)((Int64)this.mModuleHandle + (pImportDescriptor->OriginalFirstThunk == 0 ? (Int64)pImportDescriptor->FirstThunk : (Int64)pImportDescriptor->OriginalFirstThunk)));
                var sDllName = Marshal.PtrToStringAnsi((IntPtr)((Int64)this.mModuleHandle + (Int64)pImportDescriptor->Name));

                var hDll = Win32API.GetModuleHandle(sDllName);
                if (hDll == IntPtr.Zero)
                {
                    hDll = Win32API.LoadLibrary(sDllName);
                }

                if (hDll == IntPtr.Zero)
                {
                    throw new Exception(String.Format("load library({0}) fail", sDllName));
                }

                while (*pOriginalIAT != 0)
                {
                    IntPtr lpFunction = IntPtr.Zero;
                    if ((*pOriginalIAT & Win32API.IMAGE_ORDINAL_FLAG) == Win32API.IMAGE_ORDINAL_FLAG) // 最高位是1
                    {
                        var iFuncID = *pOriginalIAT & 0x0000FFFF;
                        lpFunction = Win32API.GetProcAddress(hDll, (IntPtr)((Int32)iFuncID));
                    }
                    else
                    {
                        //var sFuncName = Marshal.PtrToStringAnsi((IntPtr)((Int64)this.mModuleHandle + (Int64)(*pOriginalIAT) + 2));
                        lpFunction = Win32API.GetProcAddress(hDll, (IntPtr)((Int64)this.mModuleHandle + (Int64)(*pOriginalIAT) + 2));
                    }
                    if (lpFunction != IntPtr.Zero)
                    {
                        *pRealIAT = (UInt64)lpFunction;
                    }
                    pRealIAT++;
                    pOriginalIAT++;
                }
                pImportDescriptor++;
            }
#else
            var iOffset = pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress;
            if (iOffset == 0)
            {
                return;
            }

            if(pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_IMPORT).Size == 0)
            {
                return;
            }

            IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(this.mModuleHandle + (Int32)iOffset);
            while (pImportDescriptor->Name != 0)
            {
                UInt32* pRealIAT = (UInt32*)(this.mModuleHandle + (Int32)pImportDescriptor->FirstThunk);
                UInt32* pOriginalIAT = (UInt32*)(this.mModuleHandle + (pImportDescriptor->OriginalFirstThunk == 0 ? (Int32)pImportDescriptor->FirstThunk : (Int32)pImportDescriptor->OriginalFirstThunk));
                var sDllName = Marshal.PtrToStringAnsi(this.mModuleHandle + (Int32)pImportDescriptor->Name);

                var hDll = Win32API.GetModuleHandle(sDllName);
                if (hDll == IntPtr.Zero)
                {
                    hDll = Win32API.LoadLibrary(sDllName);
                }

                if (hDll == IntPtr.Zero)
                {
                    throw new Exception(String.Format("load library({0}) fail", sDllName));
                }

                while (*pOriginalIAT != 0)
                {
                    IntPtr lpFunction = IntPtr.Zero;
                    if ((*pOriginalIAT & Win32API.IMAGE_ORDINAL_FLAG) == Win32API.IMAGE_ORDINAL_FLAG) // 最高位是1
                    {
                        var iFuncID = *pOriginalIAT & 0x0000FFFF;
                        lpFunction = Win32API.GetProcAddress(hDll, (IntPtr)((Int32)iFuncID));
                    }
                    else
                    {
                        //var sFuncName = Marshal.PtrToStringAnsi(this.mModuleHandle + (Int32)(*pOriginalIAT) + 2);
                        lpFunction = Win32API.GetProcAddress(hDll, this.mModuleHandle + (Int32)(*pOriginalIAT) + 2);
                    }
                    if (lpFunction != IntPtr.Zero)
                    {
                        *pRealIAT = (UInt32)lpFunction;
                    }
                    pRealIAT++;
                    pOriginalIAT++;
                }
                pImportDescriptor++;
            }
#endif
        }

        /// <summary>
        /// 获取API函数委托
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="sProcName"></param>
        /// <returns></returns>
        public T GetProcDelegate<T>(String sProcName) where T : class
        {
            if (typeof(T).BaseType != typeof(MulticastDelegate))
            {
                return null;
            }

            var funcPtr = this.GetProcAddress(sProcName);
            if (funcPtr == IntPtr.Zero)
            {
                return default(T);
            }
            return Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(T)) as T;
        }

        /// <summary>
        /// 获取API函数地址
        /// </summary>
        /// <param name="sProcName"></param>
        /// <returns></returns>
        private unsafe IntPtr GetProcAddress(String sProcName)
        {
            if (this.mModuleHandle == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            if(String.IsNullOrEmpty(sProcName))
            {
                return IntPtr.Zero;
            }

            IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)this.mModuleHandle;
            IMAGE_NT_HEADERS* pPEHeader = (IMAGE_NT_HEADERS*)(this.mModuleHandle + pDosHeader->e_lfanew);
            var exportDirectoryEntry = pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_EXPORT);
            var iOffsetStart = exportDirectoryEntry.VirtualAddress;
            var iSize = exportDirectoryEntry.Size;
            if (iOffsetStart == 0 || iSize == 0)
            {
                return IntPtr.Zero;
            }

#if _WIN64
            IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)((IntPtr)((Int64)this.mModuleHandle + (Int64)iOffsetStart));
            UInt32* pAddressOfFunctions = (UInt32*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pExportDirectory->AddressOfFunctions));
            UInt16* pAddressOfNameOrdinals = (UInt16*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pExportDirectory->AddressOfNameOrdinals));
            UInt32* pAddressOfNames = (UInt32*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pExportDirectory->AddressOfNames));
#else
            IMAGE_EXPORT_DIRECTORY* pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(this.mModuleHandle + (Int32)iOffsetStart);
            UInt32* pAddressOfFunctions = (UInt32*)(this.mModuleHandle + (Int32)pExportDirectory->AddressOfFunctions);
            UInt16* pAddressOfNameOrdinals = (UInt16*)(this.mModuleHandle + (Int32)pExportDirectory->AddressOfNameOrdinals);
            UInt32* pAddressOfNames = (UInt32*)(this.mModuleHandle + (Int32)pExportDirectory->AddressOfNames);
#endif
            UInt16 iOrdinal = 0;
            if (UInt16.TryParse(sProcName, out iOrdinal))
            {
                if(iOrdinal >= pExportDirectory->Base)
                {
                    iOrdinal = (UInt16)(iOrdinal - pExportDirectory->Base);
                    if (iOrdinal >= 0 && iOrdinal < pExportDirectory->NumberOfFunctions)
                    {
                        var iFunctionOffset = pAddressOfFunctions[iOrdinal];
                        if (iFunctionOffset > iOffsetStart && iFunctionOffset < (iOffsetStart + iSize)) // maybe Export Forwarding
                        {
                            return IntPtr.Zero;
                        }
                        else
                        {
#if _WIN64
                            return (IntPtr)((Int64)this.mModuleHandle + iFunctionOffset);
#else
                            return (IntPtr)((Int32)this.mModuleHandle + iFunctionOffset);
#endif
                        }
                    }
                }
            }
            else
            {
                for (Int32 i = 0; i < pExportDirectory->NumberOfNames; i++)
                {
#if _WIN64
                    var sFuncName = Marshal.PtrToStringAnsi((IntPtr)((Int64)this.mModuleHandle + (Int64)pAddressOfNames[i]));
#else
                    var sFuncName = Marshal.PtrToStringAnsi(this.mModuleHandle + (Int32)pAddressOfNames[i]);
#endif
                    if (sProcName.Equals(sFuncName))
                    {
                        iOrdinal = pAddressOfNameOrdinals[i];
                        if (iOrdinal >= 0 && iOrdinal < pExportDirectory->NumberOfFunctions)
                        {
                            var iFunctionOffset = pAddressOfFunctions[iOrdinal];
                            if (iFunctionOffset > iOffsetStart && iFunctionOffset < (iOffsetStart + iSize)) // maybe Export Forwarding
                            {
                                return IntPtr.Zero;
                            }
                            else
                            {
#if _WIN64
                                return (IntPtr)((Int64)this.mModuleHandle + iFunctionOffset);
#else
                                return (IntPtr)((Int32)this.mModuleHandle + iFunctionOffset);
#endif
                            }
                        }
                    }
                }
            }
            return IntPtr.Zero;
        }

        /// <summary>
        /// 重定位表的处理
        /// </summary>
        /// <param name="pPEHeader"></param>
        private unsafe void ReLocation(IMAGE_NT_HEADERS* pPEHeader)
        {
#if _WIN64
            Int64 iDelta = (Int64)((Int64)this.mModuleHandle - (Int64)pPEHeader->OptionalHeader.ImageBase);
#else
            Int32 iDelta = (Int32)this.mModuleHandle - (Int32)pPEHeader->OptionalHeader.ImageBase;
#endif
            if(iDelta == 0)
            {
                return;
            }

#if _WIN64
            IMAGE_BASE_RELOCATION* pRelocation = (IMAGE_BASE_RELOCATION*)((IntPtr)((Int64)this.mModuleHandle +
                (Int64)pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress));
            while (pRelocation->VirtualAddress > 0 && pRelocation->SizeOfBlock > 0)
            {
                UInt16* pLocData = (UInt16*)((IntPtr)pRelocation + sizeof(IMAGE_BASE_RELOCATION));
                var iNumberOfReloc = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                for (Int32 i = 0; i < iNumberOfReloc; i++)
                {
                    if ((pLocData[i] & 0xFFFF) / 0x1000 == Win32API.IMAGE_REL_BASED_HIGHLOW)
                    {
                        UInt32* lpPoint = (UInt32*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pRelocation->VirtualAddress + (pLocData[i] & 0xFFF)));
                        *lpPoint += (UInt32)iDelta;
                    }
                    else if((pLocData[i] & 0xFFFF) / 0x1000 == Win32API.IMAGE_REL_BASED_DIR64)
                    {
                        UInt64* lpPoint = (UInt64*)((IntPtr)((Int64)this.mModuleHandle + (Int64)pRelocation->VirtualAddress + (pLocData[i] & 0xFFF)));
                        *lpPoint += (UInt64)iDelta;
                    }
                } 
                pRelocation  = (IMAGE_BASE_RELOCATION*)((IntPtr)((Int64)((IntPtr)pRelocation) + (Int64)pRelocation->SizeOfBlock));
            }

#else
            IMAGE_BASE_RELOCATION* pRelocation = (IMAGE_BASE_RELOCATION*)(this.mModuleHandle +
                (Int32)pPEHeader->OptionalHeader.GetDirectory(IMAGE_DIRECTORY_ENTRY.IMAGE_DIRECTORY_ENTRY_BASERELOC).VirtualAddress);
            while (pRelocation->VirtualAddress > 0 && pRelocation->SizeOfBlock > 0)
            {
                UInt16* pLocData = (UInt16*)((IntPtr)pRelocation + sizeof(IMAGE_BASE_RELOCATION));
                var iNumberOfReloc = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                for (Int32 i = 0; i < iNumberOfReloc; i++)
                {
                    if ((pLocData[i] & 0xFFFF) / 0x1000 == Win32API.IMAGE_REL_BASED_HIGHLOW)
                    {
                        UInt32* lpPoint = (UInt32*)(this.mModuleHandle + (Int32)pRelocation->VirtualAddress + (pLocData[i] & 0xFFF));
                        *lpPoint += (UInt32)iDelta;
                    }
                } 
                pRelocation  = (IMAGE_BASE_RELOCATION*)((IntPtr)pRelocation + (Int32)pRelocation->SizeOfBlock);
            }
#endif
        }

        /// <summary>
        /// 拷贝区段数据到内存
        /// </summary>
        /// <param name="pUnmanagedBuffer"></param>
        /// <param name="pPEHeader"></param>
        /// <param name="pSectionHeader"></param>
        private unsafe void CopyDllDatas(IntPtr pUnmanagedBuffer, IMAGE_NT_HEADERS* pPEHeader, IMAGE_SECTION_HEADER* pSectionHeader)
        {
            Win32API.CopyMemory(this.mModuleHandle, pUnmanagedBuffer, pPEHeader->OptionalHeader.SizeOfHeaders); // 复制(DOS头+DOS STUB) + PE头 + SECTION TABLE

            // 复制每一个SECTION
            for (Int32 i = 0; i < pPEHeader->FileHeader.NumberOfSections; i++)
            {
                if (pSectionHeader[i].VirtualAddress > 0 && pSectionHeader[i].SizeOfRawData > 0)
                {
                    var lpSection = this.mModuleHandle + (Int32)pSectionHeader[i].VirtualAddress;
                    Win32API.CopyMemory(lpSection, pUnmanagedBuffer + (Int32)pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
                }
            }
        }

        /// <summary>
        /// 计算要申请的内存空间大小
        /// </summary>
        /// <param name="pPEHeader"></param>
        /// <param name="pSectionHeader"></param>
        /// <returns></returns>
        private unsafe UInt32 CalcTotalImageSize(IMAGE_NT_HEADERS* pPEHeader, IMAGE_SECTION_HEADER* pSectionHeader)
        {
            var iAlign = pPEHeader->OptionalHeader.SectionAlignment;
            var iSize = this.GetAlignedSize(pPEHeader->OptionalHeader.SizeOfHeaders, iAlign);
            for (Int32 i = 0; i < pPEHeader->FileHeader.NumberOfSections; i++)
            {
                var iCodeSize = pSectionHeader[i].VirtualSize; // 该区块表对应的区块加载到内存后的大小，这是区块的数据在没有进行SectionAlignment对齐处理前的实际大小
                var iLoadSize = pSectionHeader[i].SizeOfRawData; // 该区块在文件中所占的大小，该字段是已经被FileAlignment对齐处理过的长度。
                var iMaxSize = iLoadSize > iCodeSize ? iLoadSize : iCodeSize;
                var iSectionSize = this.GetAlignedSize((pSectionHeader[i].VirtualAddress + iMaxSize), iAlign);
                if (iSize < iSectionSize)
                {
                    iSize = iSectionSize;
                }
            }
            return iSize;
        }

        /// <summary>
        /// 对齐
        /// </summary>
        /// <param name="iOrigin"></param>
        /// <param name="iAlignment"></param>
        /// <returns></returns>
        private UInt32 GetAlignedSize(UInt32 iOrigin, UInt32 iAlignment)
        {
            return (iOrigin + iAlignment - 1) / iAlignment * iAlignment;
        }

        /// <summary>
        /// 释放DLL
        /// </summary>
        /// <returns></returns>
        private Boolean FreeLibrary()
        {
            if (this.mModuleHandle != IntPtr.Zero)
            {
                //调用 DllMain 通知卸载DLL
                var isDetachOk = this.mDllMain.Invoke(this.mModuleHandle, Win32API.DLL_PROCESS_DETACH, IntPtr.Zero);
                if (isDetachOk)
                {
                    var isMemFreeOK = Win32API.VirtualFree(this.mModuleHandle, 0, Win32API.MEM_RELEASE); // 指定MEM_RELEASE，第二个参数dwSize必须是0，否则返回失败
                    this.mModuleHandle = IntPtr.Zero;
                    return isMemFreeOK;
                }
                else
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// 销毁 清理
        /// </summary>
        public void Dispose()
        {
            this.FreeLibrary();
        }

        /// <summary>
        /// 模块大小
        /// </summary>
        private UInt32 mModuleSize { get; set; }

        /// <summary>
        /// 模块句柄
        /// </summary>
        private IntPtr mModuleHandle { get; set; }

        /// <summary>
        /// DllMain 函数委托，用于通知DLL 模块加载卸载等
        /// </summary>
        private DllMainHandle mDllMain { get; set; }
    }
}
