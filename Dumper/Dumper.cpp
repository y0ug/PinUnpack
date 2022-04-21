#include <Windows.h>

#include <iostream>
#include <fstream>
#include <vector>

#include "Dumper.h"

DWORD dumperFileAlignA(const char* filename, BYTE* image)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(image +
		dos_header->e_lfanew);

	DWORD size = nt_headers->OptionalHeader.SizeOfHeaders;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
		size += section->SizeOfRawData;
	}

	std::ofstream fs(filename, std::ios::binary);
	fs.write((char*)image, size);
	fs.close();
	return 0;
}

DWORD dumperMemAlignA(const char* filename, BYTE* image)
{
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image;
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(image +
		dos_header->e_lfanew);
	
	DWORD size = nt_headers->OptionalHeader.SizeOfHeaders;

	std::vector<BYTE> data(size);
	memcpy(data.data(), image, size);

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) {
			// Virtual section we skip it.
			continue;
		}
		size += section->SizeOfRawData;
		data.resize(size);
		memcpy(data.data() + section->PointerToRawData,
			image + section->VirtualAddress, 
			section->SizeOfRawData);
	}

	std::cout << size << std::endl;

	std::ofstream fs(filename, std::ios::binary);
	fs.write((char*)data.data(), size);
	fs.close();
	return 0;
}