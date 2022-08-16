#include "Windows.h"
#include <iostream>

int main(int argc, char* argv[]) {
	const int MAX_FILEPATH{ 255 };
	char fileName[MAX_FILEPATH]{ 0 };
	memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH);
	HANDLE file = NULL;
	DWORD fileSize = NULL;
	DWORD bytesRead = NULL;
	LPVOID fileData = NULL;
	PIMAGE_DOS_HEADER dosHeader{};
	PIMAGE_NT_HEADERS imageNTHeaders{};
	PIMAGE_SECTION_HEADER sectionHeader{};
	PIMAGE_SECTION_HEADER importSection{};
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor{};
	PIMAGE_THUNK_DATA thunkData{};
	DWORD thunk = NULL;
	DWORD rawOffset = NULL;

	file = CreateFileA(fileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) std::cout << "File cant be read OwO";

	fileSize = GetFileSize(file, NULL);
	fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

	ReadFile(file, fileData, fileSize, &bytesRead, NULL);

	// DOS_HEADER
	dosHeader = (PIMAGE_DOS_HEADER)fileData;
	std::cout << "======== DOS HEADER ========\n";
	std::cout << "Magic number: " << std::hex << dosHeader->e_magic << "\n";
	std::cout << "Bytes on last page of file: " << std::hex << dosHeader->e_cblp << "\n";
	std::cout << "Pages in file: " << std::hex << dosHeader->e_cp << "\n";
	std::cout << "Relocations: " << std::hex << dosHeader->e_crlc << "\n";
	std::cout << "Size of header in paragraphs: " << std::hex << dosHeader->e_cparhdr << "\n";
	std::cout << "Minimum extra paragraphs needed: " << std::hex << dosHeader->e_minalloc << "\n";
	std::cout << "Maximum extra paragraphs needed: " << std::hex << dosHeader->e_maxalloc << "\n";
	std::cout << "Initial SS value: " << std::hex << dosHeader->e_ss << "\n";
	std::cout << "tInitial SP value: " << std::hex << dosHeader->e_sp << "\n";
	std::cout << "Initial SP value: " << std::hex << dosHeader->e_sp << "\n";
	std::cout << "Checksum: " << std::hex << dosHeader->e_csum << "\n";
	std::cout << "Initial IP value:	" << std::hex << dosHeader->e_ip << "\n";
	std::cout << "Initial CS value: " << std::hex << dosHeader->e_cs << "\n";
	std::cout << "File address of relocation table:" << std::hex << dosHeader->e_lfarlc << "\n";
	std::cout << "Overlay number: " << std::hex << dosHeader->e_ovno << "\n";
	std::cout << "OEM identifier: " << std::hex << dosHeader->e_oemid << "\n";
	std::cout << "OEM identifier: " << std::hex << dosHeader->e_oemid << "\n";
	std::cout << "OEM information: " << std::hex << dosHeader->e_oeminfo << "\n";
	std::cout << "File address of new exe header: " << std::hex << dosHeader->e_lfanew << "\n";

	return 0;
}