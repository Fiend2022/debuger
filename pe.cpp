#include "pe.hpp"
#include <sstream>



bool PeHeader::readMemory(DWORD_PTR address, void* buffer, SIZE_T size)
{
    SIZE_T bytesRead;
    return ::ReadProcessMemory(hProc, (LPCVOID)address, buffer, size, &bytesRead) &&
        bytesRead == size;
}

void PeHeader::loadDosHeader()
{
	if (!readMemory(base, &dosHeader, sizeof(IMAGE_DOS_HEADER)))
		throw std::runtime_error("Failed to read DOS header");

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		throw std::runtime_error("Invalid DOS signature");
}

void PeHeader::loadNtHeader()
{
    if (!readMemory(base + dosHeader.e_lfanew, &ntHeader, sizeof(IMAGE_NT_HEADERS)))
		throw std::runtime_error("Failed to read NT headers");

	if (ntHeader.Signature != IMAGE_NT_SIGNATURE) 
		throw std::runtime_error("Invalid NT signature");

	is64Bit = (ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
		
}

void PeHeader::loadSections()
{
    // Получаем указатель на начало секций в памяти процесса
    DWORD_PTR sectionHeaderAddress = base + dosHeader.e_lfanew +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        ntHeader.FileHeader.SizeOfOptionalHeader;

    WORD numberOfSections = ntHeader.FileHeader.NumberOfSections;
    sections.resize(numberOfSections);

    if (!readMemory(sectionHeaderAddress, sections.data(), numberOfSections * sizeof(IMAGE_SECTION_HEADER)))
    {
        throw std::runtime_error("Failed to read section headers");
    }
}

void PeHeader::loadExport()
{
    auto& dataDir = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dataDir.VirtualAddress == 0 || dataDir.Size == 0) 
    {
        hasExport = false;
        return;
    }


    exportDirectory = new IMAGE_EXPORT_DIRECTORY();
    DWORD_PTR exportRva = dataDir.VirtualAddress;
    DWORD_PTR exportVa = rvaToVa(exportRva);
    if (!readMemory(exportVa, exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY)))
    {
        hasExport = false;
        return;
    }

    hasExport = true;


    // Читаем таблицы
    std::vector<DWORD> addressOfFunctions(exportDirectory->NumberOfFunctions);
    std::vector<DWORD> addressOfNames(exportDirectory->NumberOfNames);
    std::vector<WORD> addressOfNameOrdinals(exportDirectory->NumberOfNames);

    DWORD_PTR funcVa = rvaToVa(exportDirectory->AddressOfFunctions);
    DWORD_PTR nameVa = rvaToVa(exportDirectory->AddressOfNames);
    DWORD_PTR ordVa = rvaToVa(exportDirectory->AddressOfNameOrdinals);

    if (!readMemory(funcVa, addressOfFunctions.data(), addressOfFunctions.size() * sizeof(DWORD)) ||
        !readMemory(nameVa, addressOfNames.data(), addressOfNames.size() * sizeof(DWORD)) ||
        !readMemory(ordVa, addressOfNameOrdinals.data(), addressOfNameOrdinals.size() * sizeof(WORD))) {
        throw std::runtime_error("Failed to read export tables");
    }

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char nameBuffer[256] = { 0 };
        DWORD_PTR nameRva = addressOfNames[i];
        DWORD_PTR nameVa = rvaToVa(nameRva);
        if (readMemory(nameVa, nameBuffer, sizeof(nameBuffer)))
        {
            if (nameBuffer[0] != '?')
            {
                DWORD funcRva = addressOfFunctions[addressOfNameOrdinals[i]];
                DWORD_PTR funcVa = base + funcRva;
                symbols.emplace_back(nameBuffer, funcVa);
            }
        }
    }

}

PeHeader::PeHeader(DWORD_PTR moduleBase, HANDLE _hProc)
     : hProc(_hProc), base(moduleBase)
{
    loadDosHeader();
    loadNtHeader();
    loadSections();
    loadExport();
}





const IMAGE_SECTION_HEADER* PeHeader::getSectionByName(const char* name) const
{
    for (const auto& section : sections)
        if (strncmp(reinterpret_cast<const char*>(section.Name), name, 8) == 0)
            return &section;
    return nullptr;
}

const IMAGE_EXPORT_DIRECTORY* PeHeader::getExportDirectory() const
{
    return hasExport ? exportDirectory : nullptr;
}

std::vector<std::pair<std::string, DWORD_PTR>> PeHeader::getExportedSymbols()
{
    
    return symbols;
}




DWORD_PTR PeHeader::rvaToVa(DWORD rva)
{
    for (const auto& section : sections)
    {
        if (rva >= section.VirtualAddress &&
            rva < section.VirtualAddress + section.Misc.VirtualSize)
        {
            return base + rva;
        }
    }
    return 0;
}