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

    if (!readMemory(sectionHeaderAddress, sections.data(),
        numberOfSections * sizeof(IMAGE_SECTION_HEADER))) {
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
}



//void PeHeader::loadImport()
//{
//    auto& impDirEntry = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
//    if (impDirEntry.VirtualAddress == 0 || impDirEntry.Size == 0) {
//        hasImport = false;
//        return;
//    }
//
//    DWORD_PTR impRva = impDirEntry.VirtualAddress;
//    DWORD_PTR impVa = rvaToVa(impRva);
//
//    IMAGE_IMPORT_DESCRIPTOR desc;
//    int i = 0;
//
//    while (true) {
//        if (!readMemory(impVa + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), &desc, sizeof(desc))) {
//            break;
//        }
//
//        if (desc.Name == 0 && desc.FirstThunk == 0) {
//            break;
//        }
//
//        char dllName[256] = { 0 };
//        if (!readMemory(base + desc.Name, dllName, sizeof(dllName))) {
//            i++;
//            continue;
//        }
//
//        char* ext = strrchr(dllName, '.');
//        if (ext) *ext = '\0';
//
//        DWORD_PTR thunkRva = desc.FirstThunk;
//        while (true) {
//            IMAGE_THUNK_DATA64 thunk;
//            if (!readMemory(base + thunkRva, &thunk, sizeof(thunk)) ||
//                thunk.u1.AddressOfData == 0) {
//                break;
//            }
//
//            if (IMAGE_SNAP_BY_ORDINAL(thunk.u1.Ordinal)) {
//                std::stringstream ss;
//                ss << "#" << IMAGE_ORDINAL(thunk.u1.Ordinal);
//                importedSymbols.emplace_back(dllName, ss.str());
//            }
//            else {
//                IMAGE_IMPORT_BY_NAME importByName;
//                if (readMemory(base + thunk.u1.AddressOfData, &importByName, sizeof(importByName))) {
//                    std::string symbolName(reinterpret_cast<char*>(&importByName.Name));
//                    importedSymbols.emplace_back(dllName, symbolName);
//                }
//            }
//            thunkRva += sizeof(IMAGE_THUNK_DATA64);
//        }
//        i++;
//    }
//
//    hasImport = true;
//}



PeHeader::PeHeader(DWORD_PTR moduleBase, HANDLE _hProc)
	: hProc(_hProc), base(moduleBase)
{
	loadDosHeader();
	loadNtHeader();
	loadSections();
	loadExport();
	//loadImport();
}


const IMAGE_SECTION_HEADER* PeHeader::getSectionByName(const char* name) const {
    for (const auto& section : sections)
        if (strncmp(reinterpret_cast<const char*>(section.Name), name, 8) == 0)
            return &section;
    return nullptr;
}

const IMAGE_EXPORT_DIRECTORY* PeHeader::getExportDirectory() const {
    return hasExport ? exportDirectory : nullptr;
}

std::vector<std::pair<std::string, DWORD_PTR>> PeHeader::getExportedSymbols() {
    std::vector<std::pair<std::string, DWORD_PTR>> symbols;

    if (!hasExport)
        return symbols;

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

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++){
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

    return symbols;
}




DWORD_PTR PeHeader::rvaToVa(DWORD rva)
{
    for (const auto& section : sections) {
        if (rva >= section.VirtualAddress &&
            rva < section.VirtualAddress + section.Misc.VirtualSize) {
            return base + rva;
        }
    }
    return 0;
}