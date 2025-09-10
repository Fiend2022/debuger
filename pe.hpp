#pragma once


#include <Windows.h>
#include <istream>
#include <vector>



class PeHeader {


private:
    char* filename;     

    HANDLE              fd;             
    HANDLE              mapd;           
    PBYTE               mem;            
    DWORD               filesize;

    DWORD_PTR base;
    HANDLE hProc;

    IMAGE_DOS_HEADER dosHeader;       
    IMAGE_NT_HEADERS ntHeader;        

    IMAGE_IMPORT_DESCRIPTOR impdir;    
    DWORD               sizeImpdir;    
    DWORD               countImpdes;   

    IMAGE_EXPORT_DIRECTORY expdir;    
    DWORD               sizeExpdir;     

    std::vector<IMAGE_SECTION_HEADER> sections;  
    DWORD                   countSec;

    IMAGE_SECTION_HEADER* sectionPTR;
    bool is64Bit;
    bool hasImport;
    bool hasExport;


    IMAGE_EXPORT_DIRECTORY* exportDirectory;
    //std::vector<IMAGE_IMPORT_DESCRIPTOR> importDescriptors;
    //std::vector<std::pair<std::string, DWORD_PTR>> importedSymbols;

    void loadDosHeader();
    void loadNtHeader();
    void loadImport();
    void loadExport();
    void loadSections();

    bool readMemory(DWORD_PTR address, void* buffer, SIZE_T size);
    DWORD_PTR rvaToVa(DWORD rva);
public:

    PeHeader(DWORD_PTR moduledBase, HANDLE _hProc);


    const std::vector<IMAGE_SECTION_HEADER>& getSections() const { return sections; }
    const IMAGE_SECTION_HEADER* getSectionByName(const char* name) const;
    

    bool hasExports() const { return hasExport; }
    const IMAGE_EXPORT_DIRECTORY* getExportDirectory() const;
    std::vector<std::pair<std::string, DWORD_PTR>> getExportedSymbols();

    //const std::vector<std::pair<std::string, DWORD_PTR>>& PeHeader::getImportedSymbols() const {
    //    return importedSymbols;
    //}

    //bool hasImports() const { return hasImport; }
    //const std::vector<IMAGE_IMPORT_DESCRIPTOR>& getImportDescriptors() const { return importDescriptors; }
    
};

