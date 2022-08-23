#include <iostream>
#include <vector>
#include <string_view>
#include <search.h>
#include <algorithm>
#include <fstream>
#include <cstring>
#include <iterator>
#if _MSC_VER
#include <intrin.h>
#endif
#include "distorm.h"
#include "include/common.h"


UINT32 getUInt32(std::vector<unsigned char> buf, UINT32 start, bool fromBE)
{
    UINT32 tmp = 0;

    tmp = (tmp << 8) + buf.at(start + 0);
    tmp = (tmp << 8) + buf.at(start + 1);
    tmp = (tmp << 8) + buf.at(start + 2);
    tmp = (tmp << 8) + buf.at(start + 3);

    if (fromBE) {
        #if _MSC_VER
        return _byteswap_ulong(tmp);
        #else // Linux
        return __builtin_bswap32(tmp);
        #endif
    }
    else
        return tmp;
}

int indexOf(std::vector<unsigned char> buf, const char* find) {
    auto ret = std::search(buf.begin(), buf.end(), find, find + strlen(find));

    // if index is at end then not found
    if (ret != buf.end())
        return ret - buf.begin();
    else
        return 0;
}

UINT8 extractDSDTfromAmiboardInfo(std::vector<unsigned char> amiboardbuf, std::vector<unsigned char>& out)
{
    INT32 offset;
    UINT32 size = 0;
    EFI_IMAGE_DOS_HEADER* HeaderDOS;

    HeaderDOS = (EFI_IMAGE_DOS_HEADER*)amiboardbuf.data();

    if (HeaderDOS->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid file, not AmiBoardInfo. Aborting!\n");
        return ERR_INVALID_FILE;
    }

    offset = indexOf(amiboardbuf, DSDT_HEADER);
    if (offset <= 0) {
        printf("ERROR: DSDT wasn't found in AmiBoardInfo\n");
        return ERR_FILE_NOT_FOUND;
    }

    size = getUInt32(amiboardbuf, offset + DSDT_HEADER_SZ, TRUE);

    if (size > (UINT32)(amiboardbuf.size() - offset)) {
        printf("ERROR: Read invalid size from DSDT. Aborting!\n");
        return ERR_INVALID_PARAMETER;
    }

    out.resize(size);

    copy(amiboardbuf.begin() + offset, amiboardbuf.begin() + offset + size, out.begin());
    return ERR_SUCCESS;
}

UINT8 injectDSDTintoAmiboardInfo(std::vector<unsigned char> ami, std::vector<unsigned char> dsdtbuf, std::vector<unsigned char>& out)
{
    int i;
    INT32 offset, diffDSDT;

    BOOLEAN hasDotROM = FALSE;
    BOOLEAN needsCodePatching = TRUE;
    UINT32 relocStart, relocSize;
    int physEntries, logicalEntries;
    UINT32 index;
    UINT32 dataLeft;
    UINT32 baseRelocAddr;

    UINT32 oldDSDTsize, newDSDTsize, sectionsStart, alignDiffDSDT;
    EFI_IMAGE_DOS_HEADER* HeaderDOS;
    EFI_IMAGE_NT_HEADERS64* HeaderNT;
    EFI_IMAGE_SECTION_HEADER* Section;
    EFI_IMAGE_BASE_RELOCATION* BASE_RELOCATION;
    RELOC_ENTRY* RELOCATION_ENTRIES;

    const static char* DATA_SECTION = ".data";
    const static char* EMPTY_SECTION = ".empty";
    const static char* RELOC_SECTION = ".reloc";

    static unsigned char* amiboardbuf = (unsigned char*)ami.data();

    HeaderDOS = (EFI_IMAGE_DOS_HEADER*)amiboardbuf;

    if (HeaderDOS->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
        printf("Error: Invalid file, not AmiBoardInfo. Aborting!\n");
        return ERR_INVALID_FILE;
    }

    offset = indexOf(ami, DSDT_HEADER);
    if (offset < 0) {
        printf("ERROR: DSDT wasn't found in AmiBoardInfo\n");
        return ERR_FILE_NOT_FOUND;
    }

    if (indexOf(ami, UNPATCHABLE_SECTION) > 0) {
        hasDotROM = TRUE;
    }

    oldDSDTsize = getUInt32(ami, offset + DSDT_HEADER_SZ, TRUE);

    if (oldDSDTsize > (UINT32)(sizeof(amiboardbuf) - offset)) {
        printf("ERROR: Read invalid size from DSDT. Aborting!\n");
        return ERR_INVALID_PARAMETER;
    }

    newDSDTsize = dsdtbuf.size();
    diffDSDT = newDSDTsize - oldDSDTsize;

    if (diffDSDT <= 0) {
        printf("Info: New DSDT is not larger than old one, no need to patch anything :)\n");
        UINT32 padbytes = (diffDSDT * (-1)); // negative val -> positive

        out.resize(offset);
        copy(ami.begin(), ami.begin() + offset, out.begin()); // Start of PE32
        out.insert(out.end(), dsdtbuf.begin(), dsdtbuf.end());  // new DSDT
        
        // padding to match old DSDT location
        std::vector<unsigned char> padding(padbytes, 0);
        out.insert(out.end(), padding.begin(), padding.end());

        copy(ami.begin() + offset + oldDSDTsize, ami.end(), std::back_inserter(out)); // rest of PE32

        return ERR_SUCCESS;
    }

    HeaderNT = (EFI_IMAGE_NT_HEADERS64*)&amiboardbuf[HeaderDOS->e_lfanew];
    sectionsStart = HeaderDOS->e_lfanew + sizeof(EFI_IMAGE_NT_HEADERS64);
    Section = (EFI_IMAGE_SECTION_HEADER*)&amiboardbuf[sectionsStart];

    relocStart = HeaderNT->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    relocSize = HeaderNT->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if ((HeaderNT->OptionalHeader.DllCharacteristics & DYNAMIC_BASE) && hasDotROM) {
        needsCodePatching = FALSE;
        printf("Info: PE32 has DYNAMIC_BASE set -> no Code Patching required...\n");
    }
    else if (hasDotROM) {
        printf("ERROR: PE32 has .ROM but not DYNAMIC_BASE set -> Unpatchable atm..\n");
        return ERR_ERROR;
    }

    alignDiffDSDT = ALIGN32(diffDSDT);

    printf(" * Patching header...\n");

    HeaderNT->OptionalHeader.SizeOfInitializedData += alignDiffDSDT;
    printf("\tSizeOfInitialzedData: %X --> %X\n",
        HeaderNT->OptionalHeader.SizeOfInitializedData - alignDiffDSDT,
        HeaderNT->OptionalHeader.SizeOfInitializedData);

    HeaderNT->OptionalHeader.SizeOfImage += alignDiffDSDT;
    printf("\tSizeOfImage: %X --> %X\n",
        HeaderNT->OptionalHeader.SizeOfImage - alignDiffDSDT,
        HeaderNT->OptionalHeader.SizeOfImage);

    printf(" * Patching directory entries...\n");
    for (i = 0; i < EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES; i++) {

        if (HeaderNT->OptionalHeader.DataDirectory[i].VirtualAddress == 0)
            continue;

        printf(" - DataDirectory %02X:\n", i);

        HeaderNT->OptionalHeader.DataDirectory[i].VirtualAddress += alignDiffDSDT;
        printf("\tVirtualAddress: %X --> %X\n",
            HeaderNT->OptionalHeader.DataDirectory[i].VirtualAddress - alignDiffDSDT,
            HeaderNT->OptionalHeader.DataDirectory[i].VirtualAddress);
    }

    printf(" * Patching sections...\n");
    for (i = 0; i < HeaderNT->FileHeader.NumberOfSections; i++) {

        if (!strcmp((char*)&Section[i].Name, "")) // Give it a clear name
            memcpy((char*)&Section[i].Name, EMPTY_SECTION, strlen(EMPTY_SECTION) + 1);

        printf(" - Section: %s\n", Section[i].Name);

        if (!strcmp((char*)&Section[i].Name, DATA_SECTION)) {
            /* DSDT blob starts in .data section */
            Section[i].Misc.PhysicalAddress += alignDiffDSDT;
            printf("\tPhysicalAddress: %X --> %X\n",
                Section[i].Misc.PhysicalAddress - alignDiffDSDT,
                Section[i].Misc.PhysicalAddress);

            Section[i].SizeOfRawData += alignDiffDSDT;
            printf("\tSizeOfRawData: %X --> %X\n",
                Section[i].SizeOfRawData - alignDiffDSDT,
                Section[i].SizeOfRawData);
        }
        else if (!strcmp((char*)&Section[i].Name, EMPTY_SECTION)) {
            /* .empty section is after .data -> needs patching */
            Section[i].VirtualAddress += alignDiffDSDT;
            printf("\tVirtualAddress: %X --> %X\n",
                Section[i].VirtualAddress - alignDiffDSDT,
                Section[i].VirtualAddress);

            Section[i].PointerToRawData += alignDiffDSDT;
            printf("\tPointerToRawData: %X --> %X\n",
                Section[i].PointerToRawData - alignDiffDSDT,
                Section[i].PointerToRawData);
        }
        else if (!strcmp((char*)&Section[i].Name, RELOC_SECTION)) {
            /* .reloc section is after .data -> needs patching */
            Section[i].VirtualAddress += alignDiffDSDT;
            printf("\tVirtualAddress: %X --> %X\n",
                Section[i].VirtualAddress - alignDiffDSDT,
                Section[i].VirtualAddress);

            Section[i].PointerToRawData += alignDiffDSDT;
            printf("\tPointerToRawData: %X --> %X\n",
                Section[i].PointerToRawData - alignDiffDSDT,
                Section[i].PointerToRawData);
        }
        else
            printf("\tNothing to do here...\n");
    }

    if (relocStart > 0) {
        printf(" * Patching actual relocations...\n");
        index = 0;
        dataLeft = relocSize;
        baseRelocAddr = relocStart;
        while (dataLeft > 0) {
            BASE_RELOCATION = (EFI_IMAGE_BASE_RELOCATION*)&amiboardbuf[baseRelocAddr];
            physEntries = (BASE_RELOCATION->SizeOfBlock - EFI_IMAGE_SIZEOF_BASE_RELOCATION) / EFI_IMAGE_SIZEOF_RELOC_ENTRY;
            logicalEntries = physEntries - 1; // physEntries needed to calc next Base Relocation Table offset
            RELOCATION_ENTRIES = (RELOC_ENTRY*)&amiboardbuf[baseRelocAddr + EFI_IMAGE_SIZEOF_BASE_RELOCATION];

            baseRelocAddr += EFI_IMAGE_SIZEOF_BASE_RELOCATION + (physEntries * EFI_IMAGE_SIZEOF_RELOC_ENTRY);
            dataLeft -= (physEntries * EFI_IMAGE_SIZEOF_RELOC_ENTRY) + EFI_IMAGE_SIZEOF_BASE_RELOCATION;


            printf(" - Relocation Table %X:\n", index);
            index++;

            if (BASE_RELOCATION->VirtualAddress < (UINT32)offset) {
                printf("\tNothing to do here - VirtualAddress < DSDTOffset (%X < %X)\n",
                    BASE_RELOCATION->VirtualAddress, offset);
                continue;
            }

            //Testing first relocation entry should be good..
            UINT32 shiftBy = ((UINT32)RELOCATION_ENTRIES[0].offset + alignDiffDSDT) & 0xF000;

            BASE_RELOCATION->VirtualAddress += shiftBy;
            printf(" - VirtualAddress: %X --> %X\n",
                BASE_RELOCATION->VirtualAddress - shiftBy,
                BASE_RELOCATION->VirtualAddress);

            for (int j = 0; j < logicalEntries; j++) {
                printf(" - Relocation: %X\n", j);

                RELOCATION_ENTRIES[j].offset += (UINT16)alignDiffDSDT;
                printf("\tOffset: %X --> %X\n",
                    (UINT16)(RELOCATION_ENTRIES[j].offset - alignDiffDSDT),
                    RELOCATION_ENTRIES[j].offset);
            }
        }
    }


    if (needsCodePatching) {
        printf(" * Patching addresses in code\n");
        const static UINT32 MAX_INSTRUCTIONS = 1000;
        _DInst *decomposed = (_DInst*)malloc(sizeof(_DInst) * MAX_INSTRUCTIONS);
        _DecodedInst *disassembled = (_DecodedInst*)malloc(sizeof(_DecodedInst) * MAX_INSTRUCTIONS);
        _DecodeResult res, res2;
        #if _MSC_VER
            _CodeInfo ci = { (_DecodeType)0, (_DecodeType)0, (_DecodeType)0, (_DecodeType)0, Decode64Bits, (_DecodeType)0 };
        #else
            _CodeInfo ci = { 0, 0, 0, 0, Decode64Bits, 0 };
        #endif
        ci.codeOffset = HeaderNT->OptionalHeader.BaseOfCode;
        ci.codeLen = HeaderNT->OptionalHeader.SizeOfCode;
        ci.code = (const unsigned char*)&amiboardbuf[ci.codeOffset];
        ci.dt = Decode64Bits;

        UINT32 decomposedInstructionsCount = 0;
        UINT32 decodedInstructionsCount = 0;
        UINT32 patchCount = 0;

        if (!decomposed || !disassembled) {
            printf("ERROR: malloc failure! Aborting!\n");
            return ERR_ERROR;
        }
        /* Actual disassembly */
        res = distorm_decode(ci.codeOffset,
            ci.code,
            ci.codeLen,
            Decode64Bits,
            disassembled,
            MAX_INSTRUCTIONS,
            &decomposedInstructionsCount);

        /* Decompose for human-readable output */
        res2 = distorm_decompose(&ci,
            decomposed,
            MAX_INSTRUCTIONS,
            &decodedInstructionsCount);

        if (decodedInstructionsCount != decomposedInstructionsCount) {
            printf("ERROR: decompose / decode mismatch! Aborting!\n");
            return ERR_ERROR;
        }

        for (int i = 0; i < (int)decodedInstructionsCount; i++) {

            if ((decomposed[i].disp < (UINT64)offset) || decomposed[i].disp > (MAX_DSDT & 0xFF000))
                continue;

            UINT32 patchOffset = (UINT32)(decomposed[i].addr - ci.codeOffset) + 3;
            UINT32* patchValue = (UINT32*)&ci.code[patchOffset];

            printf("offset: %08X: %s%s%s ",
                patchOffset,
                (char*)disassembled[i].mnemonic.p,
                disassembled[i].operands.length != 0 ? " " : "",
                (char*)disassembled[i].operands.p);

            *patchValue += alignDiffDSDT;
            printf("[%x] --> [%x]\n",
                *patchValue - alignDiffDSDT,
                *patchValue);
            patchCount++;
        }

        if (patchCount < 1) {
            printf("ERROR: Something went wrong, didn't patch anything...\n");
            return ERR_ERROR;
        }

        printf("Patched %u instructions\n", patchCount);
    }

    out.resize(offset);
    /* Copy data till DSDT */
    copy(amiboardbuf, amiboardbuf + offset, out.begin()); // Start of PE32
    // Copy new DSDT
    out.insert(out.end(), dsdtbuf.begin(), dsdtbuf.end());  // new DSDT

    // padding to match old DSDT location
    std::vector<unsigned char> padding(alignDiffDSDT - diffDSDT, 0);
    out.insert(out.end(), padding.begin(), padding.end());

    copy(ami.begin() + offset + oldDSDTsize, ami.end(), std::back_inserter(out)); // rest of PE32

    return ERR_SUCCESS;
}

std::vector<unsigned char> readFile(const char* filename)
{
    // open the file:
    std::ifstream file(filename, std::ios::binary);

    if (file.fail()) {
        printf("Failed to read %s\n", filename);
        exit(1);
    }
    // Stop eating new lines in binary mode!!!
    file.unsetf(std::ios::skipws);

    // get its size:
    std::streampos fileSize;

    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // reserve capacity
    std::vector<unsigned char> vec;
    vec.reserve((unsigned int)fileSize);

    // read the data:
    vec.insert(vec.begin(),
        std::istream_iterator<unsigned char>(file),
        std::istream_iterator<unsigned char>());

    file.close();
    return vec;
}

char* getCmdOption(char** begin, char** end, const std::string& option)
{
    char** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    uint8_t ret;
    std::vector<unsigned char> outBuffer;
    std::vector<unsigned char> dsdtBuffer = std::vector<unsigned char>();
    std::vector<unsigned char> amiBuffer;

    char* amiPath = getCmdOption(argv, argv + argc, "-a");
    char* dsdtPath = getCmdOption(argv, argv + argc, "-d");
    char* outPath = getCmdOption(argv, argv + argc, "-o");

    if (!amiPath) {
        printf("ERROR:missing -a command line option\n");
        return 1;
    }
    if (!dsdtPath) {
        printf("ERROR:missing -d command line option\n");
        return 1;
    }

    amiBuffer = readFile(amiPath);

    // if -o specified then write new AmiBoardInfo to it
    if (outPath) {
        outBuffer = std::vector<unsigned char>();
        dsdtBuffer = readFile(dsdtPath);

        printf("Creating new AmiBoardInfo based on %s with DSDT from %s at %s\n", amiPath, dsdtPath, outPath);
        if (ret = injectDSDTintoAmiboardInfo(amiBuffer, dsdtBuffer, outBuffer)) {
            return ret;
        }

        // write new AmiBoardInfo
        std::ofstream amiOut(outPath, std::ios::binary);
        copy(outBuffer.begin(), outBuffer.end(), std::ostreambuf_iterator< char>(amiOut));
    } else {
        printf("Extracting DSDT from %s to %s\n", amiPath, dsdtPath);
        if (ret = extractDSDTfromAmiboardInfo(amiBuffer, dsdtBuffer)) {
            return ret;
        }

        //write DSDT
        std::ofstream dsdtOut(dsdtPath, std::ios::binary);
        copy(dsdtBuffer.cbegin(), dsdtBuffer.cend(), std::ostreambuf_iterator<char>(dsdtOut));
    }

	return 0;
}
