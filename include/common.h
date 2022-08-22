#ifndef COMMON_H
#define COMMON_H

#include "./peImage.h"
#include "./baseTypes.h"


/* RETURN CODES */
#define ERR_FILE_NOT_FOUND                  0xEC
#define ERR_ERROR                           0xF0

/* DSDT STUFF */
#define DSDT_HEADER "DSDT"
#define DSDT_HEADER_SZ 4
#define UNPATCHABLE_SECTION ".ROM"
#define DYNAMIC_BASE        0x40
#define MAX_DSDT    0x3FFFF

#define ALIGN16(Value) (((Value)+15) & ~15)
#define ALIGN32(Value) (((Value)+31) & ~31)


/* PE IMAGE */
///
/// @attention
/// EFI_IMAGE_HEADERS64 is for use ONLY by tools.
///
typedef struct {
    UINT32                      Signature;
    EFI_IMAGE_FILE_HEADER       FileHeader;
    EFI_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} EFI_IMAGE_NT_HEADERS64;

#define EFI_IMAGE_SIZEOF_NT_OPTIONAL64_HEADER sizeof (EFI_IMAGE_NT_HEADERS64)

typedef struct {
    UINT16 offset : 12;
    UINT16 type : 4;
} RELOC_ENTRY;

#define EFI_IMAGE_SIZEOF_RELOC_ENTRY sizeof (RELOC_ENTRY)

#endif // COMMON_H
