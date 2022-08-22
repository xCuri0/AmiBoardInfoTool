#ifndef COMMON_H
#define COMMON_H

#include "./peImage.h"
#include "./baseTypes.h"

#if defined(_WIN32) || defined(_WIN64)  
#define strcasecmp _stricmp
#endif

/* RETURN CODES */
#define ERR_DIR_NOT_EXIST                   0xEB
#define ERR_FILE_NOT_FOUND                  0xEC
#define ERR_FILE_EXISTS                     0xED
#define ERR_REPLACE                         0xEE
#define ERR_RELOCATION                      0xEF
#define ERR_ERROR                           0xF0

/* DSDT STUFF */
#define DSDT_HEADER "DSDT"
#define DSDT_HEADER_SZ 4
#define UNPATCHABLE_SECTION ".ROM"
#define DYNAMIC_BASE        0x40
#define MAX_DSDT    0x3FFFF

/* COMPRESS RUN */
#define RUN_AS_IS           0
#define RUN_DELETE          1
#define RUN_DEL_OZM_NREQ    2

/* KEXT CONVERSION */
#define MIN_KEXT_ID 0xA
#define MAX_KEXT_ID 0xF

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

#define SRC_NOT_SET    0
#define SRC_KEXT       1
#define SRC_BINARY     2
#define SRC_EFI        3


#endif // COMMON_H
