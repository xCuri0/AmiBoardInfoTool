# AmiBoardInfoTool
Modify and extract DSDT from AmiBoardInfo.

### Usage
Extract to DSDT.aml from AmiBoardInfo.efi
```
./AmiBoardInfoTool -a AmiBoardInfo.efi -d DSDT.aml
```
Build AmiBoardInfoNew.efi using AmiBoardInfo.efi and DSDT.aml
```
./AmiBoardInfoTool -a AmiBoardInfo.efi -d DSDT.aml -o AmiBoardInfoNew.efi
```

### Credit
[OZMTool](https://github.com/tuxuser/UEFITool/tree/OZM/OZMTool) almost all the code was adapted from here.
