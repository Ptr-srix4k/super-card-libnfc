# super-card-libnfc
Tool for using the MIFARE Classic Super Gen2 sniffer card with Libnfc (without using Proxmark3 or smarphone app).  
I am referring to the cards described [here](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/magic_cards_notes.md#mifare-classic-super) in the **MIFARE Classic Super Gen2** paragraph.

The source code is based on [this](https://github.com/netscylla/super-card) repository (the code was for the "old" super card) and the code found on the Proxmark3 repository (for the key extraction part).  
The cards can be purchased [here](https://sneaktechnology.com/product/super-sniffer-card-1k-4k-4-byte-7-byte/) or [here](https://aliexpress.com/item/1005004796094277.html) (these are just an example and i am not affiliated with the shops listed).

The code has been successfully tested with PN532 and ARC122U.

# Building
```
git clone https://github.com/Ptr-srix4k/super-card-libnfc/
make
```
# Usage
## Set UID
This command will set the UID to 11223344
```
./nfc-super -w 11223344
```
Example output:
```
Mifare card found - print debug info...
ISO/IEC 14443A (106 kbps) target:
    ATQA (SENS_RES): 00  04  
       UID (NFCID1): 00  00  00  00  
      SAK (SEL_RES): 08  

Execute factory test...
Factory test response is correct - this card is a MIFARE Classic Super Gen2

Writing UID 11 22 33 44 ...
Write done
```
## Extract keys
```
./nfc-super -r
```
Example output:
```
Mifare card found - print debug info...
ISO/IEC 14443A (106 kbps) target:
    ATQA (SENS_RES): 00  04  
       UID (NFCID1): 11  22  33  44  
      SAK (SEL_RES): 08  

Execute factory test...
Factory test response is correct - this card is a MIFARE Classic Super Gen2

Recovering keys ...

Key found! 
UID: 11223344 Sector 00 key A [AA0012561966]

Key found! 
UID: 11223344 Sector 00 key A [AA0012561966]

Key found! 
UID: 11223344 Sector 00 key A [AA0012561966]
```
If the tool cannot extract any keys, it will exit without any "Key Found!" message.
