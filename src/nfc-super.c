#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "mifare.h"
#include "mfkey.h"
#include "crapto1.h"

#define SUPER_MAX_TRACES    7

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

uint8_t mfSectorNum(uint8_t blockNo) {
    if (blockNo < 32 * 4)
        return blockNo / 4;
    else
        return 32 + (blockNo - 32 * 4) / 16;

}

uint64_t bytes_to_num(uint8_t *src, size_t len) {
    uint64_t num = 0;
    while (len--) {
        num = (num << 8) | (*src);
        src++;
    }
    return num;
}

void usage()
{
    printf("\nUsage: ./nfc-super  [h] [r] [w xxxxxxxx]\n"); 
    printf("\t h - This help message\n"); 
    printf("\t r - Recover key\n"); 
    printf("\t w xxxxxxxx - Prepare card with UID 8-hex chars\n"); 
}

//Execute factory test command
//For the Mifare super card Gen 2 you should have 00 00 00 02 AA
void factory_test(nfc_device *pnd, nfc_context *context)
{
    uint8_t abtTx[]={0xcf,0x00,0x00,0x00,0x00,0xcc}; 
    uint8_t abtRx[5];
    int szRxBits;
    
    printf("\nExecute factory test...\n");
    
    szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0);
    if (szRxBits != 5) 
    {
        printf("ERROR: Wrong factory test response\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    else
    {
        if ((abtRx[0] == 0x00) && (abtRx[1] == 0x00) && (abtRx[2] == 0x00) && (abtRx[3] == 0x02) && (abtRx[4] == 0xAA))
            printf("Factory test response is correct - this card is a MIFARE Classic Super Gen2\n");
        else
        {
            printf("Factory test response is not correct - wrong card!\n");
            nfc_close(pnd);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }
    }
}

//Write UID to card
void write_uid(nfc_device *pnd, nfc_context *context, uint8_t *uid_sel)
{
    uint8_t abtTx[]={0xcf,0x00,0x00,0x00,0x00,0xcd,0x00,0x00,0x00,0x00,0x00}; 
    uint8_t abtRx[2];
    int szRxBits;
    
    printf("\nWriting UID %02x %02x %02x %02x ...\n",uid_sel[0],uid_sel[1],uid_sel[2],uid_sel[3]);
    
    abtTx[7]  = uid_sel[0];
    abtTx[8]  = uid_sel[1];
    abtTx[9]  = uid_sel[2];
    abtTx[10] = uid_sel[3];
    
    szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0);
    if (szRxBits != 2) 
    {
        printf("ERROR: Wrong write data response\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    else
    {
        if ((abtRx[0] == 0x90) && (abtRx[1] == 0x00))
            printf("Write done\n");
        else
        {
            printf("Write data response is not correct\n");
            nfc_close(pnd);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }
    }
}

//Recover key from sniffing
//This code was copied from proxmark3 repository
void recover_key(nfc_device *pnd, nfc_context *context)
{
    uint8_t abtRx[16];
    uint8_t trace = 0;
    uint8_t traces[SUPER_MAX_TRACES][16];
    int szRxBits;
    
    printf("\nRecovering keys ...\n");

    // read 7 traces from super card
    for (trace = 0; trace < SUPER_MAX_TRACES; trace++) {

        uint8_t abtTx[]={0x30,0x00 + trace}; 
        
        szRxBits=nfc_initiator_transceive_bytes(pnd,abtTx,sizeof(abtTx),abtRx,sizeof(abtRx),0);
        if (szRxBits != 16) 
        {
            printf("ERROR: Wrong response\n");
            nfc_close(pnd);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }
        else
            memcpy(&traces[trace], abtRx, 16);
    }
    
    // recover key from collected traces
    for (trace = 0; trace < SUPER_MAX_TRACES; trace++) 
    {
        uint8_t *trace_data = traces[trace];
        nonces_t data;

        // first
        uint16_t NT0 = (trace_data[6] << 8) | trace_data[7];
        data.cuid = bytes_to_num(trace_data, 4);
        data.nonce = prng_successor(NT0, 31);
        data.nr = bytes_to_num(trace_data + 8, 4);
        data.ar = bytes_to_num(trace_data + 12, 4);
        data.at = 0;

        // second
        for (uint8_t s_strace = trace + 1; s_strace < 7; s_strace++) {
            uint8_t *s_trace_data = traces[s_strace];
            if (mfSectorNum(s_trace_data[5]) == mfSectorNum(trace_data[5])) {
                NT0 = (s_trace_data[6] << 8) | s_trace_data[7];
                data.nonce2 = prng_successor(NT0, 31);
                data.nr2 = bytes_to_num(s_trace_data + 8, 4);
                data.ar2 = bytes_to_num(s_trace_data + 12, 4);
                data.sector = mfSectorNum(trace_data[5]);
                data.keytype = trace_data[4];
                data.state = FIRST;

                uint64_t key64 = -1;
                if (mfkey32_moebius(&data, &key64)) {
                    printf("\nKey found! \nUID: %02x%02x%02x%02x Sector %02x key %c [%" PRIX64 "]\n", trace_data[0], trace_data[1], trace_data[2], trace_data[3], data.sector, (data.keytype == 0x60) ? 'A' : 'B', key64);
                    break;
                }
            }
        }
    }
}

//Configure NFC reader 
void init(nfc_context **context, nfc_device **pnd)
{
    nfc_target nt;

    nfc_init(context);
    if (*context == NULL) 
    {
        ERR("Unable to init libnfc (malloc)");
        exit(EXIT_FAILURE);
    }
    
    //Open NFC reader
    *pnd = nfc_open(*context, NULL);
    if (pnd == NULL) 
    {
        ERR("Error opening NFC reader");
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }
    
    if (nfc_initiator_init(*pnd) < 0) 
    {
        nfc_perror(*pnd, "nfc_initiator_init");
        nfc_close(*pnd);
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }

    // Let the reader only try once to find a tag
    if (nfc_device_set_property_bool(*pnd, NP_INFINITE_SELECT, false) < 0) 
    {
        nfc_perror(*pnd, "nfc_device_set_property_bool");
        nfc_close(*pnd);
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }
    
    // Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
    if (nfc_device_set_property_bool(*pnd, NP_AUTO_ISO14443_4, false) < 0) 
    {
        nfc_perror(*pnd, "nfc_device_set_property_bool");
        nfc_close(*pnd);
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }

    // Try to find a MIFARE Classic tag
    if (nfc_initiator_select_passive_target(*pnd, nmMifare, NULL, 0, &nt) <= 0) 
    {
        printf("Error: no tag was found\n");
        nfc_close(*pnd);
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }
    
    // Test if we are dealing with a MIFARE compatible tag
    if ((nt.nti.nai.btSak & 0x08) == 0) 
    {
        printf("Warning: tag is probably not a MFC!\n");
    }

    // Get the info from the current tag
    printf("Mifare card found - print debug info...\n");
    print_nfc_target(&nt, false);    
    
    //Enable RAW command mode
    if (nfc_device_set_property_bool(*pnd, NP_EASY_FRAMING, false) < 0) 
    {
        nfc_perror(*pnd, "nfc_configure");
        nfc_close(*pnd);
        nfc_exit(*context);
        exit(EXIT_FAILURE);
    }
    
    //Execute factory test
    factory_test(*pnd, *context);
}

int main(int argc, char **argv)
{
    nfc_context *context;
    nfc_device *pnd;
   
    if(argc<=1)
    {
        usage();
        exit(0);               
    }
    
    if ((strcmp(argv[1],"w")==0)||(strcmp(argv[1],"-w")==0))
    {
        uint8_t uid_sel[4]={0x00,0x00,0x00,0x00};
        char *pos = argv[2];
        char dest[2];
        
        init(&context, &pnd);
        
        strncpy(dest, argv[2], 2);
        uid_sel[0] = (uint8_t)strtol(dest, NULL, 16);  
        strncpy(dest, argv[2]+2, 2);
        uid_sel[1] = (uint8_t)strtol(dest, NULL, 16);  
        strncpy(dest, argv[2]+4, 2);
        uid_sel[2] = (uint8_t)strtol(dest, NULL, 16);  
        strncpy(dest, argv[2]+6, 2);
        uid_sel[3] = (uint8_t)strtol(dest, NULL, 16);  

        write_uid(pnd, context, uid_sel);
    }
    
    if ((strcmp(argv[1],"r")==0)||(strcmp(argv[1],"-r")==0))
    {
        init(&context, &pnd);
        recover_key(pnd, context);
    }
    
	return 0;
}

