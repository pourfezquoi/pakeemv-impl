#define SYSTEM_CLOCK_125MHZ    125
#define SYSTEM_CLOCK_120MHZ    120
#define SYSTEM_CLOCK_112MHZ    112
#define SYSTEM_CLOCK_105MHZ    105
#define SYSTEM_CLOCK_96MHZ     96
#define SYSTEM_CLOCK_80MHZ     80
#define SYSTEM_CLOCK_68MHZ     68
#define SYSTEM_CLOCK_60MHZ     60

//---------------------------------------------------------------------
//Initialize Flash: pass the system clock value in System_Clock
//For a 125 MHz system clock, set System_Clock=125
//The cache is enabled by default
//Returns 1 on success or 0 for an invalid system clock frequency parameter.
unsigned char Flash_Setting(unsigned char System_Clock);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Read Flash by word: addr must be four-byte aligned; len is the number of words
void ReadFlash(unsigned int *buff, unsigned int addr, unsigned int len);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Read Flash by byte: len is the length in bytes
void ReadFlash_B(unsigned char *buff, unsigned int addr, unsigned int blen);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Write Flash across page boundaries automatically: addr must be four-byte aligned; len is the number of words
//Erase the affected pages before calling this function; it only writes to Flash.
void WriteFlash(unsigned int *buff,unsigned int addr,unsigned int len);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Write Flash pages across page boundaries automatically: addr must be four-byte aligned; len is the number of words
//Erase the affected pages before calling this function; it only writes to Flash.
//This function is equivalent to WriteFlash but provides faster writes.
void PageWriteFlash(unsigned int *buff,unsigned int addr,unsigned int len);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Erase Flash: addr must be four-byte aligned
void SectorEraseFlash(unsigned int addr);
//---------------------------------------------------------------------

//---------------------------------------------------------------------
//Fast Flash erase: addr must be four-byte aligned
//This function is equivalent to SectorEraseFlash but provides faster erases.
void SectorEraseFlash_Retry(unsigned int addr);
//---------------------------------------------------------------------










