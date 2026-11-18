/***************************************************************
*
* Copyright (c) 2019, HSEC@YAWEE : 2019/12/10
* All rights reserved. 
*  
**************************************************************/

#ifndef		_HASH_H_
#define		_HASH_H_

typedef void (*pHashBlock)();

typedef struct __tagHASH_CTX
{
		unsigned int 	type;
		unsigned int 	HASH_BLOCK_SIZE;
		unsigned int	MHighBitCount;			//Most significant word of the hash input bit count
		unsigned int	MLowBitCount;			//Second most significant word of the hash input bit count
		unsigned int	HighBitCount;			//Second least significant word of the hash input bit count
		unsigned int	LowBitCount;			//Least significant word of the hash input bit count
		unsigned int	*TempBuf;				//Buffer holding a partial data block of fewer than 512 bits
		unsigned int	*ABCDEFGH;	
	
		pHashBlock  HashBlock;
	
}HASH_CTX;

#define SM3_256  0
#define SHA_1    1
#define SHA_224  2
#define SHA_256  3
#define SHA_384  4
#define SHA_512  5




//SM3_256:Type = 0 SHA_160:Type = 1 SHA_224:Type = 2 SHA_256:Type = 3
//SHA_384:Type = 4 SHA_512:Type = 5

unsigned int Hash_Init(HASH_CTX *pHash_Ctx, unsigned int Type);

void Hash_Updata(HASH_CTX *pHash_Ctx, unsigned char *pData, unsigned int cBData);

void Hash_Final(HASH_CTX *pHash_Ctx, unsigned char *OPdata);

unsigned int Hash_Init_Ram(unsigned int Type, unsigned int PAddr_Result);

void Hash_Updata_NBlock_Ram(unsigned int PAddr_Data, unsigned int BlockN);


#endif

