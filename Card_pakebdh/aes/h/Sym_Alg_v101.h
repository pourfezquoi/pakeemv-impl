/***************************************************************
*
* Copyright (c) 2019, HSEC@YAWEE : 2019/12/12
* All rights reserved. 
*  
**************************************************************/

#ifndef		_SYM_ALG_H_
#define		_SYM_ALG_H_
	
//AlgMod
#define ECB 0  
#define CBC 1  
#define OFB 2  
#define CTR 3 

//OpType
#define ENC 0
#define DEC 1

//AlgType
#define DES 0  //include TDES
#define AES 1
#define SM4 2
#define SM1 3
#define SM7 4

//KeyLen
#define SM1_128 16  
#define SM1_256 32

#define DES_64  8 
#define DES_128 16  
#define DES_192 24  

#define AES_128 16  
#define AES_192 24  
#define AES_256 32  

#define SM4_KEYLEN  16 

//System RAM interface

void DES_Encrypt(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void DES_Decrypt(unsigned char* key, unsigned char* ciphertext,  unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void TDES_Encrypt(unsigned char* key, unsigned int keylen, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);
	
void TDES_Decrypt(unsigned char* key, unsigned int keylen, unsigned char* ciphertext,  unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void SM4_Encrypt(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void SM4_Decrypt(unsigned char* key, unsigned char* ciphertext, unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);
	
void AES_Encrypt(unsigned char* key, unsigned int keylen, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void AES_Decrypt(unsigned char* key, unsigned int keylen, unsigned char* ciphertext, unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void SM1_Encrypt(unsigned char* key, unsigned int keylen, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);//Supports 16-byte and 32-byte keys

void SM1_Decrypt(unsigned char* key, unsigned int keylen, unsigned char* ciphertext,  unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void SM7_Encrypt(unsigned char* key, unsigned char* plaintext, unsigned char* ciphertext, unsigned int blen, unsigned char *IV, unsigned int algmod);

void SM7_Decrypt(unsigned char* key, unsigned char* ciphertext,  unsigned char* plaintext, unsigned int blen, unsigned char *IV, unsigned int algmod);


//Dedicated RAM interface
unsigned char Sym_Alg_Init(unsigned char AlgType, unsigned char OpType, unsigned char *Key, unsigned char KeyLen, unsigned char *IV, unsigned char AlgMod);

void Sym_Alg_Update(unsigned int Paddr_In, unsigned int Paddr_Out, unsigned int BLen);

void Sym_Alg_Final(void);


//Sym_Alg_Update_Set
//This function only starts the operation; it does not wait for completion. Call Check_Finish to check the completion flag before retrieving the result.
//The input and output addresses for this function refer to the dedicated RAM region
void Sym_Alg_Update_Set(unsigned int Paddr_In, unsigned int Paddr_Out, unsigned int BLen);

//Check_Finish
//Returns 1 while the operation is incomplete;
//returns 0 when the operation is complete.
unsigned char Check_Finish(void);


#endif



