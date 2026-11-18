/***************************************************************
*
* Copyright (c) 2019, HSEC@YAWEE : 2019/12/9
* All rights reserved. 
*  
**************************************************************/

#ifndef		_TRNG_H_
#define		_TRNG_H_

#define TRUE_RANDOM_NUMER	1
#define PSEUDO_RANDOM_NUMER	0

void Trng_Init(unsigned char Type);

void Trng_Out_U32(unsigned int *buff, unsigned int len);

void Trng_Out_U8(unsigned char *buff, unsigned int len);


#endif
