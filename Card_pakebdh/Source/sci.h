#ifndef _SCI_H_
#define _SCI_H_

#include "HSCTU_Registers.h"


//SCI_CR1
#define  SCI_CR1_SRST			0x00008000
#define  SCI_CR1_CONV			0x00000200
#define  SCI_CR1_MSTR			0x00000100
#define  SCI_CR1_ERRTIME			0x00000010
#define  SCI_CR1_LC				0x00000008
#define  SCI_CR1_T				0x00000004
#define  SCI_CR1_DMAEN			0x00000002
#define  SCI_CR1_TRE				0x00000001

//SCICR2
#define  SCICR2_WTEN			0x00000100
#define  SCICR2_CSHL			0x00000008
#define  SCICR2_CIOC			0x00000004  //This bit is obsolete
#define  SCICR2_CLKC			0x00000002
#define  SCICR2_RSTC			0x00000001

//SCICR3
#define  SCICR3_CSTLPE    0x00000001

//SCIIER
#define  SCIIER_WTFIE     0x00000100
#define  SCIIER_CRESIE    0x00000080
#define  SCIIER_CSTOPIE   0x00000040
#define  SCIIER_CNTORIE   0x00000020
#define  SCIIER_PFIE      0x00000010
#define  SCIIER_ORIE      0x00000008
#define  SCIIER_RDRFIE    0x00000004
#define  SCIIER_TCIE      0x00000002
#define  SCIIER_TDREIE    0x00000001

//SCI_SR
#define  SCI_SR_WTF       0x00000100
#define  SCI_SR_CSRES     0x00000080
#define  SCI_SR_CSTOP     0x00000040
#define  SCI_SR_CNTOR     0x00000020
#define  SCI_SR_PF        0x00000010
#define  SCI_SR_OR        0x00000008
#define  SCI_SR_RDRF      0x00000004
#define  SCI_SR_TC        0x00000002
#define  SCI_SR_TRDE      0x00000001


//SCIRCR

//SCI_DR

//SCI_TCR
#define  SCI_TCR_CLKDM			0x40000000
#define  SCI_TCR_CNTEN			0x20000000


//SCI_SNDCR
#define  SCI_SNDCR_SND			0x80000000

void Master_Sci_Init(void);
void Activate_Card(void);
void Deactivate_Card(void);

void send_time_out(unsigned short clks);
void disnable_send_time_out(void);
unsigned char receive_data(unsigned char *buff, unsigned short len);
void send_byte(unsigned char x);
void send_data(unsigned char *buff, unsigned short len);

#endif

