
// +FHDR -----------------------------------------------------------------------
// Copyright (c) 2021, Hongsi.
// Hongsi Confidential Proprietary
// 2021/08/25
//
// -----------------------------------------------------------------------------
// File Name: HSC32TU_Registers.h
// Type: C Language
//
// -----------------------------------------------------------------------------
// Description:
// This code is the header file for HSC32TU registers.
//
// -----------------------------------------------------------------------------
// Revision History
// DATE         AUTHOR          DESCRIPTION
// 2021/08/25                   V1.0
// -FHDR -----------------------------------------------------------------------

// ---------------------------------------------------------------------
// Register Definitions
// ---------------------------------------------------------------------

#ifndef _HSCTU_H_
#define _HSCTU_H_

//CRM
#define MCGCR               (*(volatile unsigned int   *)0x40000000)
#define DIVCR               (*(volatile unsigned int   *)0x4000000C)
#define CNTCR               (*(volatile unsigned int   *)0x40000010)
#define RCSR                (*(volatile unsigned int   *)0x40000014)


//NVIC
#define NVIC_ISER           (*(volatile unsigned int   *)0xE000E100)
#define NVIC_ICER           (*(volatile unsigned int   *)0xE000E180)
#define NVIC_ISPR           (*(volatile unsigned int   *)0xE000E200)
#define NVIC_ICPR           (*(volatile unsigned int   *)0xE000E280)
#define NVIC_IABR           (*(volatile unsigned int   *)0xE000E300)
#define NVIC_IPR0           (*(volatile unsigned int   *)0xE000E400)
#define NVIC_IPR1           (*(volatile unsigned int   *)0xE000E404)
#define NVIC_IPR2           (*(volatile unsigned int   *)0xE000E408)
#define NVIC_IPR3           (*(volatile unsigned int   *)0xE000E40C)
#define NVIC_IPR4           (*(volatile unsigned int   *)0xE000E410)
#define NVIC_IPR5           (*(volatile unsigned int   *)0xE000E414)
#define NVIC_IPR6           (*(volatile unsigned int   *)0xE000E418)
#define NVIC_IPR7           (*(volatile unsigned int   *)0xE000E41C)

//DMAC
#define INTSR               (*(volatile unsigned int   *)0x50000000)
#define TCINTSR             (*(volatile unsigned int   *)0x50000004)
#define TCCR                (*(volatile unsigned int   *)0x50000008)
#define TERRINTSR           (*(volatile unsigned int   *)0x5000000C)
#define TERRCR              (*(volatile unsigned int   *)0x50000010)
#define TCSR                (*(volatile unsigned int   *)0x50000014)
#define TERRSR              (*(volatile unsigned int   *)0x50000018)
#define CENSR               (*(volatile unsigned int   *)0x5000001C)
#define SBRR                (*(volatile unsigned int   *)0x50000020)
#define SSRR                (*(volatile unsigned int   *)0x50000024)
#define SLBRR               (*(volatile unsigned int   *)0x50000028)
#define SLSRR               (*(volatile unsigned int   *)0x5000002C)
#define CFGR                (*(volatile unsigned int   *)0x50000030)
#define SYNCR               (*(volatile unsigned int   *)0x50000034)
#define C0SADDR             (*(volatile unsigned int   *)0x50000100)
#define C0DADDR             (*(volatile unsigned int   *)0x50000104)
#define C0LLIR              (*(volatile unsigned int   *)0x50000108)
#define C0CR                (*(volatile unsigned int   *)0x5000010C)
#define C0CFGR              (*(volatile unsigned int   *)0x50000110)
#define C1SADDR             (*(volatile unsigned int   *)0x50000120)
#define C1DADDR             (*(volatile unsigned int   *)0x50000124)
#define C1LLIR              (*(volatile unsigned int   *)0x50000128)
#define C1CR                (*(volatile unsigned int   *)0x5000012C)
#define C1CFGR              (*(volatile unsigned int   *)0x50000130)
#define C2SADDR             (*(volatile unsigned int   *)0x50000140)
#define C2DADDR             (*(volatile unsigned int   *)0x50000144)
#define C2LLIR              (*(volatile unsigned int   *)0x50000148)
#define C2CR                (*(volatile unsigned int   *)0x5000014C)
#define C2CFGR              (*(volatile unsigned int   *)0x50000150)
#define C3SADDR             (*(volatile unsigned int   *)0x50000160)
#define C3DADDR             (*(volatile unsigned int   *)0x50000164)
#define C3LLIR              (*(volatile unsigned int   *)0x50000168)
#define C3CR                (*(volatile unsigned int   *)0x5000016C)
#define C3CFGR              (*(volatile unsigned int   *)0x50000170)
#define C4SADDR             (*(volatile unsigned int   *)0x50000180)
#define C4DADDR             (*(volatile unsigned int   *)0x50000184)
#define C4LLIR              (*(volatile unsigned int   *)0x50000188)
#define C4CR                (*(volatile unsigned int   *)0x5000018C)
#define C4CFGR              (*(volatile unsigned int   *)0x50000190)
#define C5SADDR             (*(volatile unsigned int   *)0x500001A0)
#define C5DADDR             (*(volatile unsigned int   *)0x500001A4)
#define C5LLIR              (*(volatile unsigned int   *)0x500001A8)
#define C5CR                (*(volatile unsigned int   *)0x500001AC)
#define C5CFGR              (*(volatile unsigned int   *)0x500001B0)
#define C6SADDR             (*(volatile unsigned int   *)0x500001C0)
#define C6DADDR             (*(volatile unsigned int   *)0x500001C4)
#define C6LLIR              (*(volatile unsigned int   *)0x500001C8)
#define C6CR                (*(volatile unsigned int   *)0x500001CC)
#define C6CFGR              (*(volatile unsigned int   *)0x500001D0)
#define C7SADDR             (*(volatile unsigned int   *)0x500001E0)
#define C7DADDR             (*(volatile unsigned int   *)0x500001E4)
#define C7LLIR              (*(volatile unsigned int   *)0x500001E8)
#define C7CR                (*(volatile unsigned int   *)0x500001EC)
#define C7CFGR              (*(volatile unsigned int   *)0x500001F0)


//TIMER0
#define PMR0                (*(volatile unsigned int   *)0x40004000)
#define PCSR0               (*(volatile unsigned int   *)0x40004004)
#define PCNCR0              (*(volatile unsigned int   *)0x40004008)


//TIMER1
#define PMR1                (*(volatile unsigned int   *)0x40005000)
#define PCSR1               (*(volatile unsigned int   *)0x40005004)
#define PCNCR1              (*(volatile unsigned int   *)0x40005008)


//TIMER2
#define PMR2                (*(volatile unsigned int   *)0x40006000)
#define PCSR2               (*(volatile unsigned int   *)0x40006004)
#define PCNCR2              (*(volatile unsigned int   *)0x40006008)

//SYSTICK
#define SYSTCSR             (*(volatile unsigned int   *)0xE000E010)
#define SYSTRVR             (*(volatile unsigned int   *)0xE000E014)
#define SYSTCVR             (*(volatile unsigned int   *)0xE000E018)
#define SYSTCALIB           (*(volatile unsigned int   *)0xE000E01C)

//TIM1(PWM1)
#define TIM1_CR1            (*(volatile unsigned int   *)0x4000E000)
#define TIM1_CR2            (*(volatile unsigned int   *)0x4000E004)
#define TIM1_SMCR           (*(volatile unsigned int   *)0x4000E008)
#define TIM1_DIER           (*(volatile unsigned int   *)0x4000E00C)
#define TIM1_SR             (*(volatile unsigned int   *)0x4000E010)
#define TIM1_EGR            (*(volatile unsigned int   *)0x4000E014)
#define TIM1_CCMR1          (*(volatile unsigned int   *)0x4000E018)
#define TIM1_CCMR2          (*(volatile unsigned int   *)0x4000E01C)
#define TIM1_CCMR3          (*(volatile unsigned int   *)0x4000E020)
#define TIM1_CCER           (*(volatile unsigned int   *)0x4000E024)
#define TIM1_CNT            (*(volatile unsigned int   *)0x4000E028)
#define TIM1_PSC            (*(volatile unsigned int   *)0x4000E02C)
#define TIM1_ARR            (*(volatile unsigned int   *)0x4000E030)
#define TIM1_RCR            (*(volatile unsigned int   *)0x4000E034)
#define TIM1_CCR1           (*(volatile unsigned int   *)0x4000E038)
#define TIM1_CCR2           (*(volatile unsigned int   *)0x4000E03C)
#define TIM1_CCR3           (*(volatile unsigned int   *)0x4000E040)
#define TIM1_CCR4           (*(volatile unsigned int   *)0x4000E044)
#define TIM1_CCR5           (*(volatile unsigned int   *)0x4000E048)
#define TIM1_CCR6           (*(volatile unsigned int   *)0x4000E04C)
#define TIM1_BDTR           (*(volatile unsigned int   *)0x4000E050)
#define TIM1_OR1            (*(volatile unsigned int   *)0x4000E060)

//TIM2(PWM2)
#define TIM2_CR1            (*(volatile unsigned int   *)0x4000F000)
#define TIM2_SMCR           (*(volatile unsigned int   *)0x4000F008)
#define TIM2_DIER           (*(volatile unsigned int   *)0x4000F00C)
#define TIM2_SR             (*(volatile unsigned int   *)0x4000F010)
#define TIM2_EGR            (*(volatile unsigned int   *)0x4000F014)
#define TIM2_CCMR1          (*(volatile unsigned int   *)0x4000F018)
#define TIM2_CCER           (*(volatile unsigned int   *)0x4000F024)
#define TIM2_CNT            (*(volatile unsigned int   *)0x4000F028)
#define TIM2_PSC            (*(volatile unsigned int   *)0x4000F02C)
#define TIM2_ARR            (*(volatile unsigned int   *)0x4000F030)
#define TIM2_RCR            (*(volatile unsigned int   *)0x4000F034)
#define TIM2_CCR1           (*(volatile unsigned int   *)0x4000F038)
#define TIM2_CCR2           (*(volatile unsigned int   *)0x4000F03C)
#define TIM2_BDTR           (*(volatile unsigned int   *)0x4000F050)


//WDT
#define WMR                 (*(volatile unsigned int   *)0x40007000)
#define WCR                 (*(volatile unsigned int   *)0x40007004)
#define WSR                 (*(volatile unsigned int   *)0x40007008)
#define WCNTR               (*(volatile unsigned int   *)0x4000700C)

//CRC
#define CRC_CR              (*(volatile unsigned int   *)0x50007000)
#define CRC_INIT            (*(volatile unsigned int   *)0x50007004)
#define CRC_PR              (*(volatile unsigned int   *)0x50007008)
#define CRC_DR              (*(volatile unsigned int   *)0x5000700C)
#define CRC_SUM             (*(volatile unsigned int   *)0x50007010)


//USBI
#define USB_FADDR           (*(volatile unsigned char  *)0x50002000)
#define USB_POWER           (*(volatile unsigned char  *)0x50002001)
#define USB_INTRTX          (*(volatile unsigned short *)0x50002002)
#define USB_INTRRX          (*(volatile unsigned short *)0x50002004)
#define USB_INTRTXE         (*(volatile unsigned short *)0x50002006)
#define USB_INTRRXE         (*(volatile unsigned short *)0x50002008)
#define USB_INTRUSB         (*(volatile unsigned char  *)0x5000200a)
#define USB_INTRUSBE        (*(volatile unsigned char  *)0x5000200b)
#define USB_FRAME           (*(volatile unsigned short *)0x5000200c)
#define USB_INDEX           (*(volatile unsigned char  *)0x5000200e)
#define USB_TXMAXP          (*(volatile unsigned short *)0x50002010)
#define USB_CSR0            (*(volatile unsigned short *)0x50002012)
#define USB_TXCSR           (*(volatile unsigned short *)0x50002012)
#define USB_RXMAXP          (*(volatile unsigned short *)0x50002014)
#define USB_RXCSR           (*(volatile unsigned short *)0x50002016)
#define USB_COUNT0          (*(volatile unsigned char  *)0x50002018)
#define USB_RXCOUNT         (*(volatile unsigned short *)0x50002018)
#define USB_TxFIFOsz        (*(volatile unsigned char  *)0x50002062)
#define USB_RxFIFOsz        (*(volatile unsigned char  *)0x50002063)
#define USB_TxFIFOadd       (*(volatile unsigned short *)0x50002064)
#define USB_RxFIFOadd       (*(volatile unsigned short *)0x50002066)
#define USB_EP0_FIFO        (*(volatile unsigned int   *)0x50002020)
#define USB_EP0_FIFO_8      (*(volatile unsigned char  *)0x50002020)
#define USB_EP1_FIFO        (*(volatile unsigned int   *)0x50002024)
#define USB_EP1_FIFO_8      (*(volatile unsigned char  *)0x50002024)
#define USB_EP2_FIFO        (*(volatile unsigned int   *)0x50002028)
#define USB_EP2_FIFO_8      (*(volatile unsigned char  *)0x50002028)
#define USB_EP3_FIFO        (*(volatile unsigned int   *)0x5000202c)
#define USB_EP3_FIFO_8      (*(volatile unsigned char  *)0x5000202c)
#define USB_EP4_FIFO        (*(volatile unsigned int   *)0x50002030)
#define USB_EP4_FIFO_8      (*(volatile unsigned char  *)0x50002030)
#define USB_EP5_FIFO        (*(volatile unsigned int   *)0x50002034)
#define USB_EP5_FIFO_8      (*(volatile unsigned char  *)0x50002034)
#define USB_EP6_FIFO        (*(volatile unsigned int   *)0x50002038)
#define USB_EP6_FIFO_8      (*(volatile unsigned char  *)0x50002038)
#define USB_EP7_FIFO        (*(volatile unsigned int   *)0x5000203c)
#define USB_EP7_FIFO_8      (*(volatile unsigned char  *)0x5000203c)
#define USB_EP8_FIFO        (*(volatile unsigned int   *)0x50002040)
#define USB_EP8_FIFO_8      (*(volatile unsigned char  *)0x50002040)
#define USB_RAM_CTRL        (*(volatile unsigned int   *)0x5000240C)
#define USB_PHY_CTRL        (*(volatile unsigned int   *)0x50002410)
#define USB_PHY_DIV_I       (*(volatile unsigned int   *)0x50002414)
#define USB_FIFO0_ADDR      (*(volatile unsigned int   *)0x50002430)
#define USB_FIFO1_ADDR      (*(volatile unsigned int   *)0x50002434)
#define USB_FIFO2_ADDR      (*(volatile unsigned int   *)0x50002438)
#define USB_FIFO3_ADDR      (*(volatile unsigned int   *)0x5000243C)
#define USB_FIFO4_ADDR      (*(volatile unsigned int   *)0x50002440)
#define USB_FIFO5_ADDR      (*(volatile unsigned int   *)0x50002444)
#define USB_FIFO6_ADDR      (*(volatile unsigned int   *)0x50002448)
#define USB_FIFO7_ADDR      (*(volatile unsigned int   *)0x5000244C)
#define USB_FIFO8_ADDR      (*(volatile unsigned int   *)0x50002450)
#define USB_FIFO9_ADDR      (*(volatile unsigned int   *)0x50002454)
#define USB_FIFO10_ADDR     (*(volatile unsigned int   *)0x50002458)
#define USB_FIFO11_ADDR     (*(volatile unsigned int   *)0x5000245C)
#define USB_FIFO12_ADDR     (*(volatile unsigned int   *)0x50002460)
#define USB_FIFO13_ADDR     (*(volatile unsigned int   *)0x50002464)
#define USB_FIFO14_ADDR     (*(volatile unsigned int   *)0x50002468)
#define USB_FIFO15_ADDR     (*(volatile unsigned int   *)0x5000246C)



//SPI0
#define SPI0_CR1            (*(volatile unsigned int   *)0x50003000)
#define SPI0_CR2            (*(volatile unsigned int   *)0x50003004)
#define SPI0_CR3            (*(volatile unsigned int   *)0x50003008)
#define SPI0_SR             (*(volatile unsigned int   *)0x5000300C)
#define SPI0_IER            (*(volatile unsigned int   *)0x50003010)
#define SPI0_BR             (*(volatile unsigned int   *)0x50003014)
#define SPI0_DR             (*(volatile unsigned int   *)0x50003018)
#define SPI0_DYDR           (*(volatile unsigned int   *)0x5000301C)
#define SPI0_CRCINIT        (*(volatile unsigned int   *)0x50003020)
#define SPI0_CRCPR          (*(volatile unsigned int   *)0x50003024)
#define SPI0_TCRC           (*(volatile unsigned int   *)0x50003028)
#define SPI0_RCRC           (*(volatile unsigned int   *)0x5000302C)
#define SPI0_TXADDR         (*(volatile unsigned int   *)0x50003030)
#define SPI0_RXADDR         (*(volatile unsigned int   *)0x50003034)
#define SPI0_MAXLEN         (*(volatile unsigned int   *)0x50003038)
#define SPI0_VALIDLEN       (*(volatile unsigned int   *)0x5000303C)


//SPI1
#define SPI1_CR1            (*(volatile unsigned int   *)0x50004000)
#define SPI1_CR2            (*(volatile unsigned int   *)0x50004004)
#define SPI1_CR3            (*(volatile unsigned int   *)0x50004008)
#define SPI1_SR             (*(volatile unsigned int   *)0x5000400C)
#define SPI1_IER            (*(volatile unsigned int   *)0x50004010)
#define SPI1_BR             (*(volatile unsigned int   *)0x50004014)
#define SPI1_DR             (*(volatile unsigned int   *)0x50004018)
#define SPI1_DYDR           (*(volatile unsigned int   *)0x5000401C)
#define SPI1_CRCINIT        (*(volatile unsigned int   *)0x50004020)
#define SPI1_CRCPR          (*(volatile unsigned int   *)0x50004024)
#define SPI1_TCRC           (*(volatile unsigned int   *)0x50004028)
#define SPI1_RCRC           (*(volatile unsigned int   *)0x5000402C)
#define SPI1_TXADDR         (*(volatile unsigned int   *)0x50004030)
#define SPI1_RXADDR         (*(volatile unsigned int   *)0x50004034)
#define SPI1_MAXLEN         (*(volatile unsigned int   *)0x50004038)
#define SPI1_VALIDLEN       (*(volatile unsigned int   *)0x5000403C)


//USI0
#define USI0_CR             (*(volatile unsigned int   *)0x40009000)
#define USI0_IER            (*(volatile unsigned int   *)0x40009004)
#define USI0_SR             (*(volatile unsigned int   *)0x40009008)
#define USI0_BR             (*(volatile unsigned int   *)0x4000900C)
#define USI0_DR             (*(volatile unsigned int   *)0x40009010)
#define USI0_TR             (*(volatile unsigned int   *)0x40009014)
#define USI0_IR             (*(volatile unsigned int   *)0x40009018)


//USI1
#define USI1_CR             (*(volatile unsigned int   *)0x4000A000)
#define USI1_IER            (*(volatile unsigned int   *)0x4000A004)
#define USI1_SR             (*(volatile unsigned int   *)0x4000A008)
#define USI1_BR             (*(volatile unsigned int   *)0x4000A00C)
#define USI1_DR             (*(volatile unsigned int   *)0x4000A010)
#define USI1_TR             (*(volatile unsigned int   *)0x4000A014)
#define USI1_IR             (*(volatile unsigned int   *)0x4000A018)


//USI2
#define USI2_CR             (*(volatile unsigned int   *)0x4000B000)
#define USI2_IER            (*(volatile unsigned int   *)0x4000B004)
#define USI2_SR             (*(volatile unsigned int   *)0x4000B008)
#define USI2_BR             (*(volatile unsigned int   *)0x4000B00C)
#define USI2_DR             (*(volatile unsigned int   *)0x4000B010)
#define USI2_TR             (*(volatile unsigned int   *)0x4000B014)
#define USI2_IR             (*(volatile unsigned int   *)0x4000B018)


//SCI
#define SCI_ECR             (*(volatile unsigned int   *)0x4000D000)
#define SCI_CR1             (*(volatile unsigned int   *)0x4000D004)
#define SCI_CR2             (*(volatile unsigned int   *)0x4000D008)
#define SCI_CR3             (*(volatile unsigned int   *)0x4000D00C)
#define SCI_IER             (*(volatile unsigned int   *)0x4000D010)
#define SCI_SR              (*(volatile unsigned int   *)0x4000D014)
#define SCI_RCR             (*(volatile unsigned int   *)0x4000D018)
#define SCI_DR              (*(volatile unsigned int   *)0x4000D01C)
#define SCI_TCR             (*(volatile unsigned int   *)0x4000D020)
#define SCI_GTR             (*(volatile unsigned int   *)0x4000D024)
#define SCI_CWTR            (*(volatile unsigned int   *)0x4000D028)
#define SCI_BWTR            (*(volatile unsigned int   *)0x4000D02C)
#define SCI_RTR             (*(volatile unsigned int   *)0x4000D030)
#define SCI_SNDCR           (*(volatile unsigned int   *)0x4000D034)


//IIC
#define I2CI_CR1            (*(volatile unsigned int   *)0x4000C000)
#define I2CI_CR2            (*(volatile unsigned int   *)0x4000C004)
#define I2CI_SR             (*(volatile unsigned int   *)0x4000C008)
#define I2CI_IEN            (*(volatile unsigned int   *)0x4000C00C)
#define I2CI_BR             (*(volatile unsigned int   *)0x4000C010)
#define I2CI_DR             (*(volatile unsigned int   *)0x4000C014)
#define I2CI_ADDR1          (*(volatile unsigned int   *)0x4000C018)
#define I2CI_ADDR2          (*(volatile unsigned int   *)0x4000C01C)
#define I2CI_TOUTCR         (*(volatile unsigned int   *)0x4000C020)
#define I2CI_CRC_POLY       (*(volatile unsigned int   *)0x4000C024)
#define I2CI_CRC_INT        (*(volatile unsigned int   *)0x4000C028)
#define I2CI_CRC_SUM        (*(volatile unsigned int   *)0x4000C02C)



//EMMC
#define EMMCI_CCSR          (*(volatile unsigned int   *)0x50001000)
#define EMMCI_RTO_CNTR      (*(volatile unsigned int   *)0x50001004)
#define EMMCI_INDEXR        (*(volatile unsigned int   *)0x50001008)
#define EMMCI_ARGR1         (*(volatile unsigned int   *)0x5000100C)
#define EMMCI_ARGR2         (*(volatile unsigned int   *)0x50001010)
#define EMMCI_ARGR3         (*(volatile unsigned int   *)0x50001014)
#define EMMCI_ARGR4         (*(volatile unsigned int   *)0x50001018)
#define EMMCI_DATA_CR       (*(volatile unsigned int   *)0x5000101C)
#define EMMCI_BOOT_TOR      (*(volatile unsigned int   *)0x50001020)
#define EMMCI_DATA_TOR      (*(volatile unsigned int   *)0x50001024)
#define EMMCI_DATA_SR       (*(volatile unsigned int   *)0x50001028)
#define EMMCI_ADDR          (*(volatile unsigned int   *)0x5000102C)
#define EMMCI_BLENR         (*(volatile unsigned int   *)0x50001030)
#define EMMCI_BNUMR         (*(volatile unsigned int   *)0x50001034)
#define EMMCI_CLKCR         (*(volatile unsigned int   *)0x50001038)
#define EMMCI_IER           (*(volatile unsigned int   *)0x5000103C)
#define EMMCI_PADSR         (*(volatile unsigned int   *)0x50001040)
#define AUTOSTOP_CR         (*(volatile unsigned int   *)0x50001044)
#define SOFTRST_CR          (*(volatile unsigned int   *)0x50001048)

//GPCM
#define A_GPDR              (*(volatile unsigned int   *)0x40001000)
#define A_GPDDR             (*(volatile unsigned int   *)0x40001004)
#define A_GPCR              (*(volatile unsigned int   *)0x40001008)
#define A_EINTCR1           (*(volatile unsigned int   *)0x4000100C)
#define A_EINTCR2           (*(volatile unsigned int   *)0x40001010)
#define A_EINTER            (*(volatile unsigned int   *)0x40001014)
#define A_EINTSR            (*(volatile unsigned int   *)0x40001018)
#define B_GPDR              (*(volatile unsigned int   *)0x4000101C)
#define B_GPDDR             (*(volatile unsigned int   *)0x40001020)
#define B_GPCR              (*(volatile unsigned int   *)0x40001024)
#define B_EINTCR            (*(volatile unsigned int   *)0x40001028)
#define B_EINTER            (*(volatile unsigned int   *)0x4000102C)
#define B_EINTSR            (*(volatile unsigned int   *)0x40001030)

//MCGCR
#define EFM_CLKEN           0x80000000
#define CACHE_CLKEN         0x40000000
#define DMAC_CLKEN          0x20000000
#define CRC_CLKEN           0x10000000
#define TIMER2_CLKEN        0x08000000
#define TIMER1_CLKEN        0x04000000
#define TIMER0_CLKEN        0x02000000
#define WDT_CLKEN           0x01000000
#define PWM2_CLKEN          0x00200000
#define PWM1_CLKEN          0x00100000
#define EMMC_CLKEN          0x00040000
#define USBI_CLKEN          0x00020000
#define SPI1_CLKEN          0x00010000
#define SPI0_CLKEN          0x00008000
#define PAD_CLKEN           0x00004000
#define GPCM_CLKEN          0x00002000
#define USI2_CLKEN          0x00001000
#define USI1_CLKEN          0x00000800
#define USI0_CLKEN          0x00000400
#define SCI_CLKEN           0x00000200
#define I2CI_CLKEN          0x00000100
#define BEAE_CLKEN          0x00000080
#define FPAE_CLKEN          0x00000020
#define RNG_CLKEN           0x00000008
#define BCAE_CLKEN          0x00000004
#define SHAE_CLKEN          0x00000002
#define REAE_CLKEN          0x00000001

#endif
