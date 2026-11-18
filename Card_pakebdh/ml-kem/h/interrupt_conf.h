#ifndef	__INTERRUPT_CONF_H__
#define __INTERRUPT_CONF_H__

#define		NVIC_IPRx_BASE		(&NVIC_IPR0)
typedef enum IRQn
{
/******  SC300 Processor Exceptions Numbers ****************************************************/
  NonMaskableInt_IRQn           = -14,    /*!<  2 SC300 Non Maskable Interrupt                 */
  HardFault_IRQn                = -13,    /*!<  3 SC300 Hard Fault Interrupt                   */
  MemoryManagement_IRQn         = -12,    /*!<  4 SC300 Memory Management Interrupt            */
  BusFault_IRQn                 = -11,    /*!<  5 SC300 Bus Fault Interrupt                    */
  UsageFault_IRQn               = -10,    /*!<  6 SC300 Usage Fault Interrupt                  */
  SVCall_IRQn                   = -5,     /*!< 11 SC300 SV Call Interrupt                      */
  DebugMonitor_IRQn             = -4,     /*!< 12 SC300 Debug Monitor Interrupt                */
  PendSV_IRQn                   = -2,     /*!< 14 SC300 Pend SV Interrupt                      */
  SysTick_IRQn                  = -1,     /*!< 15 SC300 System Tick Interrupt                  */

/******  CMSDK Specific Interrupt Numbers *********************************************************/
  WDT_IRQn                      = 0,       
  GPIOA_IRQn                    = 1,      
  GPIOB_IRQn                    = 2,       
  USBI_IRQn                     = 3,       
  TIMER0_IRQn                   = 4,       
  TIMER1_IRQn                   = 5,       
  TIMER2_IRQn                   = 6,       
  DMAC_IRQn                     = 7,       
  I2CI_IRQn                     = 8,                                              
  SPI0_IRQn                     = 9,      
  SPI1_IRQn                     = 10,      
  EMMCI_IRQn                    = 11,      
  PWM1_IRQn                     = 14,      
  PWM2_IRQn                     = 15,     
  USI0_IRQn                     = 16,
  USI1_IRQn                     = 17,
  USI2_IRQn                     = 18,
  SCI_IRQn                      = 19,
  REAE_IRQn                     = 20,
  BEAE_IRQn                     = 21,
  FPAE_IRQn                     = 22,
  BCAE_IRQn                     = 23,
  SHAE_IRQn                     = 24,
  RNG_IRQn                      = 25,
  SCM_TD                      	= 26,
  SCM_VD                        = 27,
  SCM_SD                        = 28,
  WAKEUP0                     	= 29,
  WAKEUP1                     	= 30
  
} IRQn_Type;


//Interrupt priority selection: lower values indicate higher priority
typedef enum NVIC_PRIORITY
{
	NVIC_PRIORITY_0					= 0,       
	NVIC_PRIORITY_1					= 1,       
	NVIC_PRIORITY_2					= 2,      
	NVIC_PRIORITY_3					= 3

} NVIC_PRIORITY_Type;

#define   __IO    volatile 
#define   __I     volatile    const

#define __CM0_REV                 0x0000    /*!< Core Revision r0p0                               */
#define __NVIC_PRIO_BITS          2         /*!< Number of Bits used for Priority Levels          */
#define __Vendor_SysTickConfig    0         /*!< Set to 1 if different SysTick Config is used     */
#define __MPU_PRESENT             0         /*!< MPU present or not  */


#define _BIT_SHIFT(IRQn)         (  (((unsigned int)(IRQn)       )    &  0x03) * 8 )
#define _SHP_IDX(IRQn)           ( ((((unsigned int)(IRQn) & 0x0F)-8) >>    2)     )
#define _IP_IDX(IRQn)            (   ((unsigned int)(IRQn)            >>    2)     )


typedef struct
{
  __IO unsigned int ISER[1];                 /*!< Offset: 0x000 (R/W)  Interrupt Set Enable Register           */
       unsigned int RESERVED0[31];
  __IO unsigned int ICER[1];                 /*!< Offset: 0x080 (R/W)  Interrupt Clear Enable Register          */
       unsigned int RSERVED1[31];
  __IO unsigned int ISPR[1];                 /*!< Offset: 0x100 (R/W)  Interrupt Set Pending Register           */
       unsigned int RESERVED2[31];
  __IO unsigned int ICPR[1];                 /*!< Offset: 0x180 (R/W)  Interrupt Clear Pending Register         */
       unsigned int RESERVED3[31];
       unsigned int RESERVED4[64];
  __IO unsigned int IP[8];                   /*!< Offset: 0x300 (R/W)  Interrupt Priority Register              */
}  NVIC_Type;


typedef struct
{
  __I  unsigned int CPUID;                   /*!< Offset: 0x000 (R/ )  CPUID Base Register                                   */
  __IO unsigned int ICSR;                    /*!< Offset: 0x004 (R/W)  Interrupt Control and State Register                  */
 __IO unsigned int VTOR;
  __IO unsigned int AIRCR;                   /*!< Offset: 0x00C (R/W)  Application Interrupt and Reset Control Register      */
  __IO unsigned int SCR;                     /*!< Offset: 0x010 (R/W)  System Control Register                               */
  __IO unsigned int CCR;                     /*!< Offset: 0x014 (R/W)  Configuration Control Register                        */
       unsigned int RESERVED1;
  __IO unsigned int SHP[2];                  /*!< Offset: 0x01C (R/W)  System Handlers Priority Registers. [0] is RESERVED   */
  __IO unsigned int SHCSR;                   /*!< Offset: 0x024 (R/W)  System Handler Control and State Register             */
} SCB_Type;

/* Memory mapping of Cortex-M0 Hardware */
#define SCS_BASE            (0xE000E000UL)                            /*!< System Control Space Base Address */
#define SysTick_BASE        (SCS_BASE +  0x0010UL)                    /*!< SysTick Base Address              */
#define NVIC_BASE           (SCS_BASE +  0x0100UL)                    /*!< NVIC Base Address                 */
#define SCB_BASE            (SCS_BASE +  0x0D00UL)                    /*!< System Control Block Base Address */

#define SCB                 ((SCB_Type       *)     SCB_BASE      )   /*!< SCB configuration struct           */
#define SysTick             ((SysTick_Type   *)     SysTick_BASE  )   /*!< SysTick configuration struct       */
#define NVIC                ((NVIC_Type      *)     NVIC_BASE     )   /*!< NVIC configuration struct          */


 #define __STATIC_INLINE  static __inline



__STATIC_INLINE void NVIC_EnableIRQ(IRQn_Type IRQn)
{
  NVIC->ISER[0] = (1 << ((unsigned int)(IRQn) & 0x1F));
}


__STATIC_INLINE void NVIC_DisableIRQ(IRQn_Type IRQn)
{
  NVIC->ICER[0] = (1 << ((unsigned int)(IRQn) & 0x1F));
}



__STATIC_INLINE unsigned int NVIC_GetPendingIRQ(IRQn_Type IRQn)
{
  return((unsigned int) ((NVIC->ISPR[0] & (1 << ((unsigned int)(IRQn) & 0x1F)))?1:0));
}



__STATIC_INLINE void NVIC_SetPendingIRQ(IRQn_Type IRQn)
{
  NVIC->ISPR[0] = (1 << ((unsigned int)(IRQn) & 0x1F));
}



__STATIC_INLINE void NVIC_ClearPendingIRQ(IRQn_Type IRQn)
{
  NVIC->ICPR[0] = (1 << ((unsigned int)(IRQn) & 0x1F)); /* Clear pending interrupt */
}


__STATIC_INLINE void NVIC_SetPriority(IRQn_Type IRQn, unsigned int priority)
{
  if(IRQn < 0) {
    SCB->SHP[_SHP_IDX(IRQn)] = (SCB->SHP[_SHP_IDX(IRQn)] & ~(0xFF << _BIT_SHIFT(IRQn))) |
        (((priority << (8 - __NVIC_PRIO_BITS)) & 0xFF) << _BIT_SHIFT(IRQn)); }
  else {
    NVIC->IP[_IP_IDX(IRQn)] = (NVIC->IP[_IP_IDX(IRQn)] & ~(0xFF << _BIT_SHIFT(IRQn))) |
        (((priority << (8 - __NVIC_PRIO_BITS)) & 0xFF) << _BIT_SHIFT(IRQn)); }
}



__STATIC_INLINE unsigned int NVIC_GetPriority(IRQn_Type IRQn)
{

  if(IRQn < 0) {
    return((unsigned int)(((SCB->SHP[_SHP_IDX(IRQn)] >> _BIT_SHIFT(IRQn) ) & 0xFF) >> (8 - __NVIC_PRIO_BITS)));  } /* get priority for Cortex-M0 system interrupts */
  else {
    return((unsigned int)(((NVIC->IP[ _IP_IDX(IRQn)] >> _BIT_SHIFT(IRQn) ) & 0xFF) >> (8 - __NVIC_PRIO_BITS)));  } /* get priority for device specific interrupts  */
}





#endif