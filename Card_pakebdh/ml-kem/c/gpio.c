#include "HSCTU_Registers.h"
#include "gpio.h"
#include "interrupt_conf.h"
#include "pad_Init_v104.h"


/*****************General-purpose GPIO configuration functions******************/
//GPIO values 0-36 correspond to GP0-GP36, respectively
//Dir specifies the GPIO direction
void gpio_init(U8 GPIO, U8 Dir)
{
    T_U32 *p_GPCMDR_TMP = (T_U32 *)(&A_GPDR);
    T_U32 *p_GPCMDDR_TMP = (T_U32 *)(&A_GPDDR);
    T_U32 *p_GPCMCR_TMP = (T_U32 *)(&A_GPCR);

    MCGCR |= GPCM_CLKEN;//Enable the GPIO clock
    *(p_GPCMDR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32); //Initialize the default output level to high


    GPIO_Pad_Init(GPIO, 1, 1, 1);

    if(Dir)
    {
        *(p_GPCMDDR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32); //Set the direction to output
    }
    else
    {
        *(p_GPCMDDR_TMP + GPIO / 32 * 7) &= ~(1UL << (GPIO % 32)); //Set the direction to input
    }

    *(p_GPCMCR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32); //Enable GPIO functionality
}



//GPIO values 0-36 correspond to GP0-GP36, respectively
//value: 0 drives low, 1 drives high, 2 toggles the output; other values are invalid
void gpio_out(U8 GPIO, U8 value)
{
    T_U32 *p_GPCMDR_TMP = (T_U32 *)(&A_GPDR);

    if(1 == value)
        *(p_GPCMDR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32);
    else if(0 == value)
        *(p_GPCMDR_TMP + GPIO / 32 * 7) &= ~(1UL << (GPIO % 32));
    else if(2 == value)
        *(p_GPCMDR_TMP + GPIO / 32 * 7) ^= 1UL << (GPIO % 32);
    else {}
}



//GPIO values 0-36 correspond to GP0-GP36, respectively
unsigned char gpio_get(U8 GPIO)
{
    T_U32 *p_GPCMDR_TMP = (T_U32 *)(&A_GPDR);

    if((*(p_GPCMDR_TMP + GPIO / 32 * 7)) & (1UL << (GPIO % 32)))
        return 1;
    else
        return 0;
}



//GPIO accepts values 0-36
//mode: accepts values 0-3; see gpio.h
//Configure the interrupt mode
void gpio_intrrupt_mode_set(U8 GPIO, U8 mode)
{
    T_U32 *p_EINTCR_TMP = (T_U32 *)(&A_EINTCR1);

    MCGCR |= GPCM_CLKEN;
    if(GPIO < 32)
    {
        *(p_EINTCR_TMP + GPIO / 16) &= ~(3UL << ((GPIO % 16) << 1UL));
        *(p_EINTCR_TMP + GPIO / 16) |= mode << ((GPIO % 16) << 1UL);
    }
    else
    {
        GPIO -= 32;//This statement may be omitted
        p_EINTCR_TMP += 7;
        *(p_EINTCR_TMP) &= ~(3UL << ((GPIO % 16) << 1UL));
        *(p_EINTCR_TMP) |= mode << ((GPIO % 16) << 1UL);
    }
}



//GPIO accepts values 0-36
//Enable interrupts
void gpio_intrrupt_enable(U8 GPIO)
{
    T_U32 *p_EINTER_TMP = (T_U32 *)(&A_EINTER);

    MCGCR |= GPCM_CLKEN;
    *(p_EINTER_TMP + GPIO / 32 * 6) |= 1UL << (GPIO % 32);
}


//GPIO accepts values 0-36
//Disable interrupts
void gpio_intrrupt_disable(U8 GPIO)
{
    T_U32 *p_EINTER_TMP = (T_U32 *)(&A_EINTER);

    MCGCR |= GPCM_CLKEN;
    *(p_EINTER_TMP + GPIO / 32 * 6) &= ~(1UL << (GPIO % 32));
}


//GPIO accepts values 0-36
//Check whether an interrupt has occurred
//Returns 1 if the interrupt flag is set
unsigned char  gpio_intrrupt_state_detec(U8 GPIO)
{
    T_U32 *p_EINTSR_TMP = (T_U32 *)(&A_EINTSR);

    MCGCR |= GPCM_CLKEN;
    return ((*(p_EINTSR_TMP + GPIO / 32 * 6) & (1UL << (GPIO % 32))) ? 1 : 0); //Check whether the interrupt flag is set
}



//GPIO accepts values 0-36
//Clear the interrupt status
void gpio_intrrupt_state_clear(U8 GPIO)
{
    T_U32 *p_EINTSR_TMP = (T_U32 *)(&A_EINTSR);

    if(*(p_EINTSR_TMP + GPIO / 32 * 6) & (1UL << (GPIO % 32))) //Clear the interrupt flag only after confirming that it is set
    {
        *(p_EINTSR_TMP + GPIO / 32 * 6) = (1UL << (GPIO % 32));
				while(*(p_EINTSR_TMP + GPIO / 32 * 6) & (1UL << (GPIO % 32)));
    }
}


//GPIO accepts values 0-36
//Dir specifies the GPIO direction: 0 for input, any other value for output
void gpio_init_Lint(U8 GPIO, U8 Dir)//
{
    T_U32 *p_GPCMDR_TMP = (T_U32 *)(&A_GPDR);
    T_U32 *p_GPCMDDR_TMP = (T_U32 *)(&A_GPDDR);

    MCGCR |= GPCM_CLKEN;//Enable the GPIO clock
    *(p_GPCMDR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32); //Initialize the default output level to high


    GPIO_Pad_Init(GPIO, 1, 1, 1);

    if(Dir)
    {
        *(p_GPCMDDR_TMP + GPIO / 32 * 7) |= 1UL << (GPIO % 32); //Set the direction to output
    }
    else
    {
        *(p_GPCMDDR_TMP + GPIO / 32 * 7) &= ~(1UL << (GPIO % 32)); //Set the direction to input
    }

}

//value: 0 selects the low-speed bus clock for external interrupts; other values select the internal 32 kHz oscillator
void gpio_int_clksel(U8 value)
{
    if(value)
        CNTCR |= 0x00000040;
    else
        CNTCR &= ~0x00000040;
}

//Initialize the GPx interrupt
//GPIO accepts values 0-23
//intrrupt_mode: interrupt mode, such as falling-edge or rising-edge triggering; see gpio.h
//priority: interrupt priority; see interrupt_conf.h
void gpio_int_init(U8 GPIO, U8 intrrupt_mode, NVIC_PRIORITY_Type priority)
{
    IRQn_Type gpio_irq;

    if(GPIO < 32)
    {
        gpio_irq =  GPIOA_IRQn;
    }
    else if(GPIO <= 36)
    {
        gpio_irq =  GPIOB_IRQn;
    }
    else return;

    gpio_int_clksel(0);
    //gpio_init(GPIO, 0);
    gpio_init_Lint(GPIO, 0);
    gpio_intrrupt_mode_set(GPIO, intrrupt_mode);//
    NVIC_SetPriority(gpio_irq, priority);  //Set the priority
    NVIC_ClearPendingIRQ(gpio_irq);   //Clear the pending interrupt
    NVIC_EnableIRQ(gpio_irq);         //Enable interrupts
    gpio_intrrupt_state_clear(GPIO);//Clear any previously set interrupt flag
    gpio_intrrupt_enable(GPIO);//Enable interrupts
}



/**********************************************************/



