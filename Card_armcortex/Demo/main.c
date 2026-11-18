/***************************************************************
*
* Copyright (c) 2021, HSEC : 2021/4/26
* All rights reserved.
*
**************************************************************/

#include "demo.h"

/**
 * Configure the system clock parameter for the actual operating conditions
 * Use this global variable to quickly adjust the frequencies of certain communication interfaces
 */
uint32_t SystemCoreClock = 105000000;

int main(void)
{
    set_clk_alg140_em105_sys105();

    Flash_Setting(SYSTEM_CLOCK_105MHZ);

    SCard_Demo();

    while(1)
    {
        ;
    }
}
