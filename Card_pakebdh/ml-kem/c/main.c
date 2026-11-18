#include "HSCTU_Registers.h"
#include "clockset_v101.h"
#include "flash_v103.h"
#include "gpio.h"
#include "stdint.h"
#include "kem.h"
#include "params.h"
#include <stdlib.h>
#include "systick.h"
int main(void){
	unsigned int i;
	uint8_t sk [KYBER_SECRETKEYBYTES];
  uint8_t pk [KYBER_PUBLICKEYBYTES];
  uint8_t ct [KYBER_CIPHERTEXTBYTES];
  uint8_t ss [KYBER_SSBYTES];
  uint8_t ss1 [KYBER_SSBYTES];
	set_clk_alg140_em105_sys105();
	Flash_Setting(SYSTEM_CLOCK_105MHZ);
	systick_int_init();
	enable_systick();
  crypto_kem_keypair(pk, sk);
  crypto_kem_enc(ct, ss, pk);
  crypto_kem_dec(ss1, ct, sk);
  free(sk);
  free(pk);
  free(ct);
  free(ss);
	free(ss1);
	gpio_init(14, 1);
	while(1){
		gpio_out(14, 0);
		for(i = 0;i<1000000;i++);
		gpio_out(14, 1);
		for(i = 0;i<1000000;i++);
	}
}