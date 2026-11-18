
//HSCTU clock configuration library header
	
//Clock configuration 1: recommended for eMMC applications
//Algorithm clock: 120 MHz
//Interface (eMMC) clock: 96 MHz
//System clock: 120 MHz
//Use the internal oscillator as the clock source
void set_clk_alg120_em96_sys120(void);


//Clock configuration 2: recommended for general applications
//Algorithm clock: 140 MHz
////Communication (eMMC) clock: 105 MHz
//System clock: 105 MHz
//Use the internal oscillator as the clock source
void set_clk_alg140_em105_sys105(void);

//Contact technical support for other requirements




