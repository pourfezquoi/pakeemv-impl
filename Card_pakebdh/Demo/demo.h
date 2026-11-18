#ifndef _DEMO_H_
#define _DEMO_H_

#include <stdint.h>
#include <string.h>

#include "HSCTU_Registers.h"
#include "pad_Init_v104.h"
#include "clockset_v101.h"
#include "flash_v103.h"

// ------ SCard ------
#include "sci.h"

// ================= APDU field offsets =================
#define APDU_CLA   0
#define APDU_INS   1
#define APDU_P1    2
#define APDU_P2    3
#define APDU_LC    4

// ================= CLA values =================
#define CLA_ISO7816    0x00
#define CLA_PPS       0xFF
#define CLA_VENDOR    0x80
#define CLA_TEST      0xC0

// ================= Instruction values =================
#define INS_VERIFY_PIN      0x20  // Transmit the PIN encrypted under K [cite: 5]
#define INS_ESTABLISH_KEY   0x50  // Receive terminal ciphertext and establish the final key K [cite: 3]
#define INS_GET_CHALLENGE   0x84  // Read a card challenge [cite: 4]
#define INS_GENERATE_AC     0xAE  // Complete a transaction and return authentication data derived from K [cite: 6]
#define INS_READ_BINARY     0xB0
#define INS_READ_CERTS      0xB2  // Read card identity encrypted under K_1 [cite: 2]
#define INS_UPDATE_BINARY   0xD6
#define INS_LONG_TASK       0xDD
#define INS_KEM_ENCAP       0xCA
#define INS_PAKE_INIT       0xC1
#define INS_PAKE_RESP       0xC2
#define INS_PING            0xF0
#define INS_TRACE_LAST_CMD  0xF1
#define INS_ECHO            0xF2
#define INS_KEY_PROOF       0xF3  // Disabled: raw PAKE keys must not be exported
#define INS_KEY_PROOF_K2    0xF4  // Disabled: final confirmation is M6, without an extra proof APDU
#define INS_SS2_PROOF       0xF5  // Disabled: internal KEM secrets must not be exported
#define INS_GET_TIMING      0xF6  // Return legacy totals: T->C, C->T, CardProc, reserved
#define INS_GET_PROFILE     0xF8  // Read the public protocol profile and compiled capabilities
#define INS_BEGIN_TRANSACTION 0xF9 // Local activation outside the six protocol messages

// ================= Status-word values =================
#define SW1_SUCCESS         0x90

#define SW1_WRONG_LENGTH    0x6C
#define SW1_WRONG_LC        0x67
#define SW1_INS_NOT_SUP     0x6D
#define SW1_CLA_NOT_SUP         0x6E  // 6E00: class not supported
#define SW1_WRONG_P1P2          0x6B  // 6B00: incorrect P1/P2 parameters
#define SW1_CHECK_ERR           0x6A  // 6Axx: parameter or data validation error
#define SW2_FILE_NOT_FOUND      0x82  // 6A82: file or application not found
#define SW2_RECORD_NOT_FOUND    0x83  // 6A83: record not found
#define SW2_INCORRECT_P1P2      0x86  // 6A86: incorrect P1/P2 parameters
#define SW2_DATA_NOT_FOUND      0x88  // 6A88: referenced data not found

// --- 2. Security/permission errors for PIN and cryptographic checks ---
#define SW1_SECURITY_ERR        0x69  // 69xx: command not allowed
#define SW2_SEC_NOT_SATISFIED   0x82  // 6982: security condition not satisfied, such as a transaction before PIN verification
#define SW2_AUTH_BLOCKED        0x83  // 6983: authentication method blocked, such as a blocked PIN
#define SW2_COND_NOT_SATISFIED  0x85  // 6985: conditions of use not satisfied

// --- 3. Warnings and state changes for PIN retries or decryption failures ---
#define SW1_WARNING             0x63  // 63xx: warning

//testing
#define SW1_TESTING 0x99 //for testing

#define SW2_AUTH_FAILED         0x00  // 6300: authentication/decryption failure, including ciphertext or MAC tampering
// An incorrect PIN normally returns 63CX, where X is retries remaining; 63C2 means two retries.
#define SW2_PIN_RETRY_BASE      0xC0  // Combine as sw[1] = SW2_PIN_RETRY_BASE | retries_left.

// --- 4. Internal/fatal card errors ---
#define SW1_INTERNAL_ERR        0x6F  // 6Fxx: internal error without a precise diagnosis
#define SW2_EEPROM_FAIL         0x81  // 6581 or 6F81: memory/EEPROM write failure

#define SW2_00              0x00
// 69 82: security condition not satisfied or prerequisite authentication missing
#define SW1_SEC_STATUS_NOT_SATISFIED 0x69
#define SW2_SEC_STATUS_NOT_SATISFIED 0x82 // Use this value with 0x69 instead of SW2_00.

// 63 C0: PIN blocked; no retries remain
#define SW2_PIN_BLOCKED              0xC0

#define CERT_ADDR           0x10
#define CERT_LEN            0x10
#define SKC_ADDR            0x10
#define SKC_LEN             KYBER_SECRETKEYBYTES
#define MAX_BUFF_LEN        8192
#define NONCE_LEN           0x10
#define PIN_LEN             0x06
#define MK_AC_ADDR          0x10
#define MK_AC_LEN           0x10
// Main entry point
void SCard_Demo(void);

#endif
