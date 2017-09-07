#include <ctype.h>

#ifndef _UNIT_TEST_
#include <wiredtiger.h>
#include <wiredtiger_ext.h>
#endif


//void register_stats_report_timer();
//void unregister_stats_report_timer();
void handle_evp_errors(void);
int tde_encrypt1(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int tde_decrypt1(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
