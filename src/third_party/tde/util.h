#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include "windows_shim.h"
#endif

#define OK    1
#define ERROR 0

struct itimerval timer;
time_t last_stat_time;                    /* The last time when statistics are printed */
unsigned long long total_initialized;     /* Total initialization calls, for debug */
unsigned long long total_finalized;       /* Total finalzation calls, for debug */
unsigned long long total_encrypted;       /* Total encryption function calls */
unsigned long long total_decrypted;       /* Total decryption function calls */
unsigned long long total_encrypted_below_key_size; /* Total encryption function calls with below KEY_SIZE data length */
unsigned long long total_encryption_overhead;      /* Total encryption overhead size */
unsigned long long total_encrypted_bytes; /* Total encrypted data bytes */
unsigned long long total_decrypted_bytes; /* Total decrypted data bytes */
unsigned long long total_encryption_failed;
unsigned long long total_decryption_failed;

void print_encryption_log(char* log_file, char* message);
void print_encryption_stats(char* log_file);
void set_data_length(uint8_t* data, uint32_t data_size);
uint32_t get_data_length(uint8_t* data);
void hex_print(const void* pv, size_t len);
int convert_hex_to_unsignedchar(const char* hex, unsigned char* dst, int dst_len);
