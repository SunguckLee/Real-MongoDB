#include "util.h"

extern int   STATS_REPORT_INTERVAL;



void set_data_length(uint8_t* data, uint32_t data_size){
  data[0] = (data_size >> 24) & 0xFF;
  data[1] = (data_size >> 16) & 0xFF;
  data[2] = (data_size >> 8) & 0xFF;
  data[3] = data_size & 0xFF;
}

uint32_t get_data_length(uint8_t* data){
  uint32_t data_size = (uint32_t)data[0] << 24 |
      (uint32_t)data[1] << 16 |
      (uint32_t)data[2] << 8  |
      (uint32_t)data[3];

  return data_size;
}

void hex_print(const void* pv, size_t len){
  const unsigned char * p = (const unsigned char*)pv;
  if (NULL == pv){
    printf("NULL");
  }else{
    size_t i = 0;
    for (; i<len;++i){
      printf("%02X ", *p++);
    }
  }
}


/**
 * return OK on success, otherwise return ERROR
 */
int convert_hex_to_unsignedchar(const char* hex, unsigned char* dst, int dst_len){
  char* src = hex;
  unsigned char *end = dst + dst_len;
  unsigned int u;

  if(src==NULL || strlen(src)!=(dst_len*2)){
    return ERROR;
  }

  while (dst < end && sscanf(src, "%2x", &u) == 1){
    *dst++ = u;
    src += 2;
  }

  return OK;
}

void print_encryption_stats(char* log_file){
  FILE* file;
  char buffer[100];
  time_t now = time(NULL);
  int elapsed_secs = now - last_stat_time;

  if(elapsed_secs < 60){
    return; /* Ignore if last printing is recent */
  }

  file = fopen(log_file, "a");
  if(file == NULL){
    return; /* Just ignore */
  }

  unsigned long long initialized = total_initialized             ;
  unsigned long long finalized = total_finalized                 ; total_finalized = 0;
  unsigned long long encrypted = total_encrypted                 ; total_encrypted = 0;
  unsigned long long decrypted = total_decrypted                 ; total_decrypted = 0;
  unsigned long long encrypted_below_key_size = total_encrypted_below_key_size; total_encrypted_below_key_size = 0;
  unsigned long long encryption_overhead = total_encryption_overhead          ; total_encryption_overhead= 0;
  unsigned long long encrypted_bytes = total_encrypted_bytes     ; total_encrypted_bytes = 0;
  unsigned long long decrypted_bytes = total_decrypted_bytes     ; total_decrypted_bytes = 0;
  unsigned long long encryption_failed = total_encryption_failed ;
  unsigned long long decryption_failed = total_decryption_failed ;
  last_stat_time = now;

  strftime(buffer, 90, "%Y-%m-%d %l:%M:%S", localtime(&now));
  fprintf(file, "%s init(%llu), fin(%llu), enc(%llu/s), dec(%llu/s), enc_bytes(%llu/enc), dec_bytes(%llu/dec), enc_below_key_size(%llu/s), overhead(%llu/enc),  enc_fail(%llu), dec_fail(%llu)\n",
    buffer,
    initialized,
    finalized,
    encrypted / elapsed_secs,
    decrypted / elapsed_secs,
    (encrypted>0) ? (encrypted_bytes / encrypted) : 0,
    (decrypted>0) ? (decrypted_bytes / decrypted) : 0,
    encrypted_below_key_size / elapsed_secs,
    (encrypted>0) ? (encryption_overhead / encrypted) : 0,
    encryption_failed,
    decryption_failed);

  fclose(file);
}

void print_encryption_log(char* log_file, char* message){
  char buffer[100];
  time_t tm_time;
  FILE* file = fopen(log_file, "a");
  if(file == NULL){
    return; /* Just ignore */
  }

  tm_time = time(NULL);
  strftime(buffer, 90, "%Y-%m-%d %l:%M:%S", localtime(&tm_time));
  fprintf(file, "%s %s\n", buffer, message);

  fclose(file);
}


