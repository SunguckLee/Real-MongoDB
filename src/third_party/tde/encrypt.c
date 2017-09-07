#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "ini.h"
#include "util.h"
#include "encrypt.h"

#ifdef _WIN32
/*
 *  Explicitly export this function so it is visible when loading extensions.
 */
__declspec(dllexport)
#endif


#define     WIREDTIGER_EXT_ERROR  1
#define     WIREDTIGER_EXT_OK     0

#define     INI_HANDLER_ERROR      0
#define     INI_HANDLER_OK         1



#define     KEY_SIZE         16
#define     STATS_REPORT_INTERVAL 10*60 /* 10 minutes */


typedef struct {
#ifndef _UNIT_TEST_
  WT_ENCRYPTOR encryptor; /* Must come first */
#endif

  unsigned char* encrypt_key;
  unsigned char* init_vector;
} TDE_CRYPTO;

char* encrypt_log;



#ifndef _UNIT_TEST_
int register_tde_encryptors(WT_CONNECTION *connection);
int read_encrypt_config(char* path, TDE_CRYPTO* config);
#endif



void handle_evp_errors(){
  if(encrypt_log==NULL){
    return;
  }

  FILE* file = fopen(encrypt_log, "a");
  if(file == NULL){
    return; /* Just ignore */
  }

  ERR_print_errors_fp(file);
  fclose(file);

  abort();
}

//void register_stats_report_timer(){
//  struct sigaction sa;
//
//  /* Install timer_handler as the signal handler for SIGVTALRM. */
//  memset(&sa, 0, sizeof (sa));
//  sa.sa_handler = &print_encryption_stats;
//  // sigaction(SIGVTALRM, &sa, NULL);
//  sigaction(SIGALRM, &sa, NULL);
//
//  /* Configure the initial(only for the first time) timer */
//  timer.it_value.tv_sec = STATS_REPORT_INTERVAL;
//  timer.it_value.tv_usec = 0;
//
//  /* Configure the next(after first time) timer */
//  timer.it_interval.tv_sec = STATS_REPORT_INTERVAL;
//  timer.it_interval.tv_usec = 0;
//
//  /* Start a virtual timer. It counts down whenever this process is executing. */
//  // setitimer (ITIMER_VIRTUAL, &timer, NULL);
//  setitimer (ITIMER_REAL, &timer, NULL);
//}
//
//void unregister_stats_report_timer(){
//  /* Configure the initial(only for the first time) timer */
//  timer.it_value.tv_sec = 0;
//  timer.it_value.tv_usec = 0;
//
//  /* Configure the next(after first time) timer */
//  timer.it_interval.tv_sec = 0;
//  timer.it_interval.tv_usec = 0;
//
//  /* Start a virtual timer. It counts down whenever this process is executing. */
//  // setitimer (ITIMER_VIRTUAL, &timer, NULL);
//  setitimer (ITIMER_REAL, &timer, NULL);
//}






int
tde_encrypt1(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_evp_errors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handle_evp_errors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handle_evp_errors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_evp_errors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int
tde_decrypt1(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handle_evp_errors();

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handle_evp_errors();

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handle_evp_errors();
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_evp_errors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}






#ifndef _UNIT_TEST_
/*
 * tde_encrypt --
 */
static int
tde_encrypt(WT_ENCRYPTOR *encryptor, WT_SESSION *session, uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len, size_t *result_lenp){
  int encrypted_len;
  int max_encrypted_len = (src_len/KEY_SIZE + 1) * KEY_SIZE;
  TDE_CRYPTO *crypto = (TDE_CRYPTO *)encryptor;

  total_encrypted++;
  total_encrypted_bytes += src_len;

  if(dst_len < max_encrypted_len){
    total_encryption_failed++;
    print_encryption_log(encrypt_log, "Encryption buffer length must be greater than `(plain_text_length/KEY_SIZE + 1) * KEY_SIZE`. Aborting");
    // return (ENOMEM);
    return WIREDTIGER_EXT_ERROR;
  }

  encrypted_len = tde_encrypt1(src/*plain*/, src_len/*plain_len*/, crypto->encrypt_key, crypto->init_vector, dst/*encrypted*/);
  *result_lenp = encrypted_len;

  if(src_len < KEY_SIZE){
    total_encrypted_below_key_size++;
  }
  total_encryption_overhead += (encrypted_len - src_len);

  return WIREDTIGER_EXT_OK;
}

/*
 * tde_decrypt --
 */
static int
tde_decrypt(WT_ENCRYPTOR *encryptor, WT_SESSION *session, uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len, size_t *result_lenp){
  int decrypted_len;
  TDE_CRYPTO *crypto = (TDE_CRYPTO *)encryptor;

  total_decrypted++;
  total_decrypted_bytes += src_len;

  if(src_len<KEY_SIZE){
    total_decryption_failed++;
    print_encryption_log(encrypt_log, "Encrypted data length must be greater or equal than KEY_SIZE. Aborting");
    return WIREDTIGER_EXT_ERROR; /* Not encrypted data */
  }
  if(dst_len < src_len - KEY_SIZE){
    total_decryption_failed++;
    print_encryption_log(encrypt_log, "Decryption buffer length must be greater than encrypted data length - KEY_SIZE. Aborting");
    //return (ENOMEM);
    return WIREDTIGER_EXT_ERROR;
  }

  decrypted_len = tde_decrypt1(src/*encrypted*/, src_len/*encrypted_len*/, crypto->encrypt_key, crypto->init_vector, dst/*decrypted*/);
  *result_lenp = decrypted_len;

  return WIREDTIGER_EXT_OK;
}

/*
 * encryption_overhead_size --
 *      A sizing that returns the header size needed.
 */
static int
encryption_overhead_size(WT_ENCRYPTOR *encryptor, WT_SESSION *session, size_t *expansion_constantp){
  *expansion_constantp = KEY_SIZE;
  return WIREDTIGER_EXT_OK;
}

/*
 * encryption_initialize --
 *      initializing TDE encryption
 */
static int
encryption_initialize(WT_ENCRYPTOR *encryptor, WT_SESSION *session, WT_CONFIG_ARG *encrypt_config, WT_ENCRYPTOR **customp){
  TDE_CRYPTO *crypto;
  WT_EXTENSION_API *extapi;
  const TDE_CRYPTO *orig_crypto;
  WT_CONFIG_ITEM keyid;
  char enc_config_path[512];
  int ret;

  total_initialized++;
  extapi = session->connection->get_extension_api(session->connection);

  orig_crypto = (const TDE_CRYPTO *)encryptor;
  if ((crypto = calloc(1, sizeof(TDE_CRYPTO))) == NULL) {
    // print_encryption_log("Can not allocate TDE_CRYPTO structure. Aborting");
    ret = errno;
    goto err;
  }

  *crypto = *orig_crypto;

  if ((ret = extapi->config_get(extapi, session, encrypt_config, "keyid", &keyid)) == 0 && keyid.len != 0) {
    if(keyid.len >= 500){
      // print_encryption_log("Config file path is too long (over > 512)");
      goto err;
    }

    strncpy(enc_config_path, keyid.str, keyid.len);
    enc_config_path[keyid.len] = '\0';

    // Read config file
    ret = read_encrypt_config(enc_config_path, crypto);
    if(ret==WIREDTIGER_EXT_ERROR){
    	// print_encryption_log("Can not read encryption config (not sufficient parameters)");
    	goto err;
    }
  }else{
    // print_encryption_log("Can not read encryption config (no keyid parameter)");
    goto err;
  }

  *customp = (WT_ENCRYPTOR *)crypto;
  print_encryption_log(encrypt_log, "TDE is initialized.");
  return WIREDTIGER_EXT_OK;

err:
  if(crypto->encrypt_key!=NULL){
    free(crypto->encrypt_key);
    crypto->encrypt_key = NULL;
  }
  if(crypto->init_vector!=NULL){
    free(crypto->init_vector);
    crypto->init_vector = NULL;
  }
  if(encrypt_log!=NULL){
    free(encrypt_log);
    encrypt_log = NULL;
  }
  free(crypto);

  return WIREDTIGER_EXT_ERROR;
}

/*
 * encryption_finalize --
 *      Finalizing TDE encryption
 */
static int
encryption_finalize(WT_ENCRYPTOR *encryptor, WT_SESSION *session){
  TDE_CRYPTO *crypto = (TDE_CRYPTO *)encryptor;

  (void)session; /* Unused parameters */
  total_finalized++;

  // Log finalizing message
  print_encryption_log(encrypt_log, "TDE is finalized.");

  /* Unregistered stat timer*/
  // Timer singal conflict with mongodb socket listen
  // unregister_stats_report_timer();
  // print_encryption_log("TDE is unregistered.");

  /* Free the allocated memory. */
  if(crypto->encrypt_key!=NULL){
    free(crypto->encrypt_key);
    crypto->encrypt_key = NULL;
  }
  if(crypto->init_vector!=NULL){
    free(crypto->init_vector);
    crypto->init_vector = NULL;
  }
  if(encrypt_log!=NULL){
    free(encrypt_log);
    encrypt_log = NULL;
  }
  free(encryptor);

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return WIREDTIGER_EXT_OK;
}


/*
 * register_tde_encryptors --
 *      Adding encryption callbacks.
 */
int
register_tde_encryptors(WT_CONNECTION *connection){
  TDE_CRYPTO *m;
  WT_ENCRYPTOR *wt;
  int ret;

  /* Initialize our top level encryptor. */
  if ((m = calloc(1, sizeof(TDE_CRYPTO))) == NULL){
    // print_encryption_log("Can not allocate TDE_CRYPTO structure. Aborting");
    return (errno);
  }

  /* Initialise encryption metrics */
  last_stat_time = time(NULL);
  total_initialized = 0ULL;
  total_finalized = 0ULL;
  total_encrypted = 0ULL;
  total_decrypted = 0ULL;
  total_encrypted_bytes = 0ULL;
  total_decrypted_bytes = 0ULL;
  total_encryption_failed = 0ULL;
  total_decryption_failed = 0ULL;
  total_encryption_overhead = 0ULL;
  total_encrypted_below_key_size = 0ULL;

  /* Regiter stats timer*/
  // Timer singal conflict with mongodb socket listen
  // register_stats_report_timer();

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  /* Initialize WiredTiger interface */
  wt = (WT_ENCRYPTOR *)&m->encryptor;
  wt->encrypt = tde_encrypt;
  wt->decrypt = tde_decrypt;
  wt->sizing = encryption_overhead_size;
  wt->customize = encryption_initialize;
  wt->terminate = encryption_finalize;

  /* Registering encryptor */
  if ((ret = connection->add_encryptor(connection, "kencrypt", (WT_ENCRYPTOR *)m, NULL)) != 0){
    // print_encryption_log("Can not register TDE module. Aborting");
    return (ret);
  }

  // print_encryption_log("TDE is registered.");
  return WIREDTIGER_EXT_OK;
}
#endif


#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
static int _ini_read_handler(void* user_data, const char* section, const char* name, const char* value){
  int ret;
  TDE_CRYPTO* crypto = (TDE_CRYPTO*)user_data;

  if(MATCH("tde", "encrypt_key")){
    crypto->encrypt_key = malloc(KEY_SIZE);
    if(convert_hex_to_unsignedchar(value, crypto->encrypt_key, KEY_SIZE) == ERROR){
      return INI_HANDLER_ERROR;
    }
  }else if(MATCH("tde", "init_vector")){
    crypto->init_vector = malloc(KEY_SIZE);
    if(convert_hex_to_unsignedchar(value, crypto->init_vector, KEY_SIZE) == ERROR){
      return INI_HANDLER_ERROR;
    }
  }else if (MATCH("tde", "log_file")){
	  if(value==NULL || strlen(value)<2){
        return INI_HANDLER_ERROR;
	  }
      encrypt_log = strdup(value);
  }else{
        // Just ignore it
        // return 0;  /* unknown section/name, error */
  }

  return INI_HANDLER_OK;
}

int read_encrypt_config(char* path, TDE_CRYPTO* config){
	config->encrypt_key = NULL;
	config->init_vector = NULL;
	encrypt_log = NULL;

	// ini_parse() will returns 0 on success
	if(ini_parse(path, _ini_read_handler, config)!=0){
		return WIREDTIGER_EXT_ERROR;
	}

	if(config->encrypt_key==NULL || encrypt_log==NULL || config->init_vector==NULL){
		return WIREDTIGER_EXT_ERROR;
	}

	return WIREDTIGER_EXT_OK;
}


#ifdef _UNIT_TEST_
int main(int argc, char** argv){
  int i;
  int idx = 0;

  int ret;
  int plain_len = 16;
  int encrypted_len, decrypted_len;

  /* A 128 bit key */
  unsigned char *key = (unsigned char *)"0123456789012345"; /* A 128 bit key */


  unsigned char plain[6000];
  unsigned char encrypted[6000];
  unsigned char decrypted[6000];

  memset(plain, 0xFF, 2000);
  memset(encrypted, 0xFF, 2000);
  memset(decrypted, 0xFF, 2000);

  for(i=0; i<plain_len; i++){
    plain[i] = 'A';
  }

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);


  /* Encrypt the plaintext */
  encrypted_len = tde_encrypt1(plain, plain_len, key, (unsigned char*)INIT_VECTOR, encrypted);

  /* Decrypt the ciphertext */
  decrypted_len = tde_decrypt1(encrypted, encrypted_len, key, (unsigned char*)INIT_VECTOR, decrypted);


  /* Print result */
  printf("\n");
  printf("-------------------------------------------------------------------------\n");
  printf("-- Plain    :\n");
  printf("-------------------------------------------------------------------------\n");
  BIO_dump_fp(stdout, (const char *)plain, plain_len);
  printf("-------------------------------------------------------------------------\n");

  printf("\n");
  printf("-------------------------------------------------------------------------\n");
  printf("-- Encrypted:\n");
  printf("-------------------------------------------------------------------------\n");
  BIO_dump_fp(stdout, (const char *)encrypted, encrypted_len);
  printf("-------------------------------------------------------------------------\n");


  printf("\n");
  printf("-------------------------------------------------------------------------\n");
  printf("-- Decrypted:\n");
  printf("-------------------------------------------------------------------------\n");
  BIO_dump_fp(stdout, (const char *)decrypted, decrypted_len);
  printf("-------------------------------------------------------------------------\n");

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}
#endif
