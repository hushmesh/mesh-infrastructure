#ifndef ENCLAVE_BUILD
#include <wolfssl/options.h>
#endif

#include "hm_crypt.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>

void* hmc_init_mutex() {
  wolfSSL_Mutex* m = (wolfSSL_Mutex*) malloc(sizeof(wolfSSL_Mutex));
  if (wc_InitMutex(m) == 0) {
    return m;
  } else {
    free(m);
    return NULL;
  }
}

void hmc_lock_mutex(void* mutex) {
  if (mutex == NULL) {
    hml_error("hmc_lock_mutex invoked on NULL mutex");
    return;
  }
  wc_LockMutex((wolfSSL_Mutex*) mutex);
}

void hmc_unlock_mutex(void* mutex) {
  if (mutex == NULL) {
    hml_error("hmc_unlock_mutex invoked on NULL mutex");
    return;
  }
  wc_UnLockMutex((wolfSSL_Mutex*) mutex);
}

void hmc_free_mutex(void* mutex) {
  if (mutex == NULL) {
    return;
  }
  wc_FreeMutex((wolfSSL_Mutex*) mutex);
  free(mutex);
}

void* hmc_init_rwlock() {
  wolfSSL_RwLock* rw = (wolfSSL_RwLock*) malloc(sizeof(wolfSSL_RwLock));
  if (wc_InitRwLock(rw) == 0) {
    return rw;
  } else {
    free(rw);
    return NULL;
  }
}

void hmc_lock_shared_rwlock(void* rwlock) {
  if (rwlock == NULL) {
    hml_error("hmc_lock_shared_rwlock invoked on NULL rwlock");
    return;
  }
  wc_LockRwLock_Rd((wolfSSL_RwLock*) rwlock);
}

void hmc_unlock_shared_rwlock(void* rwlock) {
  if (rwlock == NULL) {
    hml_error("hmc_unlock_shared_rwlock invoked on NULL rwlock");
    return;
  }
  wc_UnLockRwLock((wolfSSL_RwLock*) rwlock);
}

void hmc_lock_exclusive_rwlock(void* rwlock) {
  if (rwlock == NULL) {
    hml_error("hmc_lock_exclusive_rwlock invoked on NULL rwlock");
    return;
  }
  wc_LockRwLock_Wr((wolfSSL_RwLock*) rwlock);
}

void hmc_unlock_exclusive_rwlock(void* rwlock) {
  if (rwlock == NULL) {
    hml_error("hmc_unlock_exclusive_rwlock invoked on NULL rwlock");
    return;
  }
  wc_UnLockRwLock((wolfSSL_RwLock*) rwlock);
}

void hmc_free_rwlock(void* rwlock) {
  if (rwlock == NULL) {
    return;
  }
  wc_FreeRwLock((wolfSSL_RwLock*) rwlock);
  free(rwlock);
}
