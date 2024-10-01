void* hmc_init_mutex();
void hmc_lock_mutex(void* mutex);
void hmc_unlock_mutex(void* mutex);
void hmc_free_mutex(void* mutex);

void* hmc_init_rwlock();
void hmc_lock_shared_rwlock(void* rwlock);
void hmc_unlock_shared_rwlock(void* rwlock);
void hmc_lock_exclusive_rwlock(void* rwlock);
void hmc_unlock_exclusive_rwlock(void* rwlock);
void hmc_free_rwlock(void* rwlock);
