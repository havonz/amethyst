#ifndef launchd_hook_ppl_h
#define launchd_hook_ppl_h

#include "basebin_common.h"

#ifdef __arm64e__
void ppl_write_buf(uint64_t pa, void *data, uint32_t size);
void ppl_write8(uint64_t pa, uint8_t val);
void ppl_write16(uint64_t pa, uint16_t val);
void ppl_write32(uint64_t pa, uint32_t val);
void ppl_write64(uint64_t pa, uint64_t val);
#else
#define ppl_write_buf(pa, data, size);
#define ppl_write8(pa, value);
#define ppl_write16(pa, value);
#define ppl_write32(pa, value);
#define ppl_write64(pa, value);
#endif

#endif /* launchd_hook_ppl_h */
