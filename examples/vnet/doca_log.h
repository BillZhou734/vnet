#ifndef _DOCA_LOG__H_
#define _DOCA_LOG__H_

#include <stdint.h>
#include <stdarg.h>


enum doca_log_level {
   DOCA_LOG_LEVEL_EMERG = 1U,
   DOCA_LOG_LEVEL_ALERT = 2U,
   DOCA_LOG_LEVEL_CRIT  = 3U,
   DOCA_LOG_LEVEL_ERR   =   4U,
   DOCA_LOG_LEVEL_WARNING = 5U,
   DOCA_LOG_LEVEL_NOTICE =  6U,
   DOCA_LOG_LEVEL_INFO   =  7U,
   DOCA_LOG_LEVEL_DEBUG  =  8U,
};


struct doca_log_module {
    char *name;
    uint32_t id;
    enum doca_log_level level;
};

void register_doca_log(struct doca_log_module *module, const char *name);

#define DOCA_LOG_MODULE(X) static struct doca_log_module module_instance; \
    static void doca_log_init_##X(void) __attribute__((constructor)); \
    static void doca_log_init_##X(void) { \
                register_doca_log(&module_instance,#X); \
    }


void doca_log(struct doca_log_module *module, enum doca_log_level level, const char *format,...);

#define DOCA_LOG_CRIT(format,...) doca_log(&module_instance, DOCA_LOG_LEVEL_CRIT,\
                                  "critical:[%s]," format "\n",module_instance.name,##__VA_ARGS__);
#define DOCA_LOG_ERR(format,...) doca_log(&module_instance, DOCA_LOG_LEVEL_ERR, \
                                  "error:[%s]," format "\n",module_instance.name,##__VA_ARGS__);
#define DOCA_LOG_WARN(format, ...) doca_log(&module_instance, DOCA_LOG_LEVEL_WARNING, \
                                  "warn:[%s]," format "\n",module_instance.name,##__VA_ARGS__); 
#define DOCA_LOG_INFO(format, ...) doca_log(&module_instance, DOCA_LOG_LEVEL_INFO, \
                                  "info:[%s]," format "\n",module_instance.name,##__VA_ARGS__); 
#define DOCA_LOG_DBG(format, ...) doca_log(&module_instance, DOCA_LOG_LEVEL_DEBUG, \
                                  "dbg:[%s]," format "\n",module_instance.name,##__VA_ARGS__); 

enum doca_log_type {
    DOCA_LOG_TYPE_NONE,
    DOCA_LOG_TYPE_STDERR,
};

void doca_log_cfg(enum doca_log_type type, const char *cfg);
void doca_set_log_level(uint32_t log_level);
uint32_t doca_is_debug_level(void);

#endif
