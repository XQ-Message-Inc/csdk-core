//
//  config.c
//  xqc
//
//  Created by Ike E on 10/16/20.
//

#include <stdio.h>
#include <memory.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

#include <xq/config.h>
#include <xq/connect.h>
#include <ext/inih/ini.h>
#include <ext/jread/jRead.h>
#include <ext/uri_encode/uri_encode.h>

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *xq_escape(char *str) {

  const size_t len = strlen(str);
  char *buffer = calloc(len * 3 + 1, 1);
  uri_encode(str, len, buffer);
  return buffer;
}

char *xq_strcat(char *tail, char *src, int max_buf) {
  if (tail == 0) return tail;
  if (max_buf == 0) {
    while (*tail)
      tail++;
    while ((*tail++ = *src++))
      ;
    return --tail;
  }

  char *dest = memccpy(tail, src, '\0', max_buf);
  return (dest) ? --dest : NULL;
};

_Bool xq_set_access_token(struct xq_config *config, const char *token) {

  if (!config)
    return 0;

  if (config->access_token) {
    free(config->access_token);
    config->access_token = 0;
  }

  if (token) {
    config->access_token = calloc(strlen(token) + strlen(BEARER_TAG) + 1, 1);
    xq_strcat(xq_strcat(config->access_token, BEARER_TAG, 0), (char *)token, 0);
  }

  return 1;
}

_Bool xq_set_dashboard_token(struct xq_config *config, const char *token) {

  if (!config)
    return 0;

  if (config->dashboard_token) {
    free(config->dashboard_token);
    config->dashboard_token = 0;
  }

  if (token) {
    config->dashboard_token = calloc(strlen(token) + strlen(BEARER_TAG) + 1, 1);
    xq_strcat(xq_strcat(config->dashboard_token, BEARER_TAG, 0), (char *)token,
              0);
  }

  return 1;
}

_Bool xq_set_trusted_address(struct xq_config *config, const char *addr) {

  if (!config)
    return 0;

  if (config->trusted_address) {
    free(config->trusted_address);
    config->trusted_address = 0;
  }

  if (addr) {
    config->trusted_address = calloc(strlen(addr) + strlen(TRUSTED_TAG) + 1, 1);
    xq_strcat(xq_strcat(config->trusted_address, TRUSTED_TAG, 0), (char *)addr,
              0);
  }

  return 1;
}

_Bool set_exchange_token(struct xq_config *config, const char *token, int len) {

  if (!config)
    return 0;

  if (config->exchange_token) {
    free(config->exchange_token);
    config->exchange_token = 0;
  }

  if (token) {
    if (len == 0)
      len = (int)strlen(token);
    config->exchange_token = calloc(len + BEARER_TAG_LEN + 1, 1);
    xq_strcat(xq_strcat(config->exchange_token, BEARER_TAG, BEARER_TAG_LEN),
              (char *)token, len);
  }

  return 1;
}

char* xq_get_file_name(const char* file_path, char* out_buffer) {
    char* last_separator = strrchr(file_path, PATH_SEPARATOR);
    if (last_separator)
    {
        last_separator += 1;
        if (last_separator){
            strcpy(out_buffer, last_separator);
        }
        else {
            strcpy(out_buffer, file_path);
        }
        return out_buffer;
    }
    else {
         return strcpy(out_buffer, file_path);
    }
    //char* last_separator = strrchr(file_path, PATH_SEPARATOR) + 1;
    
}

int xq_make_path(char* file_path, mode_t mode) {
    for (char* p = strchr(file_path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(file_path, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                return -1;
            }
        }
        *p = '/';
    }
    return 0;
}

const char *xq_get_access_token(struct xq_config *config) {
  if (!config)
    return 0;
  return (const char *)(config->access_token + (int)strlen(BEARER_TAG));
}

static int _ini_handler(void *user, const char *section, const char *name,
                        const char *value) {
  struct xq_config *pconfig = (struct xq_config *)user;

  // Setup default sockets ( overridden from xq.ini )

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

  if (MATCH("Connections", "Sub"))
    pconfig->subscription_url = strdup(value);
  else if (MATCH("Connections", "Val"))
    pconfig->validation_url = strdup(value);
  else if (MATCH("Connections", "Saas"))
    pconfig->saas_url = strdup(value);
  else if (MATCH("Connections", "Quantum"))
    pconfig->quantum_url = strdup(value);
  else if (MATCH("ApiKeys", "XQ")) {
    pconfig->xq_api_key = calloc(strlen(value) + strlen(APIKEY_TAG) + 1, 1);
    char *tail = xq_strcat(pconfig->xq_api_key, APIKEY_TAG, 0);
    xq_strcat(tail, (char *)value, 0);
  } else if (MATCH("ApiKeys", "Dashboard")) {
    pconfig->dashboard_api_key =
        calloc(strlen(value) + strlen(APIKEY_TAG) + 1, 1);
    char *tail = xq_strcat(pconfig->dashboard_api_key, APIKEY_TAG, 0);
    xq_strcat(tail, (char *)value, 0);
  } else if (MATCH("Settings", "Timeout"))
    pconfig->timeout_secs = atoi(value);
  else if (MATCH("Settings", "Threads"))
    pconfig->support_threads = strcmp("true", value) == 0;

  else if (MATCH("Monitor", "Key"))
    pconfig->monitor_key = strdup(value);
  else if (MATCH("Monitor", "Team"))
    pconfig->monitor_team_id = atoi(value);
  else if (MATCH("Monitor", "GatewaySock"))
    pconfig->gateway_sock = atoi(value);
  else if (MATCH("Monitor", "MonitorSock")) {
    pconfig->monitor_sock = atoi(value);
  } else if (MATCH("Monitor", "Interval")) {
    pconfig->monitor_interval = atoi(value);
  } else if (MATCH("Monitor", "Gateway")) {
    pconfig->gateway_id = atol(value);
  } else if (MATCH("Monitor", "MonitorIP"))
    pconfig->monitor_ip = strdup(value);
  else
    return 0; //  unknown section/name, error
  return 1;
}

struct xq_config xq_init(const char *configPath) {

  struct xq_config new_config = {0, 0, 0, 0, 0, 0,     0,     0,
                                 0, 0, 0, 0, 0, 25000, 25001, 0, 0, 0};

  if (ini_parse(configPath, _ini_handler, &new_config) < 0) {
    fprintf(stderr, "Unable to locate or open configuration file: %s\n",
            configPath);
    if (new_config.monitor_ip == 0) {
      new_config.monitor_ip = strdup("127.0.0.1");
    }
    return new_config;
  }

  return new_config;
}

_Bool xq_is_valid_config(struct xq_config *conf) {
  return conf->subscription_url != 0 && conf->validation_url != 0 &&
         conf->xq_api_key != 0;
}

void xq_destroy_config(struct xq_config *config) {

  if (!config)
    return;
  if (config->saas_url)
    free(config->saas_url);
  if (config->quantum_url)
    free(config->quantum_url);
  if (config->subscription_url)
    free(config->subscription_url);
  if (config->validation_url)
    free(config->validation_url);
  if (config->xq_api_key)
    free(config->xq_api_key);
  if (config->dashboard_api_key)
    free(config->dashboard_api_key);
  if (config->access_token)
    free(config->access_token);
  if (config->exchange_token)
    free(config->exchange_token);
  if (config->monitor_key)
    free(config->monitor_key);
  if (config->monitor_ip)
    free(config->monitor_ip);
  if (config->trusted_address)
    free(config->trusted_address);
  memset(config, 0, sizeof(struct xq_config));
  // curl_global_cleanup();
}

_Bool xq_fill_error(struct xq_response *response, struct xq_error_info *error) {
  if (response == 0 || error == 0 || response->content == 0)
    return 0;
  jRead_string((char *)response->content, "{'status'", error->content,
               MAX_ERROR_LENGTH, 0);
  error->responseCode = response->responseCode;
  return 1;
}

// inline function to swap two numbers
static inline void swap(char *x, char *y) {
  char t = *x;
  *x = *y;
  *y = t;
}

// function to reverse buffer[i..j]
char *reverse(char *buffer, int i, int j) {
  while (i < j)
    swap(&buffer[i++], &buffer[j--]);

  return buffer;
}

// Iterative function to implement itoa() function in C
char *itoa(int value, char *buffer, int base) {
  // invalid input
  if (base < 2 || base > 32)
    return buffer;

  // consider absolute value of number
  int n = abs(value);

  int i = 0;
  while (n) {
    int r = n % base;

    if (r >= 10)
      buffer[i++] = 65 + (r - 10);
    else
      buffer[i++] = 48 + r;

    n = n / base;
  }

  // if number is 0
  if (i == 0)
    buffer[i++] = '0';

  // If base is 10 and value is negative, the resulting string
  // is preceded with a minus sign (-)
  // With any other base, value is always considered unsigned
  if (value < 0 && base == 10)
    buffer[i++] = '-';

  buffer[i] = '\0'; // null terminate string

  // reverse the string and return it
  return reverse(buffer, 0, i - 1);
}
