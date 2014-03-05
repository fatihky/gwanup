#ifndef __GWANUP__
#define __GWANUP__

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include <hiredis/hiredis.h>

#include "gwan.h"

// print colorful text
#define GREEN(text) "\033[0;32m" text "\033[0;0m"
#define RED(text) "\033[0;31m" text "\033[0;0m"
#define YELLOW(text) "\033[0;33m" text "\033[0;0m"
#define MAGENTA(text) "\033[0;35m" text "\033[0;0m"

#define GW_LOG(text) \
	printf(MAGENTA("[line: %d]")  YELLOW(" %s():") GREEN(" %s\n"), __LINE__, __func__,  text)

#define GW_LOG_ERR(text) \
	printf(MAGENTA("[line: %d]")  YELLOW(" %s():") RED(" %s\n"), __LINE__, __func__,  text)

// used at function prototypes
#define GWARGS_ char *argv[], data_t *data

// used at functions
#define GA_ argv, data

// used at function prototypes
#define ARGV_ char *argv[]

// get current worker num
#define cur_worker() \
  (int) get_env( argv, CUR_WORKER )

// data type
typedef struct data_st {
	redisContext **rc; // redis connection
	void **data_source; // database connection, hash table pointer etc.
	xbuf_t *main_page; // main page template
} data_t;

// GWANUP can handle file uploads!
// gwanup multipart type
typedef struct gw_file_st {
	char *filename;
	char *content_type;
	xbuf_t *data;

	kv_t *fields;
} gw_mpart_t;

// GWANUP Validate Condition Types
#define	GW_VAL_IS_NOT_NULL  0
#define	GW_VAL_IS_NULL      1
#define	GW_VAL_CONTAINS     2
#define	GW_VAL_NOT_CONTAINS 3
#define	GW_VAL_IS_INT       4
#define GW_VAL_LEN          5
#define GW_VAL_IS_EMAIL     6

// GWANUP Validate Condition
typedef struct gw_val_cond_st
{
	char *field;
	int type;

	union {
		struct {
			int min;
			int max;
		} len;
		char *contains;
	};

	// validate function will modify this value
	bool is_valid;
} gw_val_cond_t;

// data initialization/deinitialization
static inline int  init_data (char *argv[], data_t **Data);
static inline void destroy_data (data_t **Data);

// new dynamic xbuffer
xbuf_t *xbuf_new ();

// load file data into memory
xbuf_t *load_file_from_www (ARGV_, char *filename);
xbuf_t *load_file_from_csp (ARGV_, char *filename);

// get cookie val
// example usage: char *val = gw_cookie (argv, "auth=", 5);
static inline char *gw_cookie (ARGV_, char *cookie_name, size_t cookie_len);

// generate 256-bit hash from input
xbuf_t *to_sha2 (char *input);

// generate random cookie from input
xbuf_t *gw_gen_cookie (char *input);
xbuf_t *gw_gen_cookie_header (char *input, xbuf_t **cookie_dst);

// Multipart parser (upload)
gw_mpart_t *gw_mpart_parser (ARGV_, int *err);

// Validation
// new validate condition
gw_val_cond_t *gw_val_cond_new (char *field, int type);
void gw_val_cond_set (gw_val_cond_t *cond, char *field, int type);

// validate function
void gw_validate_field(gw_val_cond_t *conds[], int count);

bool gw_validate_not_null (gw_val_cond_t *cond, char *field);
bool gw_validate_null (gw_val_cond_t *cond, char *field);
bool gw_validate_contains (gw_val_cond_t *cond, char *field, char *contains);
bool gw_validate_not_contains (gw_val_cond_t *cond, char *field, char *not_contains);
bool gw_validate_int (gw_val_cond_t *cond, char *field);
bool gw_validate_len (gw_val_cond_t *cond, char *field, int min, int max);
bool gw_validate_email (gw_val_cond_t *cond, char *field);

// User functions
bool gw_is_member (GWARGS_, char **uid_dst)
   , __gw_is_member (GWARGS_, char **uid_dst)
   , (*_gw_is_member) (GWARGS_, char **uid_dst) = NULL;

char *gw_get_uid_from_username (GWARGS_, char *username)
   , *__gw_get_uid_from_username (GWARGS_, char *username)
   , *(*_gw_get_uid_from_username) (GWARGS_, char *username) = NULL;

char *gw_get_username (GWARGS_, char *uid)
   , *__gw_get_username (GWARGS_, char *uid)
   , *(*_gw_get_username) (GWARGS_, char *uid) = NULL;

bool gw_user_is_exists (GWARGS_, char *username)
   , __gw_user_is_exists (GWARGS_, char *username)
   , (*_gw_user_is_exists) (GWARGS_, char *username) = NULL;

bool gw_auth_cookie (GWARGS_, char *cookie_val, u64 uid, char *username)
   , __gw_auth_cookie (GWARGS_, char *cookie_val, u64 uid, char *username)
   , (*_gw_auth_cookie) (GWARGS_, char *cookie_vale, u64 uid, char *username) = NULL;

static inline int init_data (ARGV_, data_t **Data)
{
	if(*Data != NULL) return 0;
	data_t *data;

	data = (data_t *) malloc(sizeof(data_t));
	if(!data) return -1;

	int nbr_workers = (int) get_env(argv, NBR_WORKERS);

	// set all fields to null
	data->data_source = NULL;
	data->main_page = NULL;

	// connect to redis database
	data->rc = (redisContext **) malloc(
		sizeof(redisContext *) * nbr_workers);
	for (int i=0; i < nbr_workers; i++)
	{
		data->rc[i] = redisConnect("127.0.0.1", 6379);
		if(data->rc[i]->err)
		{
			printf("ERROR! %s\n", data->rc[i]->errstr);
			free(data->rc);
			free(data);
			*Data = NULL;
			return -1;
		}
	}

	// load templates to ram
	data->main_page = load_file_from_www(argv, "index.html");
	if(!data->main_page) { destroy_data(Data); return -1; }

	*Data = data;
	return 0;
}

static inline void destroy_data (data_t **Data)
{
	data_t *data = *Data;

	if(data->main_page) {
		xbuf_free(data->main_page);
		free(data->main_page);
	}

	free(data);
	*Data = NULL;
}

xbuf_t *xbuf_new ()
{
	xbuf_t *xbuf = (xbuf_t *) malloc(sizeof(xbuf_t));
	if(xbuf == NULL) return NULL;

	xbuf_init(xbuf);

	return xbuf;
}

xbuf_t *load_file_from_www (ARGV_, char *filename)
{
	xbuf_t *out = malloc(sizeof(xbuf_t));
	if(out == NULL) return NULL;

	xbuf_init(out);
	char *wwwpath = (char*)get_env(argv, WWW_ROOT);
	char str[1024];
	s_snprintf(str, 1023, "%s/%s", wwwpath, filename);
	xbuf_frfile(out, str);

	if(out->len < 1)
	{
		xbuf_free(out);
		free(out);
		return NULL;
	}

	return out;
}

xbuf_t *load_file_from_csp (ARGV_, char *filename)
{
	xbuf_t *out = malloc(sizeof(xbuf_t));
	if(out == NULL) return NULL;

	xbuf_init(out);
	char *wwwpath = (char*)get_env(argv, WWW_ROOT);
	char str[1024];
	s_snprintf(str, 1023, "%s/%s", wwwpath, filename);
	xbuf_frfile(out, str);

	if(out->len < 1)
	{
		xbuf_free(out);
		free(out);
		return NULL;
	}

	return out;
}

static inline char *gw_cookie (ARGV_, char *cookie_name
               , size_t cookie_len)
{
	http_t *http = (http_t*)get_env(argv, HTTP_HEADERS);
	xbuf_t *read_buf  = (xbuf_t*)get_env(argv, READ_XBUF);
	char *p = read_buf->ptr;
	char *cookies = http->h_cookies ? p + http->h_cookies : 0;

	if(cookies != 0)
	{
		char *cookie = strstr(cookies, cookie_name);
		if(cookie != 0)
		{

			char *val = strchr(cookie, ' ');
			size_t len = strlen(&cookie[cookie_len + 2]);

			if(len > 1 && val == 0) val = strdup(&cookie[cookie_len]);
			if(val != 0)
			{
				if(val[len] == ';') val[len] = '\0';
				return val;
			}

		}
	}

	return NULL;
}

xbuf_t *to_sha2 (char *input)
{
  u8 result[32];
  xbuf_t *xbuf = (xbuf_t *) malloc(sizeof(xbuf_t));
  xbuf_init (xbuf); // important!
  if(!xbuf) return NULL;
  sha2((u8 *)input, strlen((const char *)input), result);
  xbuf_xcat(xbuf, "%32B", result);
  return xbuf;
}

xbuf_t *gw_gen_cookie (char *input)
{
	xbuf_t *out = to_sha2(input);
	static char c[] = "fatihky274zXc6vMT98bnQwWrt"; // 21 chars
	xbuf_growto(out, 10);

	prnd_t rnd;

	sw_init(&rnd, time(0)); // pseudo-random numbers generator 

	for(int i = 0; i < 10; i++)
	{
		xbuf_ncat(out, &c[sw_rand(&rnd) % 20], 1);
	}

	return out;
}

xbuf_t *gw_gen_cookie_header (char *input, xbuf_t **cookie_dst)
{
	xbuf_t *out = (xbuf_t *) malloc(sizeof(xbuf_t))
		 , *cookie = gw_gen_cookie(input);
	char buf[32]
	   , *time_str = time2rfc(time(NULL) + (60 * 60 * 24 * 365) // 1 year
                             , buf);
	xbuf_init(out);
	xbuf_xcat(out, "Set-Cookie: auth=%s; expires=%s; path=/\r\n"
		, cookie->ptr, time_str);

	// if you need, you can use cookie
	if(cookie_dst) *cookie_dst = cookie;
	else xbuf_free(cookie);

	return out;
}

static int gw_mpart_kv_del_proc (const kv_item *item, const void *user_defined_ctx)
{
	(void) user_defined_ctx;
	return 1;
}

gw_mpart_t *gw_mpart_parser (ARGV_, int *err)
{
	xbuf_t *file_buf = xbuf_new();
	xbuf_t *read_buf = (xbuf_t*)get_env(argv, READ_XBUF);
	char *entity   = (char*)get_env(argv, REQ_ENTITY)
		, *boundary
		, *tmp , *file, *filename, *extention, *content_type;
	u32  cont_len  = (u32)  get_env(argv, CONTENT_LENGTH)
		, boundary_len, field_num = 0
		, entity_offset = entity - read_buf->ptr
		, curr_entity_len = read_buf->len - entity_offset;
	bool req_contains_file = false;
	kv_item item;

	// Set start values
	*err = false;
	item.flags = 0;
	item.key = NULL;
	item.klen = 0;
	item.val = NULL;

	// Error macro
	#define ERR_IF__(x, fn) if(x){ \
		*err = true; \
		fn; \
		return NULL; \
	}

	#define CLEAR_DATA__ \
		if(boundary_len) free(boundary); \
		if(field_num) \
		{ \
			kv_do(mpart->fields, NULL, 0, gw_mpart_kv_del_proc, NULL); \
			kv_free(mpart->fields); \
			mpart->fields = NULL; \
		}

	// Allocate memory for return value
	gw_mpart_t *mpart = (gw_mpart_t *) malloc(sizeof(gw_mpart_t));

	ERR_IF__(mpart == NULL || file_buf == NULL || curr_entity_len < cont_len, {});

	// Allocate memory for field store
	mpart->fields = (kv_t *) malloc(sizeof(kv_t));
	ERR_IF__(mpart->fields == NULL, {});

	// Set fields to NULL
	mpart->filename = NULL;
	mpart->content_type = NULL;
	mpart->data = NULL;

	// Get Boundary
	tmp = strstr(entity, "\r\n");
	ERR_IF__(tmp == NULL, {});
	boundary = strndup(entity, tmp - entity);
	ERR_IF__(boundary == NULL, {});

	// Set boundary length
	boundary_len = strlen(boundary);

	// Check more fields
	tmp = strstr((entity + boundary_len + 2), boundary);

	// User sent two or more fields
	if(tmp != NULL)
	{
		field_num = 2;
		while((tmp = strstr((tmp + boundary_len), boundary)) != NULL)
		{
			++field_num;
		}
	}

	// Check file
	if(strstr(entity, "filename=\"") != NULL)
	{
		req_contains_file = true;
		field_num -= 1;
	}

	// İnitialize field store
	kv_init(mpart->fields, "fields", 10, 0, NULL, NULL);

	if(field_num > 0) tmp = strstr(entity, "name=");

	for(int i = 0; i < field_num; i++)
	{
		ERR_IF__(tmp == NULL, {CLEAR_DATA__});

		tmp = strstr(tmp, "name=");

		if(tmp == NULL) continue;

		item.key = strstr(tmp, "\r\n");

		if(item.key == NULL) continue;

		item.klen = item.key - tmp - 7;
		item.key = strndup(tmp + 6, item.klen);

		tmp = strstr(tmp, "\r\n");

		item.val = strndup(tmp + 4, strstr(tmp, boundary) - tmp - 6);

		tmp = strstr(tmp, boundary);

		kv_add(mpart->fields, &item);
	}

	if(req_contains_file)
	{
		tmp = strstr(entity, "filename=\"");
		ERR_IF__(tmp == NULL, {CLEAR_DATA__});

		filename = strstr(tmp, "\"\r\n");
		ERR_IF__(filename == NULL, {CLEAR_DATA__});

		filename = strndup(tmp + 10, (int)(filename - tmp - 10));
		if(!(filename[4])) return NULL; // filename must contain least 5 chars. example: x.png
		extention = strchr(filename, '.');
		if(	   ( extention == NULL )
			|| ( strchr(filename, '/') != NULL )
			|| ( strchr(filename, '\\') != NULL )
		) return NULL;

		tmp = strstr(tmp, "Content-Type: ");
		content_type = file = strstr(tmp, "\r\n\r\n");
		content_type = strndup(tmp + 14, (int)(content_type - tmp -14));

		xbuf_ncat(file_buf, file + 4, curr_entity_len);

		// Set return value's fields
		mpart->filename = filename;
		mpart->content_type = content_type;
		mpart->data = file_buf;
	}
	free(boundary);

	#undef ERR_IF__
	#undef CLEAR_DATA__

	return mpart;
}

gw_val_cond_t *gw_val_cond_new (char *field, int type)
{
	gw_val_cond_t *cond = (gw_val_cond_t *) malloc(sizeof(gw_val_cond_t));
	if(cond == NULL) return NULL;

	cond->field = strdup(field);
	cond->type = type;
	cond->contains = NULL;

	return cond;
}

void gw_val_cond_free(gw_val_cond_t *cond)
{
	free(cond->field);

	if(cond->type == GW_VAL_CONTAINS)
		free(cond->contains);

	free(cond);
}

void gw_val_cond_set (gw_val_cond_t *cond, char *field, int type)
{
	if(cond == NULL) return;

	free(cond->field);
	cond->field = strdup(field);
	cond->type = type;
	cond->len.min = 0;
	cond->len.max = 0;
}

void gw_validate_field(gw_val_cond_t *conds[], int count)
{
	for (int i = 0; i < count; i++)
	{
		if(!conds[i]) return;
		int type = conds[i]->type;
		char *field = conds[i]->field;

		switch(type)
		{
			case GW_VAL_IS_NOT_NULL:
			{
				if(strlen(conds[i]->field) < 1)
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_IS_NULL:
			{
				if(strlen(conds[i]->field) > 1)
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_CONTAINS:
			{
				size_t len = strlen(field);
				if(len < 1 || strstr(field, conds[i]->contains) == NULL)
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_NOT_CONTAINS:
			{
				size_t len = strlen(field);
				if(len > 0 && strstr(field, conds[i]->contains) != NULL)
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_IS_INT:
			{
				int val = atoi(field);
				if(val == -1)
				{
					if(field[0] == '-' && field[1] != 0 && field[1] == '1')
					{
						conds[i]->is_valid = true;
					} else {
						conds[i]->is_valid = false;
					}
				} else if(val == 0) {
					if(field[0] != '0')
						conds[i]->is_valid = false;
					else
						conds[i]->is_valid = true;
				} else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_LEN:
			{
				size_t len = strlen(field);
				if(conds[i]->len.min > len) conds[i]->is_valid = false;
				else if(conds[i]->len.max && conds[i]->len.max < len)
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			case GW_VAL_IS_EMAIL:
			{
				size_t len = strlen(field);
				char *at;

				if(len < 5) // a@b.c
					conds[i]->is_valid = false;
				else if((at = strstr(field, "@")) == NULL)
					conds[i]->is_valid = false;
				else if((at = strstr(at, ".")) == NULL)
					conds[i]->is_valid = false;
				else if(strlen(at) < 1) // domain suffix .com .net etc...
					conds[i]->is_valid = false;
				else
					conds[i]->is_valid = true;
			} break;

			default: conds[i]->is_valid = false;
		}
	}
}

bool gw_validate_not_null (gw_val_cond_t *cond, char *field)
{
	gw_val_cond_set(cond, field, GW_VAL_IS_NOT_NULL);

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_null (gw_val_cond_t *cond, char *field)
{
	gw_val_cond_set(cond, field, GW_VAL_IS_NULL);

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_contains (gw_val_cond_t *cond, char *field, char *contains)
{
	gw_val_cond_set(cond, field, GW_VAL_CONTAINS);
	cond->contains = strdup(contains);

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_not_contains (gw_val_cond_t *cond, char *field, char *not_contains)
{
	gw_val_cond_set(cond, field, GW_VAL_NOT_CONTAINS);
	cond->contains = not_contains;

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_int (gw_val_cond_t *cond, char *field)
{
	gw_val_cond_set(cond, field, GW_VAL_IS_INT);

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_len (gw_val_cond_t *cond
					, char *field, int min, int max)
{
	gw_val_cond_set(cond, field, GW_VAL_LEN);
	cond->len.min = min;
	cond->len.max = max;

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool gw_validate_email (gw_val_cond_t *cond, char *field)
{
	gw_val_cond_set(cond, field, GW_VAL_IS_EMAIL);

	gw_validate_field(&cond, 1);

	if(cond->is_valid)
		return true;
	else
		return false;
}

bool __gw_is_member (GWARGS_, char **uid_dst)
{
	char *auth = gw_cookie(argv, "auth=", 5);
	if (!auth)  return false;

	redisReply *rr = redisCommand(data->rc[cur_worker()], "GET auth:%s", auth);
	free(auth);

	if(rr != NULL && rr->len)
	{ // User is member
		if(uid_dst) *uid_dst = strndup(rr->str, rr->len);
		freeReplyObject(rr);
		return true;
	}

	freeReplyObject(rr);
	return false;
}

bool gw_is_member (GWARGS_, char **uid_dst)
{
	if(_gw_is_member != NULL) return _gw_is_member(GA_, uid_dst);

	else return __gw_is_member(GA_, uid_dst);
}

char *__gw_get_uid_from_username (GWARGS_, char *username)
{
	redisContext *rc = data->rc[cur_worker()];
	redisReply *rr = redisCommand(rc, "GET username:%s:uid", username);

	if(rr == NULL) return NULL;
	if(rr->type != REDIS_REPLY_STRING)
	{
		freeReplyObject(rr);
		return NULL;
	}

	char *uid = strndup(rr->str, rr->len);
	freeReplyObject(rr);

	return uid;
}

char *gw_get_uid_from_username (GWARGS_, char *username)
{
	if(_gw_get_uid_from_username != NULL) return _gw_get_uid_from_username(GA_, username);

	else return __gw_get_uid_from_username(GA_, username);
}

char *__gw_get_username(GWARGS_, char *uid)
{
	redisContext *rc = data->rc[cur_worker()];
	redisReply *rr;
	char *username;

	// get username
	rr = redisCommand(rc, "HGET uid:%s username", uid);
	if(rr == NULL) return NULL;
	if(rr->str != NULL) username = strndup(rr->str, rr->len);
	else username = NULL;
	freeReplyObject(rr);

	return username;
}

char *gw_get_username(GWARGS_, char *uid)
{
	if(_gw_get_username != NULL) return _gw_get_username(GA_, uid);

	else return __gw_get_username(GA_, uid);
}

bool __gw_user_is_exists (GWARGS_, char *username)
{
	redisContext *rc = data->rc[cur_worker()];
	redisReply *rr = redisCommand(rc, "EXISTS username:%s:uid", username);

	if (rr == NULL) return -1;
	if(rr->integer == 1)
	{
		freeReplyObject(rr);
		return true;
	}

	freeReplyObject(rr);
	return false;
}

bool gw_user_is_exists (GWARGS_, char *username)
{
	if(_gw_user_is_exists != NULL) return _gw_user_is_exists(GA_, username);

	else return __gw_user_is_exists(GA_, username);
}

bool __gw_auth_cookie (GWARGS_, char *cookie_val, u64 uid, char *username)
{
	redisReply *rr = redisCommand(data->rc[cur_worker()], "SET auth:%s %llu"
		, cookie_val, (long long unsigned)uid);

	if(    rr != NULL
		&& rr->type == REDIS_REPLY_STATUS
		&& rr->integer == REDIS_OK
	  )
	{ // Cookie is authendicated
		freeReplyObject(rr);
		return true;
	}

	freeReplyObject(rr);
	return false;
}

bool gw_auth_cookie (GWARGS_, char *cookie_val, u64 uid, char *username)
{
	if(_gw_auth_cookie != NULL) return _gw_auth_cookie(GA_, cookie_val, uid, username);

	else return __gw_auth_cookie(GA_, cookie_val, uid, username);
}

#endif