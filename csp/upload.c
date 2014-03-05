// ============================================================================
//   Modified entity.c
// ============================================================================

// g-wan--color-thief's upload.c's cutted version

#include "gwanup.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
/*   xbuf_t *reply = (xbuf_t *)get_reply(argv)
        , *read_buf = (xbuf_t*)get_env(argv, READ_XBUF);
   char *entity   = (char*)get_env(argv, REQ_ENTITY)
      , *tmp , *file, *filename, *extention, *content_type;
   u32  cont_len  = (u32)  get_env(argv, CONTENT_LENGTH)
      , entity_offset = entity - read_buf->ptr
      , curr_entity_len = read_buf->len - entity_offset;

   u32 *entity_size_limit = (u32*)get_env(argv, MAX_ENTITY_SIZE);
   *entity_size_limit = 1024 * 1024 * 200;

   if ( ((int) get_env(argv, REQUEST_METHOD)) != 3 )
   {
      static char redir[] = "Location: /csp_upload.html\r\n\r\n";
      http_header(HEAD_ADD, redir, sizeof(redir) - 1, argv);
      return 302; // return an HTTP code (302:'Found')
   }

   if(curr_entity_len < cont_len)
   {
      xbuf_xcat(reply, "<br>Entity[%k] is missing %k unread bytes\n",
                cont_len, curr_entity_len);
      return 500;
   }

   tmp = strstr(entity, "filename=\"");
   filename = strstr(tmp, "\"\r\n");
     if(filename == NULL) return 400;
   filename = strndup(tmp + 10, (int)(filename - tmp - 10));
     if(!(filename[4])) return 400; // filename must contain least 5 chars. example: x.png
   extention = strchr(filename, '.');
*/
/*
     if(   ( extention == NULL )
        || ( strchr(&extention[1], '.') != NULL )
        || ( strchr(filename, '/') != NULL )
        || ( strchr(filename, '\\') != NULL )
        || ( strchr(filename, ':') != NULL )
       ) return 400;
*/
/*
   tmp = strstr(tmp, "Content-Type: ");
//     if(strncmp(tmp + 14, "image/", 6) != 0) return 415; // 415: Unsupported Media Type
   content_type = file = strstr(tmp, "\r\n\r\n");
   content_type = strndup(tmp + 14, (int)(content_type - tmp -14));

   char *new_filename = malloc(256);
   char *wwwpath = (char*)get_env(argv, WWW_ROOT);
   u64 ms = getms();
   sprintf(new_filename, "%s/uploads/%llu%s", wwwpath, (unsigned long long)ms
                                            , extention);

   FILE *fp = fopen(new_filename, "wb");
   fwrite(file + 4, curr_entity_len, 1, fp);
   fflush(fp);
   fclose(fp);

   xbuf_xcat(get_reply(argv), "your file uploaded to: %s", new_filename);

   free(filename);     filename = NULL;
   free(new_filename); new_filename = NULL;
   free(content_type); content_type = NULL;
*/
   int err;
   gw_mpart_t *mpart = gw_mpart_parser(argv, &err);
   if(mpart)
   {
    //   printf("mpartname: %s\n", mpart->filename);
    //  printf("data: %s\n", (char *)mpart->data->ptr);
   }
   gw_val_cond_t *cond = gw_val_cond_new("-", GW_VAL_IS_INT); free(cond);
   printf("field_num: %llu\n", (long long unsigned)mpart->fields->nbr_items);
   return 200; // return an HTTP code (302:'Found')
}

// ============================================================================
// End of Source Code
// ============================================================================







