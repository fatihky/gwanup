// ============================================================================
//   Modified entity.c
// ============================================================================

// g-wan--color-thief's upload.c's cutted version

#include "gwanup.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
   int err;
   gw_mpart_t *mpart = gw_mpart_parser(argv, &err);
   if(mpart)
   {
		printf("mpart->filename: %s\n", mpart->filename);
		printf("data: %s\n", (char *)mpart->data->ptr);
   }

   xbuf_cat(get_reply(argv), "Hello world from gwanup!");
   return 200; // return an HTTP code (302:'Found')
}

// ============================================================================
// End of Source Code
// ============================================================================







