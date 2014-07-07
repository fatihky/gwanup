// ============================================================================
// C servlet sample for the G-WAN Web Application Server (http://trustleap.ch/)
// ----------------------------------------------------------------------------
// cookie-example.c: set a cookie
// ============================================================================

#include "gwan.h" // G-WAN exported functions
#include "gwanup.h" // G-WAN UP exported functions
#pragma link "hiredis"

int main(int argc, char *argv[])
{
	xbuf_t *sha2 = to_sha2 ("fatih-kaya");

	xbuf_t *cookie_header = gw_gen_cookie_header ("sess", sha2->ptr, (60 * 60 * 24 * 365)); // expires after 1 year

	http_header(HEAD_ADD, cookie_header->ptr, cookie_header->len, argv);

	xbuf_cat(get_reply(argv), "cookie test");

	// cleanup
	xbuf_free(cookie_header);
	free(cookie_header);
	xbuf_free(sha2);
	free(sha2);

	return 200; // return an HTTP code (200:'OK')
}

// ============================================================================
// End of Source Code
// ============================================================================

