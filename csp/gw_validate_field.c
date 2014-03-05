#include "gwanup.h"
#pragma link "hiredis"

int main(int argc, char *argv[])
{
	data_t **Data =(data_t **) get_env(argv, US_VHOST_DATA)
		, *data = NULL;
	xbuf_t *reply = get_reply ( argv );

	switch(init_data(argv, Data))
	{
		case 0: data = *Data; break;
		case 1: return 500;
		default: return 503;
	}

	char *uid;
	int auth = gw_is_member(argv, data, &uid);

	/**
    	YOUR CODE GOES HERE
	*/

	xbuf_xcat(reply, "Hello World! auth: %d\n", auth);


	// Validate int
	GW_LOG("GW_VAL_IS_INT");
	gw_val_cond_t *cond = gw_val_cond_new("-", GW_VAL_IS_INT);

	gw_validate_field(&cond, 1);

	printf("cond->field: %s\n", cond->field);
	printf("cond->type: %d\n", cond->type);
	printf("cond->is_valid: %s\n", (cond->is_valid) ? "true" : "false");


	// Validate length
	GW_LOG("GW_VAL_LEN");
	gw_val_cond_set(cond, "ssss", GW_VAL_LEN);
	cond->len.min = 10;
	cond->len.max = 0;

	gw_validate_field(&cond, 1);

	printf("cond->field: %s\n", cond->field);
	printf("cond->type: %d\n", cond->type);
	printf("cond->is_valid: %s\n", (cond->is_valid) ? "true" : "false");


	// Validate email
	GW_LOG("GW_VAL_IS_EMAIL");
	gw_val_cond_set(cond, "gwan@gwan.com", GW_VAL_IS_EMAIL);

	gw_validate_field(&cond, 1);

	printf("cond->field: %s\n", cond->field);
	printf("cond->type: %d\n", cond->type);
	printf("cond->is_valid: %s\n", (cond->is_valid) ? "true" : "false");


	// Cleaning data
	if(auth == true) free(uid);
	gw_val_cond_free(cond);

	return 200;
}
