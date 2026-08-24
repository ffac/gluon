#include <respondd.h>

#include <json-c/json.h>
#include <libgluonutil.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>

#include "mac.h"

static struct json_object * get_radv_filter() {
	/* The daemon keeps the address of the elected router in this set, and
	 * empties it while no filtering takes place.
	 */
	FILE *f = popen("exec /usr/sbin/nft list set bridge gluon radv_allow 2>/dev/null", "r");
	char *line = NULL;
	char *elements;
	size_t len = 0;
	struct ether_addr mac = {};
	struct ether_addr unspec = {};
	char macstr[F_MAC_LEN + 1] = "";

	if (!f)
		return NULL;

	while (getline(&line, &len, f) > 0) {
		elements = strstr(line, "elements = {");
		if (!elements)
			continue;

		if (sscanf(elements, "elements = { " F_MAC, F_MAC_VAR_REF(mac)) == ETH_ALEN)
			break;
	}
	free(line);

	pclose(f);

	memset(&unspec, 0, sizeof(unspec));
	if (ether_addr_equal(mac, unspec)) {
		return NULL;
	} else {
		snprintf(macstr, sizeof(macstr), F_MAC, F_MAC_VAR(mac));
		return gluonutil_wrap_string(macstr);
	}
}

static struct json_object * respondd_provider_statistics() {
	struct json_object *ret = json_object_new_object();

	json_object_object_add(ret, "gateway6", get_radv_filter());

	return ret;
}

const struct respondd_provider_info respondd_providers[] = {
	{"statistics", respondd_provider_statistics},
	{}
};
