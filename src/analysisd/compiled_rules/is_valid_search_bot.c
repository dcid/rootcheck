#include "shared.h"
#include "eventinfo.h"
#include "config.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#define NUM_OF_USERAGENTS	3
#define NUM_OF_HOSTNAMES	3
#define MAX_IP_SIZE			15

void *is_valid_search_bot(Eventinfo *lf)
{
	struct sockaddr_in src_addr;
	char host[1024];
	int i;

	static char last_match_ip[MAX_IP_SIZE + 1] = "";

	char *useragent_list[] = {
		"Googlebot",
		"msnbot",
		"Slurp"};

	char *hostname_list[] = {
		"googlebot.com",
		"search.msn.com",
		"yahoo.com"};

	if (!lf)
		return NULL;

	if (!lf->srcip)
		return NULL;

	if (!lf->log)
		return NULL;

	/* For each known useragent */
	for (i = 0; i < NUM_OF_USERAGENTS; i++) {

		/* Check if match */
		if (strstr(lf->log, useragent_list[i])) {

			/* We already know this is a match */
			if (strncmp(last_match_ip, lf->srcip, MAX_IP_SIZE) == 0)
				return lf;
			
			/* Fill sockaddr */
			memset(&src_addr, 0, sizeof(struct sockaddr_in));
			src_addr.sin_family = AF_INET;
			inet_pton(AF_INET, lf->srcip, &src_addr.sin_addr);

			/* Do reverse DNS search */
			getnameinfo((struct sockaddr *)&src_addr, sizeof src_addr, host, sizeof host,
                        NULL, 0, 0);

			/* Check if hostname is valid */
			if (strstr(host, hostname_list[i])) {

				/* Save the ip as match */
				strncpy(last_match_ip, lf->srcip, MAX_IP_SIZE);

				/* Match */
				return lf;
			}
		}
	}

	/* No match */
	return NULL;
}
