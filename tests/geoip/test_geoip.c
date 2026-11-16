/*
 * Checks a legacy GeoIP country database against the bundled libGeoIP.
 *
 * Usage: test_geoip <path to GeoIP.dat>
 * Exit 0 when every check passes; otherwise one line per failure and exit 1.
 *
 * Build (from the repository root):
 *   gcc -std=gnu99 -Wall -DPACKAGE_VERSION='"1.6.12"' -DGEOIPDATADIR='"/tmp"' -I GeoIP \
 *       -o /tmp/test_geoip tests/geoip/test_geoip.c GeoIP/GeoIP.c GeoIP/GeoIPCity.c \
 *       GeoIP/GeoIP_deprecated.c GeoIP/regionName.c GeoIP/timeZone.c
 */
#include <stdio.h>
#include <string.h>

#include "GeoIP.h"

/* Highest valid country id: 254 is "SS"; 255 ("O1") must never appear. */
#define LAST_COUNTRY_ID 254
#define SOUTH_SUDAN_ID  254

static int failures = 0;
static int checks = 0;

static void check(int ok, const char *what, const char *detail)
{
	checks++;
	if ( ! ok )
	{
		failures++;
		printf("FAIL %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	}
}

/* Countries chosen because the network belongs to an organisation that does
 * not move: a regional registry's own network, or a national ISP. No anycast. */
static const struct { const char *addr; const char *code; } known[] = {
	{ "193.0.6.139",   "NL" }, /* RIPE NCC's own network, Amsterdam */
	{ "202.12.29.205", "AU" }, /* APNIC's own network, Brisbane */
	{ "199.212.0.46",  "US" }, /* ARIN's own network */
	{ "151.1.1.1",     "IT" }, /* Wind Tre, Italian ISP */
};

/* Loopback, private, "this network" and broadcast: no country. */
static const char *no_country[] = {
	"127.0.0.1", "10.1.2.3", "192.168.178.88", "0.0.0.1", "255.255.255.255",
};

int main(int argc, char **argv)
{
	GeoIP *gi;
	unsigned long long ip;
	int seen_south_sudan = 0;
	int bad_ids = 0;
	char detail[128];
	size_t i;

	if ( argc != 2 )
	{
		fprintf(stderr, "usage: %s <GeoIP.dat>\n", argv[0]);
		return 2;
	}

	gi = GeoIP_open(argv[1], GEOIP_MEMORY_CACHE);
	if ( gi == NULL )
	{
		printf("FAIL cannot open %s\n", argv[1]);
		return 1;
	}

	snprintf(detail, sizeof(detail), "edition %d", GeoIP_database_edition(gi));
	check(GeoIP_database_edition(gi) == GEOIP_COUNTRY_EDITION, "database is the country edition", detail);

	/* Walk every IPv4 range once. Debian's file answers 0.0.0.0 with netmask 0,
	 * so a zero netmask advances by a /8. */
	for ( ip = 0; ip <= 0xFFFFFFFFULL; )
	{
		GeoIPLookup gl;
		int id, netmask;

		memset(&gl, 0, sizeof(gl));
		id = GeoIP_id_by_ipnum_gl(gi, (unsigned long)ip, &gl);
		netmask = gl.netmask;

		if ( id < 0 || id > LAST_COUNTRY_ID )
		{
			if ( bad_ids++ < 10 )
			{
				snprintf(detail, sizeof(detail), "%llu.%llu.%llu.%llu has id %d",
					ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, id);
				check(0, "country id inside the table", detail);
			}
		}
		if ( id == SOUTH_SUDAN_ID )
			seen_south_sudan = 1;

		if ( netmask <= 0 )
			netmask = 8;
		ip += 1ULL << (32 - netmask);
	}
	check(bad_ids == 0, "every range has a country id inside the table", NULL);
	check(seen_south_sudan, "some range returns South Sudan (id 254)", NULL);
	check(GeoIP_code_by_id(SOUTH_SUDAN_ID) != NULL && strcmp(GeoIP_code_by_id(SOUTH_SUDAN_ID), "SS") == 0,
		"id 254 reads as SS", NULL);

	for ( i = 0; i < sizeof(known) / sizeof(known[0]); i++ )
	{
		const char *code = GeoIP_country_code_by_addr(gi, known[i].addr);
		snprintf(detail, sizeof(detail), "%s gave %s, expected %s",
			known[i].addr, code ? code : "(none)", known[i].code);
		check(code != NULL && strcmp(code, known[i].code) == 0, "known address", detail);
	}

	for ( i = 0; i < sizeof(no_country) / sizeof(no_country[0]); i++ )
	{
		const char *code = GeoIP_country_code_by_addr(gi, no_country[i]);
		snprintf(detail, sizeof(detail), "%s gave %s", no_country[i], code ? code : "(none)");
		check(code == NULL, "reserved address has no country", detail);
	}

	GeoIP_delete(gi);

	if ( failures )
	{
		printf("%d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS %d checks\n", checks);
	return 0;
}
