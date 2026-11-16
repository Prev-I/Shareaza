#!/usr/bin/env bash
# Runs every GeoIP check on the bundled database and the refresh script (from the repository root).
set -euo pipefail
gcc -std=gnu99 -Wall -DPACKAGE_VERSION='"1.6.12"' -DGEOIPDATADIR='"/tmp"' -I GeoIP \
	-o /tmp/test_geoip tests/geoip/test_geoip.c GeoIP/GeoIP.c GeoIP/GeoIPCity.c \
	GeoIP/GeoIP_deprecated.c GeoIP/regionName.c GeoIP/timeZone.c
/tmp/test_geoip GeoIP/GeoIP.dat
bash tests/geoip/check_source.sh
bash tests/geoip/test_refresh.sh
bash tests/geoip/check_installer.sh
