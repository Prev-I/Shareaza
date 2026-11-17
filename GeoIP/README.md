# GeoIP

IP-to-country lookup for the client: `geoip.dll`, built from MaxMind's legacy GeoIP C library,
and the country database it reads, `GeoIP.dat`.

## Library

- Upstream: [maxmind/geoip-api-c](https://github.com/maxmind/geoip-api-c), tag `v1.6.12`,
  commit `4b526e7331ca1d692b74a0509ddcc725622ed31a`, directory `libGeoIP/`.
- The `.c` and `.h` files here are copied from that commit unmodified. Windows settings
  (`GEOIP_EXPORTS`, `PACKAGE_VERSION`, warnings) live in `GeoIP_143.vcxproj`.
- Licence: LGPL 2.1, in `License.txt` (upstream's `COPYING`). The upstream project is archived;
  1.6.12 is its last release.

## Database

- `GeoIP.dat` is Debian's `geoip-database` build of DB-IP's free country database
  (CC BY 4.0), in the legacy GeoIP country format. IPv4 only.
- `SOURCE.txt` records the Debian package version, the hashes and the signing key it was verified
  against.
- `refresh.sh` fetches and verifies a newer one; run it through the `geoip-refresh.yml` workflow
  before a release (see `docs/RELEASING.md`). `tests/geoip/` checks the file.
