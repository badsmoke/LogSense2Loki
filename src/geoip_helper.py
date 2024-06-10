import geoip2.database
from unidecode import unidecode

class GeoIPHelper:
    def __init__(self, geoip_db_path):
        self.reader = geoip2.database.Reader(geoip_db_path)

    def get_city(self, ip_address):
        try:
            response = self.reader.city(ip_address)
            city = response.city.name
            country = response.country.name
            country_code = response.country.iso_code
            geohash_code = geohash.encode(latitude, longitude)
            organization = response.traits.organization

            # Rewrite city and country names with umlauts
            if city:
                city = unidecode(city)
            if country:
                country = unidecode(country)

            return {
                "ip": ip_address,
                "city": city,
                "country": country,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "country_code": country_code,
                "geohash": geohash_code,
                "organization": organization
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                "ip": ip_address,
                "city": "Unknown",
                "country": "Unknown",
                "latitude": None,
                "longitude": None,
                "country_code": None,
                "geohash": None,
                "organization": None
            }