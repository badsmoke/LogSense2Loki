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

            # Stadt- und Ländernamen mit Umlauten umschreiben
            if city:
                city = unidecode(city)
            if country:
                country = unidecode(country)

            return {
                "ip": ip_address,
                "city": city,
                "country": country,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                "ip": ip_address,
                "city": "Unknown",
                "country": "Unknown",
                "latitude": None,
                "longitude": None
            }