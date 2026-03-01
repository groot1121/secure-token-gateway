import geoip2.database

reader = geoip2.database.Reader("app/GeoLite2-City.mmdb")

def get_geo(ip):

    if ip == "127.0.0.1":
        return None

    try:
        response = reader.city(ip)

        return {
            "country": response.country.name,
            "city": response.city.name,
            "lat": response.location.latitude,
            "lon": response.location.longitude
        }

    except Exception:
        return None