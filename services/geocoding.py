"""
This module handles geocoding functionality:
  - It normalizes and validates county names.
  - If the provided county value is not standard, it performs a geocoding lookup using a targeted query.
"""

import logging
import re
import unicodedata
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

VALID_COUNTIES = [
    'Alba', 'Arad', 'Arges', 'Bacau', 'Bihor', 'Bistrita-Nasaud', 'Botosani', 'Brasov', 
    'Braila', 'Buzau', 'Caras-Severin', 'Cluj', 'Constanta', 'Covasna', 'Dambovita', 'Dolj', 
    'Galati', 'Giurgiu', 'Gorj', 'Harghita', 'Hunedoara', 'Ialomita', 'Iasi', 'Ilfov', 
    'Maramures', 'Mehedinti', 'Mures', 'Neamt', 'Olt', 'Prahova', 'Satu Mare', 'Salaj', 
    'Sibiu', 'Suceava', 'Teleorman', 'Timis', 'Tulcea', 'Vaslui', 'Valcea', 'Vrancea', 'Bucuresti'
]

def get_geolocator(smartbill_email):
    """
    Returns a Nominatim geolocator instance with a dynamic user agent.
    The user agent is constructed using "FacturioApp" and the provided smartbill email.
    """
    user_agent = f"FacturioApp {smartbill_email}"
    return Nominatim(user_agent=user_agent)

def normalize_county(county):
    """
    Normalize a county name by removing diacritical marks, extra spaces,
    and capitalizing it properly.
    """
    normalized = unicodedata.normalize('NFKD', county).encode('ASCII', 'ignore').decode('ASCII')
    normalized = normalized.strip().capitalize()
    logger.debug("Normalized county '%s' to '%s'.", county, normalized)
    return normalized

def validate_county(raw_county, client_address, smartbill_email):
    """
    Validates the county value from client_address.
    If the raw county is provided and recognized, it returns the normalized version.
    Otherwise, it attempts a geocoding lookup using postal code and country, then city and country.
    """
    if raw_county:
        normalized = normalize_county(raw_county)
        if normalized.lower() in [vc.lower() for vc in VALID_COUNTIES]:
            logger.debug("Provided county '%s' is recognized as standard.", normalized)
            return normalized
        else:
            logger.info("County '%s' not recognized as standard. Attempting geocoding lookup.", normalized)
    else:
        logger.info("No county provided. Attempting geocoding lookup.")

    geolocator = get_geolocator(smartbill_email)

    # Strategy 1: Lookup using postal code and country.
    postal_code = client_address.get('postal_code', '')
    country = client_address.get('country', '')
    query_address = ', '.join([postal_code, country]).strip(', ')
    logger.debug("Attempting geocoding lookup using postal code: '%s'.", query_address)

    try:
        location = geolocator.geocode(query_address, addressdetails=True)
        if location:
            address_data = location.raw.get('address', {})
            geocoded_county = address_data.get('county') or address_data.get('state') or address_data.get('region') or None
            if geocoded_county:
                normalized_geo = normalize_county(geocoded_county)
                logger.info("Postal code lookup returned county: '%s'.", normalized_geo)
                return normalized_geo
        else:
            logger.warning("Postal code lookup for '%s' returned no result.", query_address)
    except Exception as e:
        logger.exception("Exception during postal code lookup for '%s': %s", query_address, e)

    # Strategy 2: Lookup using city and country.
    city = client_address.get('city', '')
    query_address = ', '.join([city, country]).strip(', ')
    logger.debug("Attempting geocoding lookup using city: '%s'.", query_address)
    try:
        location = geolocator.geocode(query_address, addressdetails=True)
        if location:
            address_data = location.raw.get('address', {})
            geocoded_county = address_data.get('county') or address_data.get('state') or address_data.get('region') or 'Unknown County'
            normalized_geo = normalize_county(geocoded_county)
            logger.info("City lookup returned county: '%s'.", normalized_geo)
            return normalized_geo
        else:
            logger.error("City lookup for '%s' returned no result.", query_address)
    except Exception as e:
        logger.exception("Exception during city lookup for '%s': %s", query_address, e)

    fallback = normalized if raw_county else 'Unknown County'
    logger.error("All geocoding lookups failed. Falling back to '%s'.", fallback)
    return fallback

def resolve_county_and_city(client_address, smartbill_email):
    """
    Determines and validates the county and adjusts the city for the given client address.
    For Bucharest, forces county to 'Bucuresti' and attempts to extract the sector.
    For other addresses, uses validate_county to obtain a standard county value.
    Returns a tuple: (county, city)
    """
    city = client_address.get('city', 'Unknown City')
    country = client_address.get('country', 'Unknown Country')
    line1 = client_address.get('line1', '')
    line2 = client_address.get('line2', '')
    postal_code = client_address.get('postal_code', '')

    if city.lower() in ['bucuresti', 'bucurești']:
        county = "Bucuresti"
        sector = None
        sector_pattern = re.compile(r'Sector\s*\d+', re.IGNORECASE)
        for field in [line1, line2]:
            if field:
                match = sector_pattern.search(field)
                if match:
                    sector = match.group()
                    break
        if sector:
            city = sector
            logger.info("Bucharest address: sector found: '%s'.", sector)
        else:
            logger.info("Bucharest address: no sector found. Using 'Unknown Sector'.")
            city = "Unknown Sector"
        return county, city
    else:
        raw_county = client_address.get('state', '')
        county = validate_county(raw_county, client_address, smartbill_email)
        logger.debug("Resolved county: '%s' and city: '%s' for address: %s", county, city, client_address)
        return county, city
