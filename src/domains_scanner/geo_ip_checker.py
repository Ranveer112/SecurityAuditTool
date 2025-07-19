from utils.context_logger import ContextLoggerAdapter
from domains_scanner.domain_utils import get_ip_addresses
import geoip2.database
import maxminddb
import io
import tarfile
import requests
import os

class GeoIpChecker:
    def __init__(self, logger:ContextLoggerAdapter):
        self.logger = logger

        self.db_dir = "./geolite_ip_data"
        self.db_path = os.path.join(self.db_dir, "GeoLite2-City.mmdb")
        self.__construct_geolite_db()

    def __construct_geolite_db(self):
        func_logger = self.logger.get_child("construct_geolite_db", {})

        if os.path.isfile(self.db_path):
            return

        license_key = os.getenv("MAXMIND_LICENSE_KEY")
        if not license_key:
            func_logger.error(
                "GeoLite2 database not found and MAXMIND_LICENSE_KEY not set. Please get a license key from https://dev.maxmind.com/geoip/geolite2/ and set it as an environment variable.")
            return

        func_logger.info("Downloading GeoLite2 database...")
        url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"

        r = requests.get(url, stream=True)
        if r.status_code != 200:
            func_logger.error("Failed to download GeoLite2 database. Please check your license key.")
            return

        file_like_object = io.BytesIO(r.content)
        with tarfile.open(fileobj=file_like_object, mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("GeoLite2-City.mmdb"):
                    member.name = os.path.basename(member.name)  # strip directories
                    os.makedirs(self.db_dir, exist_ok=True)
                    tar.extract(member, self.db_dir)
                    func_logger.info("GeoLite2 database downloaded and extracted.")
                    return

        func_logger.error("GeoLite2 database not found in archive. Download may have failed.")
        return
    def get_geolocation_of_ips(self, domain_name):
        func_logger = self.logger.get_child("get_geolocation_of_ips", {'domain_name': domain_name})
        ivp4_addresses = get_ip_addresses(domain_name, "ipv4", func_logger)
        geolocations = set()
        if not os.path.isfile(self.db_path):
            func_logger.error("GeoLite2 database does not exist")
            return list(geolocations)
        with geoip2.database.Reader(self.db_path) as reader:
            for ivp4_address in ivp4_addresses:
                try:
                    response = reader.city(ivp4_address)
                    if response.city.name is not None and response.country.name is not None:
                        geolocations.add(response.city.name + ", " + response.country.name)
                    elif response.city.name is not None:
                        geolocations.add(response.city.name)
                    elif response.country.name is not None:
                        geolocations.add(response.country.name)

                except geoip2.errors.AddressNotFoundError:
                    func_logger.warning("Geolocation for IP " + ivp4_address + " not found in database.")
                except maxminddb.InvalidDatabaseError:
                    func_logger.error("Database file for geolocation is corrupted")
        return list(geolocations)
