# pylint: disable=too-many-instance-attributes,too-many-locals
import json
import os
import re
from urllib.parse import parse_qs
from datetime import datetime, timedelta
import requests
import urllib3
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tmma_automation.tools.logger import Logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class AuthenticationException(Exception): ...
class UserAlreadyExistsError(Exception):...
class VpnExportForUserNotFoundError(Exception): ...
class UserNotFoundError(Exception): ...
class CertificateNotFoundError(Exception): ...
class CertificatRenewalError(Exception): ...
class CertificatesParsingError(Exception): ...

class PfsenseAPI:
    client_export_choices = {
        "Inline Configurations": {
            "Most Clients": "confinline",
            "Android": "confinlinedroid",
            "OpenVPN Connect (iOS/Android)": "confinlineios",
        },
        "Bundled Configurations": {"Archive": "confzip", "Config File Only": "conf"},
        "Current Windows Installers (2.5.2-Ix01)": {
            "64-bit": "inst-x64-msi",
            "32-bit": "inst-x86-msi",
        },
        "Legacy Windows Installers (2.4.11-Ix01)": {
            "10/2016/2019": "inst-Win10",
            "7/8/8.1/2012r2": "inst-Win7",
        },
        "Viscosity (Mac OS X and Windows)": {
            "Viscosity Bundle": "visc",
            "Viscosity Inline Config": "confinlinevisc",
        },
    }

    def __init__(self, config):
        self.host = config.get("host")
        self.base_url = f"https://{self.host}"
        self.curr_url = None
        self.username = config.get("username")
        self.password = config.get("password")
        if not self.username:
            raise Exception("Username not found in config!")
        if not self.password:
            raise Exception("Password not found in config!")
        # Create a Retry object with desired settings
        retry_strategy = Retry(
            total=3,  # Number of maximum retry attempts
            backoff_factor=1,  # Factor to apply between retries (exponential backoff)
            status_forcelist=[500, 502, 503, 504],  # HTTP status codes to retry on
        )
        # Create an HTTPAdapter with the Retry object
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        # Mount the adapter to the session
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.csrf_token = None
        self.login(self.username, self.password)
        self.users_certs = {}

    def go_to_page(self, page_url):
        Logger().debug(f'moving to page {page_url}')
        response = self.session.get(page_url, verify=False)
        if response.status_code != 200:
            raise Exception(f"Failed to load page at {page_url}")
        soup = BeautifulSoup(response.content, "html.parser")
        crf_magic_elem = soup.find("input", {"name": "__csrf_magic"})
        if crf_magic_elem is None:
            csrf_token_pattern = re.compile(r'var csrfMagicToken = "(.*?)";')
            # Search for the CSRF token in the response text
            match = csrf_token_pattern.search(response.text)
            if match:
                self.csrf_token = match.group(1)
            else:
                raise Exception(f"Failed to find CSRF token on page at {page_url}")
        else:
            self.csrf_token = crf_magic_elem["value"]
        self.curr_url = page_url
        return soup

    def login(self, username, password):
        self.username = username
        self.password = password
        Logger().debug(f"Logging in to pfSense. Username: {username}")
        login_url = f"{self.base_url}/index.php"
        self.go_to_page(login_url)

        payload = {
            "__csrf_magic": self.csrf_token,
            "usernamefld": username,
            "passwordfld": password,
            "login": "Sign In",
        }

        Logger().debug("Logging in to pfSense...")
        response = self.session.post(login_url, data=payload, verify=False)
        if response.status_code == 200:
            if "Username or Password incorrect" in response.text:
                raise Exception(
                    "Login to pfsense failed: Username or Password incorrect."
                )
            if "Dashboard" in response.text:
                Logger().debug("Landed on the Dashboard : Logged in to pfSense successfully.")
                return True
            raise AuthenticationException("Auth failed!")
        raise Exception("Login to pfsense failed!")

    def extract_users(self, soup):
        # Find the table body within the specified selector
        table_body = soup.select_one(
            "#\\32 > div > form > div > div.panel-body > div > table > tbody"
        )

        # Initialize an empty list to hold user information
        users = []

        # Iterate over each row in the table body
        for row in table_body.find_all("tr"):
            # Extract username, user ID, and the full name
            username = row.find("td").find_next_sibling("td").text.strip()
            full_name = row.find_all("td")[2].text.strip()
            user_id = row.find("input", {"name": "delete_check[]"}).get("value")

            # Append this user's information to the users list
            users.append(
                {"username": username, "full_name": full_name, "user_id": user_id}
            )

        return users

    def parse_users_export(self, soup):
        pattern = r"servers\[(\d+)\]\[1]\[(\d+)\]\[(\d+)\]\s*=\s*'([^']+)';"
        matches = re.findall(pattern, soup.prettify())
        certs = {}
        for match in matches:
            server_id, user_enum, field_idx, field_value = match
            user_enum = int(user_enum)
            server_id = int(server_id)
            if server_id not in certs:
                certs[server_id] = {}
            if user_enum not in certs[server_id]:
                certs[server_id][user_enum] = {
                    "server_id": server_id,
                    "user_id": None,
                    "cert_id": None,
                    "username": None,
                    "cert_name": None,
                }
            if field_idx == "0":
                certs[server_id][user_enum]["user_id"] = int(field_value)
            elif field_idx == "1":
                certs[server_id][user_enum]["cert_id"] = int(field_value)
            elif field_idx == "2":
                certs[server_id][user_enum]["username"] = field_value
            elif field_idx == "3":
                certs[server_id][user_enum]["cert_name"] = field_value
        return certs

    def download_openvpn_bundle(
        self,
        username,
        dest_folder,
        bundle_cat1="Current Windows Installers (2.5.2-Ix01)",
        bundle_cat2="64-bit",
    ):
        if bundle_cat1 not in self.client_export_choices:
            raise ValueError(
                f"Invalid bundle category 1: {bundle_cat1}, available choices: {self.client_export_choices.keys()}"
            )
        if bundle_cat2 not in self.client_export_choices[bundle_cat1]:
            raise ValueError(
                f"Invalid bundle category 2: {bundle_cat2}, available choices: {self.client_export_choices[bundle_cat1].keys()}"
            )
        download_url = f"{self.base_url}/vpn_openvpn_export.php"
        page_soup = self.go_to_page(download_url)
        Logger().debug(f"looking for user: {username}")
        if username in page_soup.prettify():
            Logger().debug("User found in the page text.")
        else:
            with open("vpn_openvpn_export.html", "w") as file:
                file.write(page_soup.prettify())
            raise VpnExportForUserNotFoundError(f"User {username} not found.")
        server_certs = self.parse_users_export(page_soup)
        # save users to a file
        with open("users_openvpn_export.json", "w") as file:
            json.dump(server_certs, file, indent=2)
        for user in server_certs[2].values():
            if user["username"] == username:
                break
        else:
            raise VpnExportForUserNotFoundError(f"User {username} not found.")
        Logger().debug("Found user: ", user)
        client_export_choice = self.client_export_choices[bundle_cat1][bundle_cat2]
        post_data = {
            "act": client_export_choice,
            "srvid": str(user["server_id"]),
            "usrid": str(user["user_id"]),
            "useaddr": "serveraddr",
            "crtid": str(user["cert_id"]),
            "verifyservercn": "auto",
            "__csrf_magic": self.csrf_token,
        }
        Logger().debug("Downloading client config...")
        response = self.session.post(download_url, data=post_data, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            error_div = soup.find("div", {"class": "alert alert-danger input-errors"})
            if error_div:
                error_text = error_div.get_text(strip=True)
                raise Exception(error_text)
            filename = response.headers["Content-Disposition"].split("filename=")[1]
            #create dest folder if it doesn't exist
            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)
            dest_filepath = os.path.join(dest_folder, filename)
            with open(dest_filepath, "wb") as file:
                file.write(response.content)
            Logger().debug("Download successful.")
            return dest_filepath
        Logger().debug("Download failed.")
        return None

    def download_openvpn_bundle2(
        self,
        username,
        bundle_cat1="Current Windows Installers (2.5.2-Ix01)",
        bundle_cat2="64-bit",
    ):
        if bundle_cat1 not in self.client_export_choices:
            raise ValueError(
                f"Invalid bundle category 1: {bundle_cat1}, available choices: {self.client_export_choices.keys()}"
            )
        if bundle_cat2 not in self.client_export_choices[bundle_cat1]:
            raise ValueError(
                f"Invalid bundle category 2: {bundle_cat2}, available choices: {self.client_export_choices[bundle_cat1].keys()}"
            )
        download_url = f"{self.base_url}/vpn_openvpn_export.php"
        page_soup = self.go_to_page(download_url)
        Logger().debug(f"looking for user: {username}")
        if username in page_soup.prettify():
            Logger().debug("User found in the page text.")
        else:
            with open("vpn_openvpn_export.html", "w") as file:
                file.write(page_soup.prettify())
            raise VpnExportForUserNotFoundError(f"User {username} not found.")
        server_certs = self.parse_users_export(page_soup)

        with open("users_openvpn_export.json", "w") as file:
            json.dump(server_certs, file, indent=2)
        for user in server_certs[2].values():
            if user["username"] == username:
                break
        else:
            raise VpnExportForUserNotFoundError(f"User {username} not found.")
    
        Logger().debug("Found user: ", user)
        client_export_choice = self.client_export_choices[bundle_cat1][bundle_cat2]
        post_data = {
            "act": client_export_choice,
            "srvid": str(user["server_id"]),
            "usrid": str(user["user_id"]),
            "useaddr": "serveraddr",
            "crtid": str(user["cert_id"]),
            "verifyservercn": "auto",
            "__csrf_magic": self.csrf_token,
        }
        Logger().debug("Downloading client config...")
        response = self.session.post(download_url, data=post_data, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            error_div = soup.find("div", {"class": "alert alert-danger input-errors"})
            if error_div:
                error_text = error_div.get_text(strip=True)
                raise Exception(error_text)
            return response
        Logger().debug("Download failed.")
        return None
    
    def create_user(
        self,
        user_name,
        user_password,
        groups=None,
        caref="5416cb7f08e9d",
        key_type="RSA",
        key_len=4096,
        ec_name="prime256v1",
        digest_alg="sha256",
        lifetime=365,
        create_cert=True,
    ):
        if groups is None:
            groups = []
        soup = self.go_to_page(f"{self.base_url}/system_usermanager.php")
        users = self.extract_users(soup)
        user = next((user for user in users if user["username"] == user_name), None)
        if user is not None:
            raise UserAlreadyExistsError(f"User {user_name} already exists.")
        self.go_to_page(f"{self.base_url}/system_usermanager.php?act=new")
        post_data = {
            "__csrf_magic": self.csrf_token,
            "usernamefld": user_name,
            "passwordfld1": user_password,
            "passwordfld2": user_password,
            "descr": user_name,
            "expires": "",
            "groups[]": groups,
            "name": user_name,
            "caref": caref,
            "webguicss": "pfSense.css",
            "webguifixedmenu": "",
            "webguihostnamemenu": "",
            "dashboardcolumns": "2",
            "keytype": key_type,
            "keylen": str(key_len),
            "ecname": ec_name,
            "digest_alg": digest_alg,
            "lifetime": lifetime,
            "userid": "",
            "certid": "",
            "utype": "user",
            "oldusername": "",
            "save": "Save",
        }
        if create_cert:
            post_data["showcert"] = "yes"
        Logger().debug("Creating user...")
        response = self.session.post(
            f"{self.base_url}/system_usermanager.php?act=new", data=post_data, verify=False
        )
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            error_div = soup.find("div", {"class": "alert alert-danger input-errors"})
            if error_div:
                error_text = error_div.get_text(strip=True)
                if "already exists" in error_text:
                    raise UserAlreadyExistsError("User already exists.")
                raise Exception(error_text)
            Logger().debug("User created successfully.")
            return True

        raise Exception("User creation failed.")

    def edit_user(self, username, new_password, groups=None):
        if groups is None:
            groups = []
        soup = self.go_to_page(f"{self.base_url}/system_usermanager.php")
        users = self.extract_users(soup)
        Logger().debug(f"looking for user: {username}")
        user = next((user for user in users if user["username"] == username), None)
        if user is None:
            raise Exception(f"User {username} not found.")
        Logger().debug(f"Found user: {user}")
        user_edit_url = (
            f"{self.base_url}/system_usermanager.php?act=edit&userid={user['user_id']}"
        )
        soup = self.go_to_page(user_edit_url)
        Logger().debug("Editing user...")
        post_data = {
            "__csrf_magic": self.csrf_token,
            "usernamefld": username,
            "passwordfld1": new_password,
            "passwordfld2": new_password,
            "descr": username,
            "name": username,
            "userid": user["user_id"],
            "certid": "",
            "utype": "user",
            "oldusername": username,
            "save": "Save",
        }
        response = self.session.post(user_edit_url, data=post_data, verify=False)
        if response.status_code == 200:
            Logger().debug("User edited successfully.")
        else:
            Logger().debug("User edition failed.")

    def remove_user(self, username):
        remove_user_url = f"{self.base_url}/system_usermanager.php"
        soup = self.go_to_page(remove_user_url)
        link = soup.find(
            "a",
            href=lambda href: href
            and f"username={username}" in href
            and "act=deluser" in href,
        )
        if not link:
            raise UserNotFoundError(f"User {username} not found.")
        post_data = parse_qs(link["href"].lstrip("?"))
        post_data["__csrf_magic"] = self.csrf_token
        response = self.session.post(remove_user_url, data=post_data, verify=False)
        if response.status_code == 200:
            if f"Successfully deleted user: {username}" in response.text:
                Logger().debug("User removed successfully.")
            else:
                Logger().debug("User removal failed!")
        else:
            Logger().debug("User removal failed!")

    @staticmethod
    def parse_certificates(html_soup):
        Logger().debug("Parsing certificates...")
        tbody = html_soup.find('table').find('tbody')
        if not tbody:
            raise CertificatesParsingError("Table body not found")

        certificates = []

        # Iterate over each row in the table body
        for tr in tbody.find_all("tr"):
            cert_info = {}

            # Attempt to extract user name and certificate type from the first td
            tds = tr.find_all("td")
            if tds:
                first_td = tds[0]
                user_name = first_td.contents[0].strip() if first_td.contents else "Unknown"
                cert_type = first_td.find("i").text.strip() if first_td.find("i") else "Unknown"
                cert_info["user_name"] = user_name
                cert_info["cert_type"] = cert_type

                # Parsing Valid From and Valid Until
                date_info_td = tds[2]  # Assuming the dates are in the third <td>
                certificate_text = date_info_td.get_text(strip=True)
                patterns = {
                    "Serial": r"Serial:(\d+)",
                    "Signature Digest": r"Signature Digest:(RSA-SHA\d+)",
                    "SAN": r"SAN:(DNS:[^,]+,?\s*email:[^\s<]+)",
                    "KU": r"KU:([^\n]+?Encipherment)",
                    "EKU": r"EKU:([^\n]+?Authentication)",
                    "Key Type": r"Key Type:(\w+)",
                    "Key Size": r"Key Size:(\d+)",
                    "DN": r"DN:([^H]+)Hash",
                    "Hash": r"Hash:([\da-f]+)",
                    "Subject Key ID": r"Subject Key ID:([^\n]+?)(?=Authority)",
                    "Authority Key ID": r"Authority Key ID:([^\n]+?)(?=DirName)",
                    "DirName": r"DirName:(/[^\n]+)(?=serial)",
                    "Total Lifetime": r"Total Lifetime:(\d+ days)",
                    "Lifetime Remaining": r"Lifetime Remaining:([^\n]+?)(?=Valid)",
                    "Valid From": r"Valid From:([^\n]+?)(?=Valid Until)",
                    "Valid Until": r"Valid Until:([^\n]+)",
                }

                for key, pattern in patterns.items():
                    match = re.search(pattern, certificate_text)
                    if match:
                        cert_info[key] = match.group(1).strip()
                # Extracting the renewal link, assuming it's in the last <td>
                renewal_td = tds[-1]  # Get the last <td> which contains the links
                renewal_link = renewal_td.find("a", class_="fa fa-repeat")
                if renewal_link and "href" in renewal_link.attrs:
                    href = renewal_link.attrs["href"]
                    cert_info["renewal_link"] = href
                    # Parse out the type and refid from the link
                    link_parts = href.split("?")[-1].split("&")
                    for part in link_parts:
                        key, value = part.split("=")
                        cert_info[key] = value

            certificates.append(cert_info)
        Logger().debug("Certificates parsed successfully.")
        return certificates

    @staticmethod
    def is_about_to_expire(cert_info, days_before_expiration):
        """
        Check if the certificate is about to expire within the given days before expiration.

        :param cert_info: Dictionary containing certificate information, including 'Valid Until'.
        :param days_before_expiration: Number of days to check if the certificate is about to expire.
        :return: True if the certificate is about to expire within the specified days and has not expired yet; False otherwise.
        """
        valid_until_str = cert_info.get("Valid Until")
        if not valid_until_str:
            Logger().debug("Valid Until date is missing from the certificate info.")
            return False

        # Parse the Valid Until date string into a datetime object
        try:
            valid_until = datetime.strptime(valid_until_str, "%a, %d %b %Y %H:%M:%S %z")
        except ValueError as exc:
            raise Exception(f"Error parsing Valid Until date: {exc}") from exc

        current_time = datetime.now(tz=valid_until.tzinfo)
        expiration_threshold = current_time + timedelta(days=days_before_expiration)

        # Check if the certificate is about to expire and has not already expired
        if current_time < valid_until <= expiration_threshold:
            return True
        return False

    def renew_cert(self, cert):
        Logger().debug(f"Renewing certificate for user {cert['user_name']}")
        post_data = {
            "__csrf_magic": self.csrf_token,
            "reusekey": "yes",
            "refid": cert["refid"],
            "type": "cert",
            "renew": "Renew/Reissue",
        }
        self.go_to_page(f"{self.base_url}/{cert['renewal_link']}")
        response = self.session.post(f"{self.base_url}/{cert['renewal_link']}", data=post_data, verify=False)
        if response.status_code != 200:
            raise CertificatRenewalError(f"Failed to renew certificate for user {cert['user_name']}")
        Logger().debug(f"Certificate for user {cert['user_name']} renewed successfully.")

    def remove_cert(self, cert):
        Logger().debug(f"Removing certificate for user {cert['user_name']}")
        post_data = {
            "__csrf_magic": self.csrf_token,
            "act": "del",
            "id": cert["refid"]
        }
        response = self.session.post(self.curr_url, data=post_data, verify=False)
        if response.status_code != 200:
            raise Exception(f"Failed to remove certificate for user {cert['user_name']}")
        Logger().debug(f"Certificate for user {cert['user_name']} removed successfully.")

    def remove_cert_user(self, username):
        renew_cert_url = f"{self.base_url}/system_certmanager.php"
        soup = self.go_to_page(renew_cert_url)
        self.users_certs = self.parse_certificates(soup)
        with open("users_certificates.json", "w") as file:
            json.dump(self.users_certs, file, indent=2)
        for cert in self.users_certs:
            if cert['user_name'] == username:
                self.remove_cert(cert)
                return
        raise CertificateNotFoundError(f"Certificate for user {username} not found.")

    def renew_certs(self, days_before_expiration=30 * 3):
        renew_cert_url = f"{self.base_url}/system_certmanager.php"
        soup = self.go_to_page(renew_cert_url)
        self.users_certs = self.parse_certificates(soup)
        with open("users_certificates.json", "w") as file:
            json.dump(self.users_certs, file, indent=2)
        for cert in self.users_certs:
            if self.is_about_to_expire(cert, days_before_expiration):
                self.renew_cert(cert)

    def renew_cert_user(self, username):
        renew_cert_url = f"{self.base_url}/system_certmanager.php"
        soup = self.go_to_page(renew_cert_url)
        self.users_certs = self.parse_certificates(soup)
        with open("users_certificates.json", "w") as file:
            json.dump(self.users_certs, file, indent=2)
        for cert in self.users_certs:
            if cert["user_name"] == username:
                self.renew_cert(cert)
                return
        raise CertificateNotFoundError(f"Certificate for user {username} not found.")
