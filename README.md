# PfsenseAPI Client

A Python client for interacting with the pfSense web interface. This library provides programmatic access to pfSense's user management, VPN configuration, and certificate management features.

## Features

- User Management
  - Create new users with certificates
  - Edit existing users
  - Remove users
  - List all users

- OpenVPN Configuration
  - Download OpenVPN bundles for users
  - Support for various client configurations (Windows, Android, iOS)
  - Bundle customization options

- Certificate Management
  - Parse and list certificates
  - Renew certificates
  - Remove certificates
  - Auto-renewal support for expiring certificates

## Installation

You can install the package using pip:

```bash
pip install pfsense-api-client
```

Or install from source:

```bash
git clone https://github.com/yourusername/pfsense-api-client.git
cd pfsense-api-client
pip install -e .
```

## Quick Start

Here's a simple example to get you started:

```python
from pfsense_api import PfsenseAPI

# Initialize the client
config = {
    "host": "your-pfsense-host",
    "username": "admin",
    "password": "your-password"
}

client = PfsenseAPI(config)

# Create a new user with certificate
client.create_user(
    user_name="newuser",
    user_password="userpass123",
    groups=["VPNUsers"],
    create_cert=True
)

# Download OpenVPN configuration for the user
client.download_openvpn_bundle(
    username="newuser",
    dest_folder="./vpn_configs",
    bundle_cat1="Current Windows Installers (2.5.2-Ix01)",
    bundle_cat2="64-bit"
)
```

## Configuration Options

The PfsenseAPI client accepts the following configuration parameters:

- `host`: Your pfSense server hostname or IP address
- `username`: Administrator username
- `password`: Administrator password

## Common Operations

### Managing Users

```python
# Create a user
client.create_user(
    user_name="newuser",
    user_password="password123",
    groups=["VPNUsers"],
    create_cert=True,
    key_type="RSA",
    key_len=4096
)

# Edit a user
client.edit_user(
    username="existinguser",
    new_password="newpass123",
    groups=["NewGroup"]
)

# Remove a user
client.remove_user("username")
```

### Managing Certificates

```python
# Renew certificates that will expire within 90 days
client.renew_certs(days_before_expiration=90)

# Renew specific user's certificate
client.renew_cert_user("username")

# Remove user's certificate
client.remove_cert_user("username")
```

### OpenVPN Configuration

```python
# Download Windows 64-bit installer
client.download_openvpn_bundle(
    username="user",
    dest_folder="./vpn_configs",
    bundle_cat1="Current Windows Installers (2.5.2-Ix01)",
    bundle_cat2="64-bit"
)

# Download Android configuration
client.download_openvpn_bundle(
    username="user",
    dest_folder="./vpn_configs",
    bundle_cat1="Inline Configurations",
    bundle_cat2="Android"
)
```

## Error Handling

The library includes several custom exceptions for specific error cases:

- `AuthenticationException`: Failed to authenticate with pfSense
- `UserAlreadyExistsError`: Attempted to create a user that already exists
- `UserNotFoundError`: User not found in the system
- `CertificateNotFoundError`: Certificate not found for the specified user
- `CertificateRenewalError`: Failed to renew certificate
- `VpnExportForUserNotFoundError`: VPN configuration not found for user

## Logging

The library uses Python's built-in logging system. You can configure the logging level and format according to your needs:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
