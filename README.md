# PfsenseAPI Module

The PfsenseAPI module is a Python library that simplifies interaction with the pfSense firewall's web interface. It provides a convenient way to automate common tasks such as user management, certificate management, and OpenVPN client configuration downloads.

## Features

- User Management:
  - Create new users with customizable attributes
  - Edit existing users
  - Remove users
- Certificate Management:  
  - Parse and retrieve certificate information
  - Check if certificates are about to expire
  - Renew certificates
  - Remove certificates
- OpenVPN Client Configuration:
  - Download OpenVPN client configuration bundles
  - Customize bundle categories and options
- Robust Error Handling:
  - Custom exceptions for specific error scenarios
  - Detailed error messages for easier debugging
- Logging:
  - Built-in logging for tracking module actions and errors
- Session Management:
  - Automatic handling of authentication and CSRF tokens
  - Retry mechanism for handling network failures

## Installation

1. Clone the repository or download the module files.
2. Install the required dependencies:
   ```
   pip install requests beautifulsoup4
   ```
3. Import the PfsenseAPI class in your Python script:
   ```python
   from pfsense_api import PfsenseAPI
   ```

## Usage

1. Create an instance of the PfsenseAPI class:
   ```python
   pfsense = PfsenseAPI()
   ```
2. Use the available methods to interact with pfSense. For example:
   - Create a new user:
     ```python
     pfsense.create_user(user_name, user_password)
     ```
   - Download an OpenVPN client configuration bundle:
     ```python
     pfsense.download_openvpn_bundle(username, dest_folder)  
     ```
   - Renew certificates that are about to expire:
     ```python
     pfsense.renew_certs(days_before_expiration=90)
     ```

Refer to the module's docstrings and inline comments for detailed information on each method's parameters and usage.

## Configuration

The module relies on a `Settings` class to retrieve the pfSense configuration. Make sure to properly set up the `Settings` class with the correct host, username, and password for your pfSense instance.

## Error Handling

The module raises custom exceptions for specific error scenarios. Catch these exceptions in your code to handle errors gracefully. The available exceptions include:
- `UserAlreadyExistsError`
- `VpnExportForUserNotFoundError`
- `UserNotFoundError` 
- `CertificateNotFoundError`
- `CertificatRenewalError`
- `CertificatesParsingError`

## Logging

The module uses the `Logger` class for logging. Log messages are generated for important actions and errors. You can customize the logging behavior by modifying the `Logger` class.

## Contributing

Contributions to the PfsenseAPI module are welcome! If you find any bugs, have suggestions for improvements, or want to add new features, please open an issue or submit a pull request on the GitHub repository.

## License

This module is open-source and available under the [MIT License](https://opensource.org/licenses/MIT).
