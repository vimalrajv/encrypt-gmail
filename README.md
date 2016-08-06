# encrypt-gmail
An application that retrieves email from Google Mailbox and stores them encrypted. The encryption used in this application is AES provided by libcrypto++.
The package restclient-cpp obtained from https://github.com/mrtazz/restclient-cpp is used for HTTP GETs and POSTs in this application.

Before using the application, you must authorize it.
Authorizing using username and password has been deprecated and current Google login is via OAuth2.

More details on this:
https://developers.google.com/gmail/api/auth/web-server
https://google.github.io/google-api-cpp-client/latest/start/get_started.html#preparation

Follow the steps in the URL - https://google.github.io/google-api-cpp-client/latest/start/get_started.html#preparation
and download the OAuth 2.0 client ID json file.
Check if the json file contains client_id & client_secret fields.

The application takes username, the OAuth Client ID json, date after, date before as arguments.


INSTALL:
Pre-requisites:

The following packages are required:
curl
libcurlpp-dev
libcurl3
libboost1.58-all-dev
libboost1.58-dev
libcrypto++-dev
libcrypto++9v5
Note: libcrypto++ include files are from /usr/include/crypto++. If your libcrypto++ installation is elsewhere please provide the right path in Makefile.

RUN:
Run make in the source folder
Run the executable 'Main' along with by the parameters
- Usage ./Main <username@gmail.com>  <client_secret_json> <DateAfter> <DateBefore> [-verbose]
