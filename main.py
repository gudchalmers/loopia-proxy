import json
import logging
import os
import re
import sys
from xmlrpc.client import ServerProxy
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHash, VerifyMismatchError, VerificationError
from defusedxml.xmlrpc import monkey_patch
from http.server import BaseHTTPRequestHandler as http_handler
from dotmap import DotMap

# Monkey patch xmlrpc to protect it from attacks https://github.com/tiran/defusedxml
monkey_patch()

logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)
log = logging.getLogger()


def log_message(self, format, *args):
    """Overrides the logging used by the xmlrpc server with our custom one"""
    log.info("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


http_handler.log_message = log_message


class LoopiaHelper:
    def __init__(self):
        self._ph = PasswordHasher()

        # Read and hash any un-hashed passwords
        with open('config/settings.json', encoding='utf-8', mode='r+t') as f:
            self.users = DotMap(json.load(f))

            updated = False
            for name, user in self.users.items():
                try:
                    extract_parameters(user.password)
                except InvalidHash:
                    user.password = self._ph.hash(user.password)
                    updated = True

            # Update the file if we have hashed the password
            if updated:
                f.seek(0)
                json.dump(self.users.toDict(), f, indent=2)
                f.truncate()

        self.loopia = ServerProxy("https://api.loopia.se/RPCSERV")
        self._api_user = os.environ['LOOPIA_USER']
        self._api_pass = os.environ['LOOPIA_PASS']

    def _updateUser(self, username, password):
        log.debug(f"Updating user {username=}")
        self.users[username].password = self._ph.hash(password)
        with open('config/settings.json', encoding='utf-8', mode='w') as f:
            json.dump(self.users.toDict(), f, indent=2)

    # Authenticates the username against the local file
    def _auth(self, username, password):
        if username in self.users:
            try:
                user = self.users[username]
                self._ph.verify(user.password, password)

                if self._ph.check_needs_rehash(user.password):
                    self._updateUser(username, password)
                return True
            except (VerificationError, VerifyMismatchError, InvalidHash):
                pass
        return False

    # noinspection PyPep8Naming
    def getDomains(self, username, password):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        domains = self.loopia.getDomains(self._api_user, self._api_pass)
        result = []
        for domain in domains:
            if domain['domain'] in user.domains:
                result.append(domain)
        return result

    # noinspection PyPep8Naming
    def getSubdomains(self, username, password, domain):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return self.loopia.getSubdomains(self._api_user, self._api_pass, domain)

    # noinspection PyPep8Naming
    def addSubdomain(self, username, password, domain, subdomain):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return self.loopia.addSubdomain(self._api_user, self._api_pass, domain, subdomain)

    # noinspection PyPep8Naming
    def getZoneRecords(self, username, password, domain, subdomain):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return self.loopia.getZoneRecords(self._api_user, self._api_pass, domain, subdomain)

    # noinspection PyPep8Naming
    def addZoneRecord(self, username, password, domain, subdomain, record):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return self.loopia.addZoneRecord(self._api_user, self._api_pass, domain, subdomain, record)

    # noinspection PyPep8Naming
    def removeSubdomain(self, username, password, domain, subdomain):
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self.users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return self.loopia.removeSubdomain(self._api_user, self._api_pass, domain, subdomain)


class LoopiaProxyFunctions:
    _helper = LoopiaHelper()
    _domain_re = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,}$")

    def getDomains(self, username, password):
        log.info(f"getting domains for: {username}")
        return self._helper.getDomains(username, password)

    def getSubdomains(self, username, password, domain):
        # Filter out bad input
        if domain == "" or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        log.info(f"getting subdomains for: {username} -> {domain}")
        return self._helper.getSubdomains(username, password, domain)

    def getZoneRecords(self, username, password, domain, subdomain):
        # Filter out bad input
        if domain == "" or subdomain == "" or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        log.info(f"getting zone records for: {username} -> {subdomain}.{domain}")
        return self._helper.getZoneRecords(username, password, domain, subdomain)

    def addSubdomain(self, username, password, domain, subdomain):
        # Filter out bad input
        if domain == "" or subdomain == "" or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        log.info(f"adding subdomain for: {username} -> {subdomain}.{domain}")
        return self._helper.addSubdomain(username, password, domain, subdomain)

    def addZoneRecord(self, username, password, domain, subdomain, record):
        # Filter out bad input
        if domain == "" or subdomain == "" or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        log.info(f"adding zone record to subdomain for: {username} -> {subdomain}.{domain}")
        return self._helper.addZoneRecord(username, password, domain, subdomain, record)

    def removeSubdomain(self, username, password, domain, subdomain):
        # Filter out bad input
        if domain == "" or subdomain == "" or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        log.info(f"adding subdomain for: {username} -> {subdomain}.{domain}")
        return self._helper.removeSubdomain(username, password, domain, subdomain)

    def __close(self):
        self._helper.loopia("close")

    def __call__(self, attr):
        if attr == "close":
            return self.__close


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPCSERV',)

    def do_GET(self):
        """Return 404 on all GET requests"""
        self.report_404()


# Host available on POST http://localhost:8000/RPCSERV
port = int(os.environ.get('PORT', '8000'))
host = os.environ.get('HOST', 'localhost')
log.info("Starting server on: " + host + ':' + str(port))
with SimpleXMLRPCServer((host, port), RequestHandler) as server:
    server.register_introspection_functions()
    proxy = LoopiaProxyFunctions()
    server.register_instance(proxy)
    try:
        server.serve_forever()
    except KeyboardInterrupt as err:
        log.error(f"Stopping from keyboard interrupt: {err=}")
        proxy("close")
        sys.exit(0)
