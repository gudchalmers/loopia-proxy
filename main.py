import json
import logging
import os
import re
import sys
from http.server import BaseHTTPRequestHandler as httpHandler
from xmlrpc.client import ServerProxy
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHash, VerifyMismatchError, VerificationError
from defusedxml.xmlrpc import monkey_patch
from dotmap import DotMap

# Monkey patch xmlrpc to protect it from attacks https://github.com/tiran/defusedxml
monkey_patch()

logging.basicConfig(stream=sys.stdout, format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)
log = logging.getLogger()


def log_message(self, format, *args):
    """Overrides the logging used by the xmlrpc server with our custom one"""
    log.info("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


httpHandler.log_message = log_message


class LoopiaProxyFunctions:
    # Regex to validate domains
    _domain_re = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,}$")

    def __init__(self):
        self._ph = PasswordHasher()

        # Read and hash any un-hashed passwords
        with open('config/settings.json', encoding='utf-8', mode='r+t') as f:
            self._users = DotMap(json.load(f))

            updated = False
            for name, user in self._users.items():
                try:
                    extract_parameters(user.password)
                except InvalidHash:
                    user.password = self._ph.hash(user.password)
                    updated = True

            # Update the file if we have hashed the password
            if updated:
                f.seek(0)
                json.dump(self._users.toDict(), f, indent=2)
                f.truncate()

        self._loopia = ServerProxy("https://api.loopia.se/RPCSERV")
        self._api_user = os.environ['LOOPIA_USER']
        self._api_pass = os.environ['LOOPIA_PASS']

    def _updateUser(self, username, password):
        log.debug(f"Updating user {username=}")
        self._users[username].password = self._ph.hash(password)
        with open('config/settings.json', encoding='utf-8', mode='w') as f:
            json.dump(self._users.toDict(), f, indent=2)

    # Authenticates the username against the local file
    def _auth(self, username, password):
        if username in self._users:
            try:
                user = self._users[username]
                self._ph.verify(user.password, password)

                if self._ph.check_needs_rehash(user.password):
                    self._updateUser(username, password)
                return True
            except (VerificationError, VerifyMismatchError, InvalidHash):
                pass
        return False

    def _checkAndRun(self, username, password, domain, subdomain, func):
        # Filter out bad input
        if domain == "" or (subdomain is not None and subdomain == "") or not self._domain_re.match(domain):
            return ["BAD_INDATA"]

        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self._users[username]
        if domain not in user.domains:
            return ["UNKNOWN_ERROR"]

        return func()

    def getDomains(self, username, password):
        """Returns a list of domains that the account has access to"""
        log.info(f"getting domains: {username}")
        if not self._auth(username, password):
            return ["AUTH_ERROR"]

        user = self._users[username]
        domains = self._loopia.getDomains(self._api_user, self._api_pass)
        result = []
        for domain in domains:
            if domain['domain'] in user.domains:
                result.append(domain)
        return result

    def getSubdomains(self, username, password, domain):
        """Returns a list of subdomains on the provided domain"""
        log.info(f"getting subdomains: {username} -> {domain}")
        return self._checkAndRun(username, password, domain, None,
                                 lambda: self._loopia.getSubdomains(self._api_user, self._api_pass, domain))

    def getZoneRecords(self, username, password, domain, subdomain):
        """Returns a list of zone records for the provided subdomain on the provided domain"""
        log.info(f"getting zone records: {username} -> {subdomain}.{domain}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.getZoneRecords(self._api_user, self._api_pass, domain, subdomain))

    def addSubdomain(self, username, password, domain, subdomain):
        """Adds a subdomain to the provided domain"""
        log.info(f"adding subdomain: {username} -> {subdomain}.{domain}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.addSubdomain(self._api_user, self._api_pass, domain, subdomain))

    def removeSubdomain(self, username, password, domain, subdomain):
        """Removes a subdomain on the provided domain"""
        log.info(f"removing subdomain: {username} -> {subdomain}.{domain}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.removeSubdomain(self._api_user, self._api_pass, domain, subdomain))

    def addZoneRecord(self, username, password, domain, subdomain, record):
        """Adds a zone records to the provided subdomain for the provided domain"""
        log.info(f"adding zone record to subdomain: {username} -> {subdomain}.{domain}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.addZoneRecord(self._api_user, self._api_pass, domain, subdomain, record))

    def removeZoneRecord(self, username, password, domain, subdomain, record_id):
        """Removes a zone record from the provided subdomain for the provided domain"""
        log.info(f"removing zone record on subdomain: {username} -> {subdomain}.{domain}. ID: {record_id}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.removeZoneRecord(self._api_user, self._api_pass, domain, subdomain, record_id))

    def updateZoneRecord(self, username, password, domain, subdomain, record):
        """Updates a zone record on the provided subdomain for the provided domain"""
        if 'record_id' not in record:
            return 'BAD_INDATA'

        log.info(f"updating zone record on subdomain: {username} -> {subdomain}.{domain}. ID: {record['record_id']}")
        return self._checkAndRun(username, password, domain, subdomain,
                                 lambda: self._loopia.updateZoneRecord(self._api_user, self._api_pass, domain, subdomain, record))

    def __close(self):
        self._loopia("close")

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
