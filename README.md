# Loopia API Proxy

This is a basic proxy for [LoopiaAPI][1] to be able to limit which domain the api has access to.

It only has support for the endpoints used in [acme.sh][2] to automate DNS verification of certificate creation/renewal.

## Requirements

- Python 3
- Python [Virtualenv][3] (not really required but highly recommended for non docker setups).

## Setup
Rename the `config/settings-example.json` to `config/settings.json` and edit it as needed:
- The root of each object is the username used for authenticating to the proxy.
- `password`: The password is used to authenticate to the proxy.
  - This will be hashed when the proxy starts.
- `domains`: The list of domains to allow this specific username to edit.


Install all the libraries with the following:

```sh
pip install -r requirements.txt
```

Then to run the proxy you just need to run the following:

```sh
LOOPIA_USER=username@loopiaapi LOOPIA_PASS=password python main.py
```
Or use an equivalent way of setting the environment variables first.

Bt default there should now be accessible on http://localhost:8000/RPCSERV

The host and port is controllable with the `HOST` and `PORT` environment variables.

## License

[MIT][4]

[1]: https://www.loopia.se/api/
[2]: https://github.com/acmesh-official/acme.sh
[3]: https://packaging.python.org/guides/installing-using-pip-and-virtual-environments
[4]: https://choosealicense.com/licenses/mit/
