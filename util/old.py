import argparse
import base64
import binascii
import json
import os
import textwrap
import sys

from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder

from util.math import modexp, egcd, modinv, factorrsa


def asn1sequence(*elems):
    seq = univ.Sequence(componentType=namedtype.NamedTypes())
    for i,item in enumerate(elems):
        seq.setComponentByPosition(i, item)
    return seq


def jbase2int(s):
    s64 = s.replace("-", "+").replace("_", "/")
    s64 += "=" * (4 - (len(s64) % 4))
    bin = base64.b64decode(s64)
    hex = binascii.hexlify(bin)
    num = int(hex, 16)
    return num


def jwkrsa2pem(j, type='PEM'):
    if not hasattr(j, '__getitem__') or not hasattr(j, 'items'):
        # not a dict. probably json.
        try:
            j = json.loads(j)
        except Exception as e:
            # not json.
            raise
            raise ValueError("The parameter is neither a dictionary-like object, nor a JSON string.")

    conditions = (
        lambda d: "kty" in d,
        lambda d: d["kty"].lower().strip() == "rsa",
        lambda d: all(map(lambda k: k in d, ("n", "e", "d"))),
    )
    if not all(map(lambda f: f(j), conditions)):
        raise ValueError("The parameter is not a valid JWK RSA key")

    n = jbase2int(j["n"])
    assert n % 2 == 1, "n should not be an even number..."
    e = jbase2int(j["e"])
    d = jbase2int(j["d"])
    if "p" in j and "q" in j:
        p = jbase2int(j["p"])
        q = jbase2int(j["q"])
    else:
        p, q = factorrsa(n, e, d)
    if "dp" in j and "dq" in j:
        dp = jbase2int(j["dp"])
        dq = jbase2int(j["dq"])
    else:
        dp = modexp(d, 1, p-1)
        dq = modexp(d, 1, q-1)
    if "qi" in j:
        qi = jbase2int(j["qi"])
    else:
        qi = modinv(q, p)

    inner = der_encoder.encode(asn1sequence(
        univ.Integer(0),
        univ.Integer(n),
        univ.Integer(e),
        univ.Integer(d),
        univ.Integer(p),
        univ.Integer(q),
        univ.Integer(dp),
        univ.Integer(dq),
        univ.Integer(qi),
    ))

    if type == 'PEM':
        wrapper = textwrap.TextWrapper(width=64, break_on_hyphens=False)
        pem_b64 = wrapper.fill(base64.b64encode(inner))
        pem_tpl = """-----BEGIN RSA PRIVATE KEY-----
{}
-----END RSA PRIVATE KEY-----"""
        return pem_tpl.format(pem_b64).encode('ascii')
    elif type == 'DER':
        return inner
    else:
        raise ValueError("Output type can only be 'DER' or 'PEM'")


def main():
    parser = argparse.ArgumentParser(description='Convert JWK private key to PEM or DER')
    parser.add_argument('-P', '--pem', dest='outform', action='store_const', const='PEM', default='PEM', help='Output in PEM format')
    parser.add_argument('-D', '--der', dest='outform', action='store_const', const='DER', help='Output in DER format')
    parser.add_argument('-e', '--encoding', dest='encoding', default='utf-8', help='Encoding of the JWK file')
    parser.add_argument('-in', dest='infile', required=True, help='Destination file, can be \'-\' for stdout')
    parser.add_argument('-out', dest='outfile', default='-', help='Input file')
    args = parser.parse_args()

    jwk_key = None
    try:
        with open(args.infile, "rb") as f:
            jwk_bytes = f.read()
            jwk_key = jwk_bytes.decode(args.encoding)
    except IOError:
        sys.stderr.write("ERROR: Cannot read file {}".format(args.infile))
        return 1

    out = jwkrsa2pem(jwk_key, type=args.outform)

    if args.outfile == '-':
        print(out)
    else:
        with open(args.outfile, "wb") as f:
            f.write(out)

    return 0
