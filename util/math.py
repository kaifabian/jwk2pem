import random
import fractions

# via: http://stackoverflow.com/questions/5486204/fast-modulo-calculations-in-python-and-ruby
def modexp(g, u, p):
    """computes s = (g ^ u) mod p
        args are base, exponent, modulus
        (see Bruce Schneier's book, _Applied Cryptography_ p. 244)"""
    s = 1
    while u != 0:
        if u & 1:
            s = (s * g)%p
        u >>= 1
        g = (g * g)%p;
    return s


# implemented freely after: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def egcd(a, b):
    ab_stack = list()
    g, y, x = None, None, None

    while True:
        if a == 0:
            g, y, x = b, 0, 1
            break
        else:
            ab_stack.append((a, b))
            a, b = (b % a), a

    while ab_stack:
        a, b = ab_stack.pop()
        y, x = x - (b // a) * y, y

    return g, y, x


# via: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# implemented freely after: http://www.di-mgt.com.au/rsa_factorize_n.html
def factorrsa(n, e, d):
    # rsa sanity check:
    m = random.randint(0, n)
    me = modexp(m, e, n)
    md = modexp(me, d, n)
    assert md == m, ValueError("Not a valid RSA key!")

    k = d*e - 1
    while True:
        g = random.randint(2, n)
        t = k

        while t % 2 == 0 and t > 0:
            t = t//2
            x = modexp(g, t, n)
            y = egcd(x-1, n)[0]
            if x > 1 and y > 1:
                p = y
                q = n/y
                return (p, q)
