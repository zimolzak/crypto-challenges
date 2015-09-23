from diffie_hellman import modexp
import random
from hashlib import sha256
import hmac

class SRPEntity:
    def __init__(self, N, g, k, I, P):
        self.N = N
        self.g = g
        self.k = k
        self.email = I
        self.password = P

class Server(SRPEntity):
    def __init__(self, N, g, k, I, P, simple=False):
        SRPEntity.__init__(self, N, g, k, I, P)
        self.salt = random.randint(0, 2 ** 32)
        xH = sha256(str(self.salt) + P).hexdigest()
        x = int('0x' + xH, 16)
        self.v = modexp(g, x, N)
        self.simple = simple
    def take_logon(self, email, A):
        self.I = email # I / email is not really used by server
        self.A = A
        self.b = random.randint(0, self.N - 1)                    # private
        if self.simple:
            self.B = modexp(self.g, self.b, self.N)
            u = random.randint(0, 2**128 - 1)
        else:
            self.B = self.k * self.v + modexp(self.g, self.b, self.N) # public
            uH = sha256(str(self.A) + str(self.B)).hexdigest()
            u = int('0x' + uH, 16)
        S = modexp(self.A * modexp(self.v, u, self.N),
                   self.b,
                   self.N)
        # If A is congruent to 0 (mod N), then S = 0!!
        self.K = sha256(str(S)).hexdigest()
        if self.simple:
            return self.salt, self.B, u
        else:
            return self.salt, self.B
    def validate_hash(self, unknown_mac):
        true_mac = hmac.new(self.K, str(self.salt), sha256).hexdigest()
        if true_mac == unknown_mac:
            return "OK"
        else:
            return "YOU LOSE. GET OFF MY PROPERTY."

class Client(SRPEntity):
    def __init__(self, N, g, k, I, P, ntimes=None, simple=False):
        SRPEntity.__init__(self, N, g, k, I, P)
        self.a = random.randint(0, self.N - 1) # private
        self.ntimes = ntimes
        self.simple = simple
        if ntimes == None:
            self.A = modexp(g, self.a, self.N) # public (normal)
        else:
            self.A = self.N * ntimes          # evil zero key
    def logon_to(self, robot):
        if self.simple:
            [self.salt, self.B, u] = robot.take_logon(self.email, self.A)
        else:
            [self.salt, self.B] = robot.take_logon(self.email, self.A)
            uH = sha256(str(self.A) + str(self.B)).hexdigest()
            u = int('0x' + uH, 16)
        xH = sha256(str(self.salt) + self.password).hexdigest()
        x = int('0x' + xH, 16)
        if self.simple:
            S = modexp(self.B, self.a + u * x, self.N)
        else:
            S = modexp(self.B - self.k * modexp(self.g, x, self.N),
                       self.a + u * x,
                       self.N)
        if self.ntimes == None:
            self.K = sha256(str(S)).hexdigest()
        else:
            self.K = sha256(str(0)).hexdigest()
        mac = hmac.new(self.K, str(self.salt), sha256).hexdigest()
        print "Server says:", robot.validate_hash(mac)
