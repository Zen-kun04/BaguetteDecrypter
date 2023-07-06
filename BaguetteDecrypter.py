import hashlib
import os
import threading


hash_types = {
    "SHA1": "$P",
    "SHA256": "($P).$S",
    "SHA512": "$P"
}

identify_rules = {
    "SHA1":
        {
            "len": 40
        },
    "SHA256":
        {
            "len": 64
        },
    "SHA512":
        {
            "len": 128
        }
    
}

def getPosition(hash_type: str):
    return hash_types[hash_type]

class Decrypter():

    splitter = False

    def __init__(self) -> None:
        self.splitter = False
    
    def setSplitter(self, boolean: bool):
        self.splitter = boolean
    
    def hashByPosition(self, password: str, position: str, hash_type, salt: str | None) -> str:
        if position == "$P":
            if hash_type == "SHA1":
                return hashlib.sha1(password.encode()).hexdigest()
            if hash_type == "SHA512":
                return hashlib.sha512(password.encode()).hexdigest()
        split = position.split('.', 1)
        if len(split) == 2:
            
            if split[0].startswith('(') and split[0].endswith(')'):
                
                if split[0] == "($P)":
                    
                    if hash_type == "SHA256":
                        return hashlib.sha256(hashlib.sha256(password.encode()).hexdigest().encode() + salt.encode()).hexdigest()
                if hash_type == "SHA256":
                    return hashlib.sha256(hashlib.sha256(salt.encode()).hexdigest().encode() + password.encode()).hexdigest()

    def testHasher(self, password: str):
        for hash_type in hash_types:
            position = getPosition(hash_type)
            if not position.__contains__("$S"):
                print(hash_type + " => " + self.hashByPosition(password, position, hash_type, None))
            else:
                print(hash_type + " => " + self.hashByPosition(password, position, hash_type, "c6784e5bfa46ace4"))


    def identify(self, hash: str) -> str:
        """
        SHA1 => 2276eaf0cb4b87809ac7987c40b92203e64d0410
        SHA256 => 92c4753a26c3ad75a3dc0901ce12867f9139985f6da018240622cf6160def408
        SHA512 => 021b1c440a198d34c2f0d2d463340bfec459d706732214ad8f82f2a456e99c3d43835221f2c12f47849e80761b48573eeddb543a9db38e992c0ba3e437dcc1fd
        SHA256 => $SHA$0f0faf39e308b627$e6144bfd23f049f06d6eb11b3df3b18f3db7cc4c5215da51487e1f7817d87e04
        SHA256 => $SHA$e6144bfd23f049f06d6eb11b3df3b18f3db7cc4c5215da51487e1f7817d87e04
        """

        if hash.startswith("$SHA"):
            hash_split = hash.split('$', 3)
            if len(hash_split) == 4: # contiene salt
                if len(hash_split[-1]) > len(hash_split[-2]):
                    hash = hash_split[-1]
                else:
                    hash = hash_split[-2]
            elif len(hash_split) == 3: # no contiene salt
                hash = hash_split[-1]

        for hash_type in identify_rules:
            rule = identify_rules[hash_type]
            for condition in rule:
                if (condition == "len") and len(hash) == rule[condition]:
                    return hash_type

        return "Could not find hash type"
    
    
