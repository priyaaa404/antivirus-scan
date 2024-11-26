import hashlib
#Get Hash Of File
def md5_hash(filename):
    with open(filename, "rb") as f:
        bytes = f.read()
        md5hash = hashlib.md5(bytes).hexdigest()
        f.close()

    return md5hash

# print(md5_hash("sample.jpg"))   to get hash of things.

#Ma1ware Dectection By Hash
def malware_checker(pathOfFile):
    hash_malware_check = md5_hash(pathOfFile)

    malware_hashes = open("virusHash.txt","r")
    malware_hashes_read = malware_hashes.read()
    malware_hashes.close()

    virusInfo = open("virusInfo.txt","r").readlines()


    if malware_hashes_read.find(hash_malware_check) != -1:
        return virusInfo[malware_hashes_read.index(hash_malware_check)]
    else:
        return 0

print(malware_checker("sample.jpg"))
    
