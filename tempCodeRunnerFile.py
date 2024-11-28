
            return sha256hash
    except PermissionError:
        print(f"Permission denied: {filename}")
        return None  # Skip files with permission issues
# print(sha256_hash("sample.jpg"))
# Malware Detection By Hash
def malware_checker(pathOfFile):
    global malware_hashes
    global virusInfo

    hash_malware_check = sha256_hash(pathOfFile)
    if hash_malware_check is None:
        return 0  # Skip files that couldn't be hashed

    for idx, malware_hash in enumerate(malware_hashes):
        if malware_hash == hash_malware_check:
            return virusInfo[idx]
