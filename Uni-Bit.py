import hashlib
import os

# Global variable
malware_hashes = list(open("virusHash.unibit", "r").read().split("\n"))
virusInfo = list(open("virusInfo.unibit", "r").read().split("\n"))

# Get Hash Of File
def sha256_hash(filename):
    try:
        with open(filename, "rb") as f:
            bytes = f.read()
            sha256hash = hashlib.sha256(bytes).hexdigest()
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

    return 0

# Malware Detection In Folder
virusName = []  # List of detected malware files
def folderScanner():
    # Get the list of all files and directories
    dir_list = list()
    for (dirpath,dirnames,filenames) in os.walk(r"C:\Users\Priya Sharma\Desktop\antivirus-scan"):
        dir_list +=[os.path.join(dirpath, file) for file in filenames]

    for i in dir_list:
        print(i)
        if malware_checker(i) != 0:
            virusName.append(malware_checker(i)+" ::  File :: " + i)    

    # for root, dirs, files in os.walk(path):
    #      Exclude .git directory
    #     dirs[:] = [d for d in dirs if d != ".git"]

    #     for file in files:
    #         file_path = os.path.join(root, file)
    #         result = malware_checker(file_path)
    #         if result != 0:
    #             virusName.append(f"{result} :: File :: {file}")

folderScanner()

print(virusName)
