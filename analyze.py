import os
import hashlib

# Define known virus signatures (byte sequences)
virus_signatures = [
    b'VIRUS_EXAMPLE',

]

# Define known malicious file hashes (SHA-256)
virus_hashes = [
    '89f4b6e49dcc11ce3ef48f5c78ed9a682923e749af6bc0cd5dd7dabdc3e530bd',
    'b3f97a0e77cc8ff4b81d5e9c33cdcce761a3bf23fa8e1fd31dd7dabdc3e530bd',
    "6419b7248e2f8d3a955c0753fed2d3d6cd4b29ce05d0de79dd7dabdc3e530bd",
    '5a8c11dcd5509077d1bbad88eecb440f0ed17a7632ce5dd7dabdc3e530bd',

    # Add more hashes as needed
]

def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.

    :param file_path: Path to the file.
    :return: SHA-256 hash of the file content.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                sha256.update(chunk)
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None
    return sha256.hexdigest()

def scan_file(file_path):
    """
    Scan a single file for known virus signatures and hashes.

    :param file_path: Path to the file to be scanned.
    :return: List of found virus signatures and a boolean indicating if the file hash matches a known virus hash.
    """
    found_signatures = []
    hash_match = False
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            for signature in virus_signatures:
                if signature in content:
                    found_signatures.append(signature)

        file_hash = calculate_file_hash(file_path)
        if file_hash in virus_hashes:
            hash_match = True
    except Exception as e:
        print(f"Error scanning {file_path}: {e}")
    return found_signatures, hash_match

def scan_directory(directory_path):
    """
    Scan all files in a directory for known virus signatures and hashes.

    :param directory_path: Path to the directory to be scanned.
    :return: Dictionary with file paths as keys and found signatures plus hash match status as values.
    """
    results = {}
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            found_signatures, hash_match = scan_file(file_path)
            if found_signatures or hash_match:
                results[file_path] = {
                    'signatures': found_signatures,
                    'hash_match': hash_match
                }
    return results

def main():
    """
    Main function to drive the antivirus script.
    """
    directory_path = input("Enter the directory path to scan: ")
    if not os.path.isdir(directory_path):
        print("Invalid directory path.")
        return

    results = scan_directory(directory_path)
    if results:
        print("Potential threats found:")
        for file_path, data in results.items():
            print(f"File: {file_path}")
            if data['signatures']:
                for signature in data['signatures']:
                    print(f"  - Signature: {signature}")
            if data['hash_match']:
                print(f"  - Hash match found!")
    else:
        print("No threats found.")

if __name__ == "__main__":
    main()
