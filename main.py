import os
import argparse
from google.cloud import kms
from google.cloud import storage
from google.oauth2 import service_account

# Function to encrypt the file using KMS and upload it to Google Cloud Storage
def encrypt_and_upload(project_id, file_path, bucket_name, key_ring_name, key_name):
    # Initialize the KMS client
    client = kms.KeyManagementServiceClient()

    # Get the key version
    key_name_full = f"projects/{project_id}/locations/global/keyRings/{key_ring_name}/keys/{key_name}"
    response = client.get_crypto_key(key_name_full)

    # Initialize the Cloud Storage client
    storage_client = storage.Client()

    # Read the file to be encrypted
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the file using KMS
    encrypt_response = client.encrypt(name=key_name_full, plaintext=plaintext)
    ciphertext = encrypt_response.ciphertext

    # Print encrypted file info
    print(f"Encrypted file size: {len(ciphertext)} bytes")

    # Upload the encrypted file to Google Cloud Storage
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(f"encrypted-{os.path.basename(file_path)}")
    blob.upload_from_string(ciphertext)

    print(f"Encrypted file uploaded to gs://{bucket_name}/encrypted-{os.path.basename(file_path)}")

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Encrypt a file using Google Cloud KMS and upload it to Google Cloud Storage.")
    parser.add_argument('project_id', type=str, help="Your Google Cloud Project ID")
    parser.add_argument('file_path', type=str, help="Path to the file to be encrypted")
    parser.add_argument('bucket_name', type=str, help="Google Cloud Storage bucket name to store the encrypted file")
    parser.add_argument('key_ring_name', type=str, help="The name of the KeyRing containing the KMS key")
    parser.add_argument('key_name', type=str, help="The name of the KMS key to use for encryption")

    args = parser.parse_args()

    encrypt_and_upload(args.project_id, args.file_path, args.bucket_name, args.key_ring_name, args.key_name)

if __name__ == "__main__":
    main()
