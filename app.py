# app.py

from fastapi import FastAPI, Request, HTTPException
from models import RunCodeRequest, GetFolderInfoRequest  # Import request models
import requests
import hashlib
from datetime import datetime
import pytz
import PyPDF2
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from io import BytesIO

# Initialize FastAPI app
app = FastAPI()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Register rate limit exceeded handler
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Valid API keys for authenticating requests to this endpoint
# Replace 'your_api_key_here' with your actual API key(s)
VALID_API_KEYS = ["your_api_key_here"]

def authenticate_api_key(api_key: str):
    if api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")

def download_pdf(url):
    response = requests.get(url, allow_redirects=True)
    if response.status_code == 200:
        pdf_bytes = BytesIO(response.content)
        logging.info("PDF downloaded successfully.")
        return pdf_bytes
    else:
        raise Exception(f"Error downloading PDF: {response.status_code}")

def verify_pdf(pdf_bytes):
    try:
        pdf_bytes.seek(0)  # Ensure we're at the start of the file
        reader = PyPDF2.PdfReader(pdf_bytes)
        if reader.is_encrypted:
            raise Exception("Downloaded file is encrypted and cannot be processed.")
        num_pages = len(reader.pages)
        logging.info(f"PDF is valid and has {num_pages} pages.")
    except PyPDF2.errors.PdfReadError:
        raise Exception("Downloaded file is not a valid PDF.")

def generate_signature(http_method, path, utc_time, key_secret):
    data = f"{http_method} {path} {utc_time} {key_secret}"
    logging.debug(f"Data to hash: {data}")
    signature = hashlib.sha512(data.encode('utf-8')).hexdigest().upper()
    logging.debug(f"Generated Signature: {signature}")
    return signature

def get_utc_time():
    return datetime.now(pytz.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def get_upload_url(api_key_id, api_key_secret):
    url = "https://www.rabbitsign.com/api/v1/upload-url"
    utc_time = get_utc_time()
    path = "/api/v1/upload-url"
    signature = generate_signature("POST", path, utc_time, api_key_secret)
    headers = {
        "x-rabbitsign-api-time-utc": utc_time,
        "x-rabbitsign-api-key-id": api_key_id,
        "x-rabbitsign-api-signature": signature
    }
    response = requests.post(url, headers=headers)
    logging.info(f"Upload URL response: {response.status_code}")
    if response.status_code == 200:
        return response.json()['uploadUrl']
    else:
        raise Exception(f"Error fetching upload URL: {response.text}")

def upload_pdf_file(upload_url, pdf_bytes):
    verify_pdf(pdf_bytes)
    pdf_bytes.seek(0)  # Ensure we're at the start of the file
    headers = {"Content-Type": "binary/octet-stream"}
    response = requests.put(upload_url, data=pdf_bytes.read(), headers=headers)
    if response.status_code == 200:
        logging.info("File uploaded successfully")
    else:
        raise Exception(f"Error uploading file: {response.text}")

def create_folder(file_url, api_key_id, api_key_secret, signerInfo, folder_title, folder_summary):
    url = "https://www.rabbitsign.com/api/v1/folder"
    utc_time = get_utc_time()
    signature = generate_signature("POST", "/api/v1/folder", utc_time, api_key_secret)
    headers = {
        "x-rabbitsign-api-time-utc": utc_time,
        "x-rabbitsign-api-key-id": api_key_id,
        "x-rabbitsign-api-signature": signature,
        "Content-Type": "application/json"
    }
    payload = {
        "folder": {
            "title": folder_title,
            "summary": folder_summary,
            "docInfo": [
                {
                    "url": file_url,
                    "docTitle": "UploadedDocument.pdf"
                }
            ],
            "signerInfo": signerInfo
        },
        "date": utc_time.split("T")[0]
    }
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        logging.info("Folder created successfully")
        return response.json().get('folderId', 'Folder created but no ID returned')
    else:
        raise Exception(f"Error creating folder: {response.text}")

def fetch_folder_info(api_key_id, api_key_secret, folder_id):
    url = f"https://www.rabbitsign.com/api/v1/folder/{folder_id}"
    utc_time = get_utc_time()
    path = f"/api/v1/folder/{folder_id}"
    signature = generate_signature("GET", path, utc_time, api_key_secret)
    headers = {
        "x-rabbitsign-api-time-utc": utc_time,
        "x-rabbitsign-api-key-id": api_key_id,
        "x-rabbitsign-api-signature": signature,
        "Accept": "*/*"
    }
    response = requests.get(url, headers=headers)
    logging.info(f"Folder info response: {response.status_code}")
    if response.status_code == 200:
        folder_info = response.json()
        return folder_info
    else:
        raise Exception(f"Error fetching folder info: {response.text}")

@app.post('/run_code')
@limiter.limit("5/second")
def run_code(request_data: RunCodeRequest, request: Request):
    # Authenticate the API key
    authenticate_api_key(request_data.api_key)

    try:
        api_key_id = request_data.api_key_id
        api_key_secret = request_data.api_key_secret
        pdf_url = request_data.file_url
        signerInfo = request_data.signerInfo
        folder_title = request_data.folder_title
        folder_summary = request_data.folder_summary

        # Step 1: Download the PDF file
        pdf_bytes = download_pdf(pdf_url)

        # Step 2: Get the pre-signed upload URL from RabbitSign
        upload_url = get_upload_url(api_key_id, api_key_secret)
        logging.info(f"Upload URL: {upload_url}")

        # Step 3: Upload the downloaded PDF to RabbitSign
        upload_pdf_file(upload_url, pdf_bytes)

        # Step 4: Create a folder that references the uploaded PDF
        folder_id = create_folder(upload_url, api_key_id, api_key_secret, signerInfo, folder_title, folder_summary)

        # Return the folder ID
        return {"folder_id": folder_id}

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/get_folder_info')
@limiter.limit("5/second")
def get_folder_info_endpoint(request_data: GetFolderInfoRequest, request: Request):
    # Authenticate the API key
    authenticate_api_key(request_data.api_key)

    try:
        api_key_id = request_data.api_key_id
        api_key_secret = request_data.api_key_secret
        folder_id = request_data.folder_id

        # Fetch folder information from RabbitSign
        folder_info = fetch_folder_info(api_key_id, api_key_secret, folder_id)

        # Extract the downloadUrl from folder_info
        download_url = folder_info.get('downloadUrl', '')
        if not download_url:
            # Handle case where downloadUrl is empty
            logging.warning("No download URL available for this folder.")
            return {"message": "No download URL available for this folder."}

        return {"download_url": download_url}

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))