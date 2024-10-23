# app.py

from fastapi import FastAPI, Request, HTTPException
from starlette.responses import JSONResponse
from models import RunCodeRequest
import requests
import hashlib
from datetime import datetime
import pytz
import os
import PyPDF2
import uuid
import logging
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

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
# Replace 'your_api_key_here' with your actual API key
VALID_API_KEYS = ["your_api_key_here"]

def authenticate_api_key(api_key: str):
    if api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")

def download_pdf(url, file_name):
    response = requests.get(url, allow_redirects=True)
    if response.status_code == 200:
        with open(file_name, 'wb') as f:
            f.write(response.content)
        logging.info(f"PDF downloaded successfully: {file_name}")
    else:
        raise Exception(f"Error downloading PDF: {response.status_code}")

def verify_pdf(file_path):
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
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

def upload_pdf_file(upload_url, file_path):
    verify_pdf(file_path)
    with open(file_path, 'rb') as f:
        response = requests.put(upload_url, data=f, headers={"Content-Type": "binary/octet-stream"})
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

        # Generate a unique file name for concurrency safety
        pdf_file_name = f"downloaded_pdf_{uuid.uuid4()}.pdf"

        # Step 1: Download the PDF file
        download_pdf(pdf_url, pdf_file_name)

        # Step 2: Get the pre-signed upload URL from RabbitSign
        upload_url = get_upload_url(api_key_id, api_key_secret)
        logging.info(f"Upload URL: {upload_url}")

        # Step 3: Upload the downloaded PDF to RabbitSign
        upload_pdf_file(upload_url, pdf_file_name)

        # Step 4: Create a folder that references the uploaded PDF
        folder_id = create_folder(upload_url, api_key_id, api_key_secret, signerInfo, folder_title, folder_summary)

        # Clean up the downloaded file
        if os.path.exists(pdf_file_name):
            os.remove(pdf_file_name)
            logging.info(f"Cleaned up the local file: {pdf_file_name}")

        # Return the folder ID or any other relevant URL
        return {"folder_id": folder_id}

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# You can run the application with the following command
# uvicorn app:app --reload

