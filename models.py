from pydantic import BaseModel
from typing import Optional, Dict

class RunCodeRequest(BaseModel):
    api_key: str  # API key to authenticate the request
    api_key_id: str  # RabbitSign API Key ID
    api_key_secret: str  # RabbitSign API Key Secret
    file_url: str  # URL of the PDF file to download
    signerInfo: Dict  # Signer information
    folder_title: Optional[str] = "Test Document Folder"  # Default value
    folder_summary: Optional[str] = "Test folder for document signing"  # Default value

class GetFolderInfoRequest(BaseModel):
    api_key: str  # API key to authenticate the request
    api_key_id: str  # RabbitSign API Key ID
    api_key_secret: str  # RabbitSign API Key Secret
    folder_id: str  # Folder ID to fetch information for
