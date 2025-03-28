from flask import Flask, jsonify
import hmac
import hashlib
import datetime
import uuid
import random
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

def generate_signature_v4(marketplace_id, endpoint_type):
    # Generate timestamp
    now = datetime.datetime.now(datetime.UTC)
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    
    # Generate request ID
    request_id = str(uuid.uuid4())
    
    # Get host from environment or use default
    host = os.environ.get('RENDER_HOST', 'signature-service.onrender.com')
    
    # Generate canonical request based on endpoint type
    if endpoint_type == 'accept':
        path = f"/accept/357f7bab-25ed-4fdb-a8e5-a7b3a9f97411/{marketplace_id}"
    else:
        path = f"/challenge/357f7bab-25ed-4fdb-a8e5-a7b3a9f97411/{marketplace_id}"
    
    canonical_request = f"GET\n{path}\n\nhost:{host}\nx-amz-date:{amz_date}\n\nhost;x-amz-date\n"
    
    # Generate string to sign
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/us-east-1/execute-api/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    
    # Generate signing key
    def sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()
    
    # Use environment variables for AWS credentials
    secret_key = os.environ.get('AWS_SECRET_KEY', 'your-secret-key')
    access_key = os.environ.get('AWS_ACCESS_KEY', 'your-access-key')
    
    k_date = sign(('AWS4' + secret_key).encode(), date_stamp)
    k_region = sign(k_date, 'us-east-1')
    k_service = sign(k_region, 'execute-api')
    k_signing = sign(k_service, 'aws4_request')
    
    # Generate signature
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    
    # Generate authorization header
    authorization_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders=host;x-amz-date, Signature={signature}"
    
    # Generate user agent
    user_agent = f"AmazonFlex/1.0 (Android; {random.randint(1, 9)}.{random.randint(0, 9)}.{random.randint(0, 9)})"
    
    return {
        "signature": authorization_header,
        "signature_input": f"host;x-amz-date",
        "user_agent": user_agent
    }

@app.route('/accept/357f7bab-25ed-4fdb-a8e5-a7b3a9f97411/<marketplace_id>')
def accept_offer(marketplace_id):
    try:
        signature_data = generate_signature_v4(marketplace_id, 'accept')
        return jsonify(signature_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/challenge/357f7bab-25ed-4fdb-a8e5-a7b3a9f97411/<marketplace_id>')
def validate_challenge(marketplace_id):
    try:
        signature_data = generate_signature_v4(marketplace_id, 'challenge')
        return jsonify(signature_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port) 