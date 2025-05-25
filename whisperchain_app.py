#Anvi Kalyana and Mehar Bhasin
#main whisperchain file

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import secrets
import json
import datetime
import logging
import os
from functools import wraps

app = Flask(__name__)

# Configure audit logging to file
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Create audit.log file 
audit_handler = logging.FileHandler('audit.log', mode='a')
audit_handler.setLevel(logging.INFO)

# Formatting the audit logs (timestamp, action, role, details)
audit_formatter = logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
audit_handler.setFormatter(audit_formatter)

# Add handler to audit logger
audit_logger.addHandler(audit_handler)

# Prevent audit logs from going to console
audit_logger.propagate = False

# In-memory storage
users = {}  # {user_id: {role, public_key, private_key, name}}
tokens = {}  # {token: {user_id, used}}
messages = {}  # {message_id: {recipient_id, encrypted_content, flagged}}
moderator_queue = []

# Role definitions
ROLES = {
    'SENDER': 'sender',
    'RECIPIENT': 'recipient', 
    'MODERATOR': 'moderator',
    'ADMIN': 'admin'
}

def log_action(action_type, role=None, details=None):
    """Add entry to audit log file - preserves anonymity by not logging sender identity"""
    details_str = json.dumps(details or {})
    log_message = f"{action_type} | {role or 'SYSTEM'} | {details_str}"
    
    # Write to audit.log file 
    audit_logger.info(log_message)

def require_role(required_roles):
    # Enforce role-based access control
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                return jsonify({'error': 'No token provided'}), 401
            
            token = token.replace('Bearer ', '')
            
            # Check if it's a message token
            if token in tokens:
                token_data = tokens[token]
                user = users.get(token_data['user_id'])
                if not user or user['role'] not in required_roles:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                request.current_user = user
                request.current_token = token
                return f(*args, **kwargs)
            
            # Check if it's a user session 
            user = users.get(token)
            if not user or user['role'] not in required_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            request.current_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/register', methods=['POST'])
def register():
    """Register a new user with assigned role"""
    data = request.get_json()
    user_id = data.get('user_id')
    name = data.get('name')
    role = data.get('role', ROLES['RECIPIENT'])
    
    if user_id in users:
        return jsonify({'error': 'User already exists'}), 400
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    users[user_id] = {
        'name': name,
        'role': role,
        'private_key': private_pem,
        'public_key': public_pem
    }
    
    log_action('USER_REGISTERED', role=role, details={'role_assigned': role, 'keys_generated': True})
    
    return jsonify({
        'message': 'User registered successfully',
        'user_id': user_id,
        'role': role,
        'public_key': public_pem.decode('utf-8')
    })

@app.route('/issue-token', methods=['POST'])
@require_role([ROLES['ADMIN']])
def issue_token():
    """Admin issues anonymous tokens to senders"""
    data = request.get_json()
    sender_id = data.get('sender_id')
    
    sender = users.get(sender_id)
    if not sender or sender['role'] != ROLES['SENDER']:
        return jsonify({'error': 'Invalid sender'}), 400
    
    # Generate anonymous token
    token = secrets.token_urlsafe(32)
    tokens[token] = {
        'user_id': sender_id,
        'used': False,
        'issued_at': datetime.datetime.now().isoformat()
    }
    
    log_action('TOKEN_ISSUED', role=ROLES['ADMIN'], details={'tokens_active': len([t for t in tokens.values() if not t['used']])})
    
    return jsonify({
        'token': token,
        'message': 'Anonymous token issued'
    })

@app.route('/send-message', methods=['POST'])
@require_role([ROLES['SENDER']])
def send_message():
    """Send encrypted anonymous message"""
    data = request.get_json()
    recipient_id = data.get('recipient_id')
    message_content = data.get('message')
    
    # Check if token is already used
    token = request.current_token
    if tokens[token]['used']:
        return jsonify({'error': 'Token already used'}), 400
    
    recipient = users.get(recipient_id)
    if not recipient:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # Encrypt message with recipient's public key
    recipient_public_key = serialization.load_pem_public_key(recipient['public_key'])
    
    encrypted_message = recipient_public_key.encrypt(
        message_content.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Store encrypted message
    message_id = secrets.token_urlsafe(16)
    messages[message_id] = {
        'recipient_id': recipient_id,
        'encrypted_content': encrypted_message,
        'flagged': False,
        'sent_at': datetime.datetime.now().isoformat()
    }
    
    # Mark token as used
    tokens[token]['used'] = True
    
    log_action('MESSAGE_SENT', role=ROLES['SENDER'], details={'recipient_role': recipient['role'], 'encrypted': True})
    
    return jsonify({
        'message': 'Message sent successfully',
        'message_id': message_id
    })

@app.route('/messages', methods=['GET'])
@require_role([ROLES['RECIPIENT']])
def get_messages():
    """Get encrypted messages for recipient"""
    user_id = request.headers.get('Authorization') 
    
    user_messages = []
    for msg_id, msg_data in messages.items():
        if msg_data['recipient_id'] == user_id:
            user_messages.append({
                'message_id': msg_id,
                'encrypted_content': msg_data['encrypted_content'].hex(),
                'sent_at': msg_data['sent_at'],
                'flagged': msg_data['flagged']
            })
    
    return jsonify({'messages': user_messages})

@app.route('/decrypt-message', methods=['POST'])
@require_role([ROLES['RECIPIENT']])
def decrypt_message():
    """Decrypt message locally (helper endpoint)"""
    data = request.get_json()
    message_id = data.get('message_id')
    user_id = request.headers.get('Authorization')
    
    message = messages.get(message_id)
    if not message or message['recipient_id'] != user_id:
        return jsonify({'error': 'Message not found'}), 404
    
    user = users[user_id]
    private_key = serialization.load_pem_private_key(user['private_key'], password=None)
    
    try:
        decrypted_message = private_key.decrypt(
            message['encrypted_content'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({'decrypted_message': decrypted_message.decode('utf-8')})
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt message'}), 500

@app.route('/flag-message', methods=['POST'])
@require_role([ROLES['RECIPIENT']])
def flag_message():
    """Flag inappropriate message"""
    data = request.get_json()
    message_id = data.get('message_id')
    user_id = request.headers.get('Authorization')
    
    message = messages.get(message_id)
    if not message or message['recipient_id'] != user_id:
        return jsonify({'error': 'Message not found'}), 404
    
    message['flagged'] = True
    moderator_queue.append({
        'message_id': message_id,
        'flagged_at': datetime.datetime.now().isoformat(),
        'flagged_by': user_id
    })
    
    log_action('MESSAGE_FLAGGED', role=ROLES['RECIPIENT'], 
               details={'flagged_messages_total': len(moderator_queue)})
    
    return jsonify({'message': 'Message flagged successfully'})

@app.route('/moderation-queue', methods=['GET'])
@require_role([ROLES['MODERATOR']])
def get_moderation_queue():
    """Get flagged messages for moderation"""
    queue_with_content = []
    for item in moderator_queue:
        message = messages.get(item['message_id'])
        if message:
            # Moderators can see flagged content
            queue_with_content.append({
                'message_id': item['message_id'],
                'flagged_at': item['flagged_at'],
                'encrypted_content': message['encrypted_content'].hex(),
                'recipient_id': message['recipient_id']
            })
    
    return jsonify({'flagged_messages': queue_with_content})

@app.route('/freeze-token', methods=['POST'])
@require_role([ROLES['MODERATOR']])
def freeze_token():
    """Freeze token to prevent future abuse"""
    data = request.get_json()
    message_id = data.get('message_id')
    
    log_action('TOKEN_FROZEN', role=ROLES['MODERATOR'], 
               details={'action': 'token_frozen', 'reason': 'abuse_prevention'})
    
    return jsonify({'message': 'Token frozen successfully'})

@app.route('/audit-log', methods=['GET'])
@require_role([ROLES['MODERATOR'], ROLES['ADMIN']])
def get_audit_log():
    """Get audit log from file (moderators and admins only)"""
    try:
        audit_entries = []
        if os.path.exists('audit.log'):
            with open('audit.log', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        # Parse log line 
                        parts = line.split(' | ', 3)
                        if len(parts) >= 4:
                            timestamp = parts[0]
                            action_type = parts[1]
                            role = parts[2]
                            details = parts[3]
                            
                            audit_entries.append({
                                'timestamp': timestamp,
                                'action_type': action_type,
                                'role': role,
                                'details': details
                            })
        
        return jsonify({
            'audit_log': audit_entries,
            'total_entries': len(audit_entries)
        })
    except Exception as e:
        return jsonify({'error': 'Failed to read audit log'}), 500

@app.route('/users', methods=['GET'])
@require_role([ROLES['ADMIN']])
def get_users():
    """Admin endpoint to manage users"""
    user_list = []
    for user_id, user_data in users.items():
        user_list.append({
            'user_id': user_id,
            'name': user_data['name'],
            'role': user_data['role']
        })
    return jsonify({'users': user_list})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5500)