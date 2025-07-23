"""
Server Module
Flask server with WebSocket support for real-time secure messaging
"""

import os
import json
import base64
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import jwt
import mimetypes
from werkzeug.utils import secure_filename

from .crypto_core import CryptoCore
from .database import Database
from .security import rate_limiter, security_auditor


class SecureChatServer:
    """Flask server with WebSocket support"""
    
    def __init__(self, secret_key: str = None):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = secret_key or secrets.token_hex(32)
        self.app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
        
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.db = Database()
        self.crypto = CryptoCore()
        self.active_sessions = {}  # username -> session_id
        
        # Create file storage directory
        self.file_storage_path = os.path.join(os.path.dirname(__file__), '..', 'file_storage')
        os.makedirs(self.file_storage_path, exist_ok=True)
        
        self.setup_routes()
        self.setup_websocket_handlers()
    
    def setup_routes(self):
        """Setup HTTP API routes"""
        
        @self.app.route('/api/health', methods=['GET'])
        def health_check():
            """Health check endpoint"""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0'
            })
        
        @self.app.route('/api/register', methods=['POST'])
        def register():
            """User registration endpoint"""
            try:
                data = request.get_json()
                username = data.get('username', '').strip()
                password = data.get('password', '')
                
                if not username or not password:
                    return jsonify({'error': 'Username and password required'}), 400
                
                if len(username) < 3:
                    return jsonify({'error': 'Username must be at least 3 characters'}), 400
                
                if len(password) < 6:
                    return jsonify({'error': 'Password must be at least 6 characters'}), 400
                
                # Generate keys for new user
                identity_private, identity_public = self.crypto.generate_identity_keypair()
                prekey_private, prekey_public = self.crypto.generate_prekey()
                
                success = self.db.create_user(
                    username, password,
                    base64.b64encode(identity_public).decode(),
                    base64.b64encode(prekey_public).decode(),
                    base64.b64encode(prekey_private).decode()
                )
                
                if success:
                    return jsonify({
                        'message': 'User registered successfully',
                        'identity_private': base64.b64encode(identity_private).decode(),
                        'username': username
                    })
                else:
                    return jsonify({'error': 'Username already exists'}), 400
            
            except Exception as e:
                return jsonify({'error': f'Registration failed: {str(e)}'}), 500
        
        @self.app.route('/api/login', methods=['POST'])
        def login():
            """User login endpoint"""
            try:
                data = request.get_json()
                username = data.get('username', '').strip()
                password = data.get('password', '')
                
                if not username or not password:
                    return jsonify({'error': 'Username and password required'}), 400
                
                user = self.db.authenticate_user(username, password)
                if user:
                    # Generate JWT token
                    token = jwt.encode({
                        'user_id': user['id'],
                        'username': username,
                        'exp': datetime.utcnow() + timedelta(hours=24)
                    }, self.app.config['SECRET_KEY'], algorithm='HS256')
                    
                    return jsonify({
                        'token': token, 
                        'user': user,
                        'message': f'Login successful for {username}'
                    })
                else:
                    return jsonify({'error': 'Invalid credentials'}), 401
            
            except Exception as e:
                return jsonify({'error': f'Login failed: {str(e)}'}), 500
        
        @self.app.route('/api/prekeys/<username>', methods=['GET'])
        def get_prekeys(username):
            """Get user's prekeys for key exchange"""
            try:
                prekeys = self.db.get_user_prekeys(username)
                if prekeys:
                    return jsonify(prekeys)
                else:
                    return jsonify({'error': 'User not found'}), 404
            except Exception as e:
                return jsonify({'error': f'Failed to get prekeys: {str(e)}'}), 500
        
        @self.app.route('/api/users', methods=['GET'])
        def get_users():
            """Get all users (for testing/demo purposes)"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                
                users = self.db.get_all_users()
                return jsonify({'users': users})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get users: {str(e)}'}), 500
        
        @self.app.route('/api/messages/<partner_username>', methods=['GET'])
        def get_messages(partner_username):
            """Get message history with a partner"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Get partner
                partner = self.db.get_user_by_username(partner_username)
                if not partner:
                    return jsonify({'error': 'Partner not found'}), 404
                
                # Get messages
                messages = self.db.get_messages(user_id, partner['id'])
                return jsonify({'messages': messages})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get messages: {str(e)}'}), 500
        
        @self.app.route('/api/groups', methods=['POST'])
        def create_group():
            """Create a new group"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                data = request.get_json()
                name = data.get('name', '').strip()
                description = data.get('description', '').strip()
                
                if not name:
                    return jsonify({'error': 'Group name required'}), 400
                
                if len(name) > 50:
                    return jsonify({'error': 'Group name too long (max 50 characters)'}), 400
                
                # Generate group key
                group_key = base64.b64encode(self.crypto.generate_group_key()).decode()
                
                group_id = self.db.create_group(name, description, user_id, group_key)
                
                if group_id:
                    group = self.db.get_group_by_id(group_id)
                    return jsonify({
                        'message': 'Group created successfully',
                        'group': group
                    })
                else:
                    return jsonify({'error': 'Failed to create group'}), 500
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to create group: {str(e)}'}), 500
        
        @self.app.route('/api/groups', methods=['GET'])
        def get_user_groups():
            """Get user's groups"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                groups = self.db.get_user_groups(user_id)
                return jsonify({'groups': groups})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get groups: {str(e)}'}), 500
        
        @self.app.route('/api/groups/search', methods=['GET'])
        def search_groups():
            """Search for groups"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                
                query = request.args.get('q', '').strip()
                if not query:
                    return jsonify({'error': 'Search query required'}), 400
                
                groups = self.db.search_groups(query)
                return jsonify({'groups': groups})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to search groups: {str(e)}'}), 500
        
        @self.app.route('/api/groups/<int:group_id>/join', methods=['POST'])
        def join_group(group_id):
            """Join a group"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                success = self.db.join_group(group_id, user_id)
                
                if success:
                    group = self.db.get_group_by_id(group_id)
                    return jsonify({
                        'message': 'Joined group successfully',
                        'group': group
                    })
                else:
                    return jsonify({'error': 'Failed to join group (group full or already member)'}), 400
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to join group: {str(e)}'}), 500
        
        @self.app.route('/api/groups/<int:group_id>/leave', methods=['POST'])
        def leave_group(group_id):
            """Leave a group"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                success = self.db.leave_group(group_id, user_id)
                
                if success:
                    return jsonify({'message': 'Left group successfully'})
                else:
                    return jsonify({'error': 'Failed to leave group (not a member)'}), 400
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to leave group: {str(e)}'}), 500
        
        @self.app.route('/api/groups/<int:group_id>/members', methods=['GET'])
        def get_group_members(group_id):
            """Get group members"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Check if user is member of group
                if not self.db.is_group_member(group_id, user_id):
                    return jsonify({'error': 'Access denied: not a group member'}), 403
                
                members = self.db.get_group_members(group_id)
                return jsonify({'members': members})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get group members: {str(e)}'}), 500
        
        @self.app.route('/api/groups/<int:group_id>/messages', methods=['GET'])
        def get_group_messages(group_id):
            """Get group messages"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Check if user is member of group
                if not self.db.is_group_member(group_id, user_id):
                    return jsonify({'error': 'Access denied: not a group member'}), 403
                
                messages = self.db.get_group_messages(group_id)
                return jsonify({'messages': messages})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get group messages: {str(e)}'}), 500
        
        # File sharing endpoints
        
        @self.app.route('/api/files/upload', methods=['POST'])
        def upload_file():
            """Upload and encrypt a file"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Check if file was uploaded
                if 'file' not in request.files:
                    return jsonify({'error': 'No file uploaded'}), 400
                
                uploaded_file = request.files['file']
                if uploaded_file.filename == '':
                    return jsonify({'error': 'No file selected'}), 400
                
                # Get additional parameters
                recipient_username = request.form.get('recipient')
                group_id = request.form.get('group_id', type=int)
                expires_hours = request.form.get('expires_hours', type=int)
                
                # Validate that either recipient or group is specified
                recipient_id = None
                if recipient_username:
                    recipient = self.db.get_user_by_username(recipient_username)
                    if not recipient:
                        return jsonify({'error': 'Recipient not found'}), 404
                    recipient_id = recipient['id']
                elif group_id:
                    # Check if user is member of group
                    if not self.db.is_group_member(group_id, user_id):
                        return jsonify({'error': 'Access denied: not a group member'}), 403
                else:
                    return jsonify({'error': 'Either recipient or group_id must be specified'}), 400
                
                # Validate file
                original_filename = secure_filename(uploaded_file.filename)
                file_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'
                
                # Security checks
                allowed_extensions = {
                    '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif',
                    '.mp4', '.mp3', '.wav', '.zip', '.tar', '.gz', '.py', '.js',
                    '.html', '.css', '.json', '.xml', '.csv', '.xlsx', '.pptx'
                }
                
                file_ext = os.path.splitext(original_filename)[1].lower()
                if file_ext not in allowed_extensions:
                    return jsonify({'error': f'File type {file_ext} not allowed'}), 400
                
                # Read file data
                file_data = uploaded_file.read()
                file_size = len(file_data)
                
                # Check file size (50MB limit)
                if file_size > 50 * 1024 * 1024:
                    return jsonify({'error': 'File too large (max 50MB)'}), 400
                
                # Generate unique filename for storage
                stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
                
                # Check if file is already encrypted by client
                client_encrypted = request.form.get('client_encrypted') == 'true'
                
                if client_encrypted:
                    # Client has already encrypted the file and file key
                    encrypted_key_data = request.form.get('encrypted_key')
                    file_hash = request.form.get('file_hash')
                    
                    if not encrypted_key_data or not file_hash:
                        return jsonify({'error': 'Missing encryption data for client-encrypted file'}), 400
                    
                    # file_data is already encrypted (nonce + encrypted_data)
                    encrypted_file_data = file_data
                    
                    # Store encrypted file to disk
                    file_path = os.path.join(self.file_storage_path, stored_filename)
                    with open(file_path, 'wb') as f:
                        f.write(encrypted_file_data)
                else:
                    # Legacy server-side encryption (fallback)
                    # Encrypt file
                    encrypted_data, nonce, file_key = self.crypto.encrypt_file(file_data)
                    
                    # Encrypt file key based on sharing type
                    if group_id:
                        # For group sharing, encrypt with group key
                        group = self.db.get_group_by_id(group_id)
                        if not group:
                            return jsonify({'error': 'Group not found'}), 404
                        
                        group_key = base64.b64decode(group['group_key'])
                        encrypted_file_key, key_nonce = self.crypto.encrypt_file_key(file_key, group_key)
                    else:
                        # This would fail for user sharing without session key
                        return jsonify({'error': 'User file sharing requires client-side encryption'}), 400
                    
                    # Combine encrypted key and nonce for storage
                    encrypted_key_data = base64.b64encode(encrypted_file_key + key_nonce).decode()
                    
                    # Generate file hash for integrity
                    file_hash = self.crypto.hash_file(file_data)
                    
                    # Store encrypted file to disk
                    file_path = os.path.join(self.file_storage_path, stored_filename)
                    with open(file_path, 'wb') as f:
                        f.write(nonce + encrypted_data)  # Store nonce + encrypted data
                
                # Store file metadata in database
                file_id = self.db.store_file_metadata(
                    filename=stored_filename,
                    original_filename=original_filename,
                    file_size=file_size,
                    file_type=file_type,
                    encrypted_key=encrypted_key_data,
                    file_hash=file_hash,
                    uploader_id=user_id,
                    recipient_id=recipient_id,
                    group_id=group_id,
                    expires_hours=expires_hours
                )
                
                if file_id:
                    # Get file metadata for response
                    file_metadata = self.db.get_file_metadata(file_id)
                    
                    # Notify recipient or group members
                    if recipient_username and recipient_username in self.active_sessions:
                        self.socketio.emit('file_shared', {
                            'file_id': file_id,
                            'filename': original_filename,
                            'uploader': decoded['username'],
                            'file_size': file_size,
                            'timestamp': datetime.now().isoformat()
                        }, room=self.active_sessions[recipient_username])
                    
                    elif group_id:
                        # Notify group members
                        room_name = f"group_{group_id}"
                        self.socketio.emit('file_shared_group', {
                            'file_id': file_id,
                            'filename': original_filename,
                            'uploader': decoded['username'],
                            'group_id': group_id,
                            'file_size': file_size,
                            'timestamp': datetime.now().isoformat()
                        }, room=room_name)
                    
                    return jsonify({
                        'message': 'File uploaded successfully',
                        'file_id': file_id,
                        'file': file_metadata
                    }), 201
                else:
                    # Clean up file if database storage failed
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    return jsonify({'error': 'Failed to store file metadata'}), 500
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'File upload failed: {str(e)}'}), 500
        
        @self.app.route('/api/files/<int:file_id>/download', methods=['GET'])
        def download_file(file_id):
            """Download and decrypt a file"""
            try:
                # Verify token
                token = request.args.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
                if not token:
                    return jsonify({'error': 'Token required'}), 401
                
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Get file metadata
                file_metadata = self.db.get_file_metadata(file_id)
                if not file_metadata:
                    return jsonify({'error': 'File not found'}), 404
                
                # Check access permissions
                if not self.db.can_access_file(file_id, user_id):
                    return jsonify({'error': 'Access denied'}), 403
                
                # Read encrypted file from disk
                file_path = os.path.join(self.file_storage_path, file_metadata['filename'])
                if not os.path.exists(file_path):
                    return jsonify({'error': 'File not found on disk'}), 404
                
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                
                # For client-encrypted files, return encrypted data and metadata for client-side decryption
                # We can detect client-encrypted files by checking if they have specific metadata patterns
                # or add a flag to the database (for now, assume all user files are client-encrypted)
                
                is_client_encrypted = file_metadata['recipient_id'] is not None  # User files are client-encrypted
                
                if is_client_encrypted:
                    # Return encrypted file data and metadata for client-side decryption
                    encrypted_file_data = base64.b64encode(file_content).decode()
                    
                    response_data = {
                        'encrypted_file_data': encrypted_file_data,
                        'encrypted_key': file_metadata['encrypted_key'],
                        'file_hash': file_metadata['file_hash'],
                        'original_filename': file_metadata['original_filename'],
                        'file_type': file_metadata['file_type'],
                        'client_encrypted': True
                    }
                    
                    # Update download count
                    self.db.increment_download_count(file_id)
                    
                    return jsonify(response_data), 200
                else:
                    # Legacy server-side decryption for group files
                    # Extract nonce and encrypted data
                    nonce = file_content[:12]  # First 12 bytes are nonce
                    encrypted_data = file_content[12:]  # Rest is encrypted file data
                    
                    # Decrypt file key
                    encrypted_key_data = base64.b64decode(file_metadata['encrypted_key'])
                    encrypted_file_key = encrypted_key_data[:-12]  # All but last 12 bytes
                    key_nonce = encrypted_key_data[-12:]  # Last 12 bytes
                    
                    # Group file - decrypt with group key
                    group = self.db.get_group_by_id(file_metadata['group_id'])
                    group_key = base64.b64decode(group['group_key'])
                    file_key = self.crypto.decrypt_file_key(encrypted_file_key, key_nonce, group_key)
                    
                    # Decrypt file data
                    decrypted_data = self.crypto.decrypt_file(encrypted_data, nonce, file_key)
                    
                    # Verify file integrity
                    if not self.crypto.verify_file_hash(decrypted_data, file_metadata['file_hash']):
                        return jsonify({'error': 'File integrity check failed'}), 500
                    
                    # Update download count
                    self.db.increment_download_count(file_id)
                    
                    # Create temporary file for download
                    import tempfile
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    temp_file.write(decrypted_data)
                    temp_file.close()
                    
                    # Return file as download
                    return send_file(
                        temp_file.name,
                        as_attachment=True,
                        download_name=file_metadata['original_filename'],
                        mimetype=file_metadata['file_type']
                    )
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'File download failed: {str(e)}'}), 500
        
        @self.app.route('/api/files', methods=['GET'])
        def list_user_files():
            """Get files for current user"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                files = self.db.get_user_files(user_id)
                return jsonify({'files': files})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get files: {str(e)}'}), 500
        
        @self.app.route('/api/groups/<int:group_id>/files', methods=['GET'])
        def list_group_files(group_id):
            """Get files for a group"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Check if user is member of group
                if not self.db.is_group_member(group_id, user_id):
                    return jsonify({'error': 'Access denied: not a group member'}), 403
                
                files = self.db.get_group_files(group_id)
                return jsonify({'files': files})
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'Failed to get group files: {str(e)}'}), 500
        
        @self.app.route('/api/files/<int:file_id>', methods=['DELETE'])
        def delete_file(file_id):
            """Delete a file (only uploader can delete)"""
            try:
                # Verify token
                token = request.headers.get('Authorization')
                if not token or not token.startswith('Bearer '):
                    return jsonify({'error': 'Token required'}), 401
                
                token = token.split(' ')[1]
                decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                user_id = decoded['user_id']
                
                # Get file metadata to check ownership
                file_metadata = self.db.get_file_metadata(file_id)
                if not file_metadata:
                    return jsonify({'error': 'File not found'}), 404
                
                # Check if user is the uploader
                if file_metadata['uploader_id'] != user_id:
                    return jsonify({'error': 'Access denied: only uploader can delete files'}), 403
                
                # Deactivate file in database
                success = self.db.deactivate_file(file_id, user_id)
                
                if success:
                    # Optionally delete physical file from disk
                    file_path = os.path.join(self.file_storage_path, file_metadata['filename'])
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                    except Exception as e:
                        print(f"Warning: Could not delete physical file: {e}")
                    
                    return jsonify({'message': 'File deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete file'}), 500
            
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'error': 'Invalid token'}), 401
            except Exception as e:
                return jsonify({'error': f'File deletion failed: {str(e)}'}), 500
    
    def setup_websocket_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            print(f"Client connected: {request.sid}")
            emit('status', {'message': 'Connected to server', 'timestamp': datetime.now().isoformat()})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            print(f"Client disconnected: {request.sid}")
            # Remove from active sessions
            disconnected_user = None
            for username, sid in list(self.active_sessions.items()):
                if sid == request.sid:
                    disconnected_user = username
                    del self.active_sessions[username]
                    break
            
            if disconnected_user:
                print(f"User {disconnected_user} disconnected")
        
        @self.socketio.on('join')
        def handle_join(data):
            """Handle user joining (authentication via WebSocket)"""
            try:
                username = data.get('username')
                token = data.get('token')
                
                if not username or not token:
                    emit('error', {'message': 'Username and token required'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Token mismatch'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Add to active sessions
                self.active_sessions[username] = request.sid
                print(f"User {username} joined with session {request.sid}")
                
                emit('status', {
                    'message': f'Joined as {username}',
                    'online_users': list(self.active_sessions.keys()),
                    'timestamp': datetime.now().isoformat()
                })
                
                # Notify other users
                for other_user, other_sid in self.active_sessions.items():
                    if other_user != username:
                        self.socketio.emit('user_online', {
                            'username': username,
                            'timestamp': datetime.now().isoformat()
                        }, room=other_sid)
            
            except Exception as e:
                emit('error', {'message': f'Join failed: {str(e)}'})
        
        @self.socketio.on('send_message')
        def handle_message(data):
            """Handle encrypted message sending"""
            try:
                sender = data.get('sender')
                recipient = data.get('recipient')
                encrypted_message = data.get('encrypted_message')
                token = data.get('token')
                
                if not all([sender, recipient, encrypted_message, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token and sender
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != sender:
                        emit('error', {'message': 'Unauthorized sender'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Get sender and recipient from database
                sender_user = self.db.get_user_by_username(sender)
                recipient_user = self.db.get_user_by_username(recipient)
                
                if not sender_user or not recipient_user:
                    emit('error', {'message': 'Invalid sender or recipient'})
                    return
                
                # Parse encrypted message
                try:
                    encrypted_data = json.loads(encrypted_message)
                    if not all(key in encrypted_data for key in ['ciphertext', 'nonce', 'message_number']):
                        emit('error', {'message': 'Invalid message format'})
                        return
                except json.JSONDecodeError:
                    emit('error', {'message': 'Invalid message format'})
                    return
                
                # Store message in database
                self.db.store_message(
                    sender_user['id'],
                    recipient_user['id'],
                    encrypted_data['ciphertext'],
                    encrypted_data['nonce'],
                    encrypted_data['message_number']
                )
                
                # Update session activity
                self.db.update_session_activity(sender_user['id'], recipient_user['id'])
                
                # Forward to recipient if online
                if recipient in self.active_sessions:
                    self.socketio.emit('new_message', {
                        'sender': sender,
                        'encrypted_message': encrypted_message,
                        'timestamp': datetime.now().isoformat(),
                        'message_id': f"{sender_user['id']}_{recipient_user['id']}_{datetime.now().timestamp()}"
                    }, room=self.active_sessions[recipient])
                    
                    print(f"Message forwarded from {sender} to {recipient}")
                else:
                    print(f"Recipient {recipient} is offline, message stored")
                
                # Confirm to sender
                emit('message_sent', {
                    'recipient': recipient,
                    'timestamp': datetime.now().isoformat()
                })
            
            except Exception as e:
                print(f"Error handling message: {str(e)}")
                emit('error', {'message': f'Message handling failed: {str(e)}'})
        
        @self.socketio.on('start_session')
        def handle_start_session(data):
            """Handle session initialization request (send chat request to partner)"""
            try:
                username = data.get('username')
                partner = data.get('partner')
                root_key = data.get('root_key')
                token = data.get('token')
                
                if not all([username, partner, root_key, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Get users
                user = self.db.get_user_by_username(username)
                partner_user = self.db.get_user_by_username(partner)
                
                if not user or not partner_user:
                    emit('error', {'message': 'Invalid users'})
                    return
                
                # Send chat request to partner if online
                if partner in self.active_sessions:
                    self.socketio.emit('chat_request', {
                        'from_user': username,
                        'from_user_id': user['id'],
                        'root_key': root_key,  # Include root key for when accepted
                        'timestamp': datetime.now().isoformat(),
                        'message': f'{username} wants to start a secure chat with you'
                    }, room=self.active_sessions[partner])
                    
                    # Confirm to requester
                    emit('chat_request_sent', {
                        'partner': partner,
                        'message': f'Chat request sent to {partner}',
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    print(f"Chat request sent from {username} to {partner}")
                else:
                    emit('error', {'message': f'{partner} is not online'})
            
            except Exception as e:
                emit('error', {'message': f'Failed to send chat request: {str(e)}'})
        
        @self.socketio.on('accept_chat_request')
        def handle_accept_chat_request(data):
            """Handle accepting a chat request"""
            try:
                username = data.get('username')  # User accepting the request
                requester = data.get('requester')  # User who sent the request
                root_key = data.get('root_key')
                token = data.get('token')
                
                if not all([username, requester, root_key, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Get users
                user = self.db.get_user_by_username(username)
                requester_user = self.db.get_user_by_username(requester)
                
                if not user or not requester_user:
                    emit('error', {'message': 'Invalid users'})
                    return
                
                # Create session
                success = self.db.create_session(user['id'], requester_user['id'], root_key)
                
                if success:
                    # Notify both users that session is established
                    session_data = {
                        'partner': requester,
                        'root_key': root_key,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Notify accepter
                    emit('session_established', session_data)
                    
                    # Notify requester
                    if requester in self.active_sessions:
                        requester_session_data = {
                            'partner': username,
                            'root_key': root_key,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.socketio.emit('session_established', requester_session_data, 
                                         room=self.active_sessions[requester])
                    
                    print(f"Chat session established between {username} and {requester}")
                else:
                    emit('error', {'message': 'Failed to create session'})
            
            except Exception as e:
                emit('error', {'message': f'Failed to accept chat request: {str(e)}'})
        
        @self.socketio.on('decline_chat_request')
        def handle_decline_chat_request(data):
            """Handle declining a chat request"""
            try:
                username = data.get('username')  # User declining the request
                requester = data.get('requester')  # User who sent the request
                token = data.get('token')
                
                if not all([username, requester, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Notify requester that request was declined
                if requester in self.active_sessions:
                    self.socketio.emit('chat_request_declined', {
                        'partner': username,
                        'message': f'{username} declined your chat request',
                        'timestamp': datetime.now().isoformat()
                    }, room=self.active_sessions[requester])
                
                # Confirm to decliner
                emit('chat_request_declined_sent', {
                    'requester': requester,
                    'message': f'You declined the chat request from {requester}',
                    'timestamp': datetime.now().isoformat()
                })
                
                print(f"Chat request from {requester} declined by {username}")
            
            except Exception as e:
                emit('error', {'message': f'Failed to decline chat request: {str(e)}'})
        
        @self.socketio.on('get_online_users')
        def handle_get_online_users():
            """Get list of online users"""
            emit('online_users', {
                'users': list(self.active_sessions.keys()),
                'timestamp': datetime.now().isoformat()
            })
        
        @self.socketio.on('join_group_room')
        def handle_join_group_room(data):
            """Join a group room for real-time messaging"""
            try:
                username = data.get('username')
                group_id = data.get('group_id')
                token = data.get('token')
                
                if not all([username, group_id, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Check if user is member of group
                user = self.db.get_user_by_username(username)
                if not user or not self.db.is_group_member(group_id, user['id']):
                    emit('error', {'message': 'Access denied: not a group member'})
                    return
                
                # Join the group room
                room_name = f"group_{group_id}"
                self.socketio.server.enter_room(request.sid, room_name)
                
                # Get group info and send to user
                group = self.db.get_group_by_id(group_id)
                if group:
                    emit('group_joined', {
                        'group': group,
                        'room': room_name,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    # Notify other group members
                    self.socketio.emit('user_joined_group', {
                        'username': username,
                        'group_id': group_id,
                        'group_name': group['name'],
                        'timestamp': datetime.now().isoformat()
                    }, room=room_name, skip_sid=request.sid)
                    
                    print(f"User {username} joined group {group_id} room")
                else:
                    emit('error', {'message': 'Group not found'})
            
            except Exception as e:
                emit('error', {'message': f'Failed to join group room: {str(e)}'})
        
        @self.socketio.on('leave_group_room')
        def handle_leave_group_room(data):
            """Leave a group room"""
            try:
                username = data.get('username')
                group_id = data.get('group_id')
                token = data.get('token')
                
                if not all([username, group_id, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Leave the group room
                room_name = f"group_{group_id}"
                self.socketio.server.leave_room(request.sid, room_name)
                
                emit('group_left', {
                    'group_id': group_id,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Notify other group members
                self.socketio.emit('user_left_group', {
                    'username': username,
                    'group_id': group_id,
                    'timestamp': datetime.now().isoformat()
                }, room=room_name)
                
                print(f"User {username} left group {group_id} room")
            
            except Exception as e:
                emit('error', {'message': f'Failed to leave group room: {str(e)}'})
        
        @self.socketio.on('send_group_message')
        def handle_group_message(data):
            """Handle encrypted group message sending"""
            try:
                sender = data.get('sender')
                group_id = data.get('group_id')
                encrypted_message = data.get('encrypted_message')
                token = data.get('token')
                
                if not all([sender, group_id, encrypted_message, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token and sender
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != sender:
                        emit('error', {'message': 'Unauthorized sender'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Get sender from database
                sender_user = self.db.get_user_by_username(sender)
                if not sender_user:
                    emit('error', {'message': 'Invalid sender'})
                    return
                
                # Check if sender is member of group
                if not self.db.is_group_member(group_id, sender_user['id']):
                    emit('error', {'message': 'Access denied: not a group member'})
                    return
                
                # Parse encrypted message
                try:
                    encrypted_data = json.loads(encrypted_message)
                    required_fields = ['ciphertext', 'nonce', 'message_number', 'group_id']
                    if not all(key in encrypted_data for key in required_fields):
                        emit('error', {'message': 'Invalid group message format'})
                        return
                except json.JSONDecodeError:
                    emit('error', {'message': 'Invalid message format'})
                    return
                
                # Store message in database
                self.db.store_group_message(
                    group_id,
                    sender_user['id'],
                    encrypted_data['ciphertext'],
                    encrypted_data['nonce'],
                    encrypted_data['message_number']
                )
                
                # Broadcast to all group members
                room_name = f"group_{group_id}"
                message_data = {
                    'sender': sender,
                    'group_id': group_id,
                    'encrypted_message': encrypted_message,
                    'timestamp': datetime.now().isoformat(),
                    'message_id': f"group_{group_id}_{sender_user['id']}_{datetime.now().timestamp()}"
                }
                
                self.socketio.emit('new_group_message', message_data, room=room_name, skip_sid=request.sid)
                
                # Confirm to sender
                emit('group_message_sent', {
                    'group_id': group_id,
                    'timestamp': datetime.now().isoformat()
                })
                
                print(f"Group message sent from {sender} to group {group_id}")
            
            except Exception as e:
                print(f"Error handling group message: {str(e)}")
                emit('error', {'message': f'Group message handling failed: {str(e)}'})
        
        @self.socketio.on('get_group_info')
        def handle_get_group_info(data):
            """Get group information and members"""
            try:
                username = data.get('username')
                group_id = data.get('group_id')
                token = data.get('token')
                
                if not all([username, group_id, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                # Check if user is member of group
                user = self.db.get_user_by_username(username)
                if not user or not self.db.is_group_member(group_id, user['id']):
                    emit('error', {'message': 'Access denied: not a group member'})
                    return
                
                # Get group info and members
                group = self.db.get_group_by_id(group_id)
                members = self.db.get_group_members(group_id)
                
                if group:
                    emit('group_info', {
                        'group': group,
                        'members': members,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    emit('error', {'message': 'Group not found'})
            
            except Exception as e:
                emit('error', {'message': f'Failed to get group info: {str(e)}'})
        
        # File sharing WebSocket handlers
        
        @self.socketio.on('get_user_files')
        def handle_get_user_files(data):
            """Get files for a user via WebSocket"""
            try:
                username = data.get('username')
                token = data.get('token')
                
                if not all([username, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                user = self.db.get_user_by_username(username)
                if not user:
                    emit('error', {'message': 'User not found'})
                    return
                
                files = self.db.get_user_files(user['id'])
                emit('user_files', {
                    'files': files,
                    'timestamp': datetime.now().isoformat()
                })
            
            except Exception as e:
                emit('error', {'message': f'Failed to get user files: {str(e)}'})
        
        @self.socketio.on('get_group_files')
        def handle_get_group_files(data):
            """Get files for a group via WebSocket"""
            try:
                username = data.get('username')
                group_id = data.get('group_id')
                token = data.get('token')
                
                if not all([username, group_id, token]):
                    emit('error', {'message': 'Missing required fields'})
                    return
                
                # Verify token
                try:
                    decoded = jwt.decode(token, self.app.config['SECRET_KEY'], algorithms=['HS256'])
                    if decoded['username'] != username:
                        emit('error', {'message': 'Unauthorized'})
                        return
                except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                    emit('error', {'message': 'Invalid or expired token'})
                    return
                
                user = self.db.get_user_by_username(username)
                if not user or not self.db.is_group_member(group_id, user['id']):
                    emit('error', {'message': 'Access denied: not a group member'})
                    return
                
                files = self.db.get_group_files(group_id)
                emit('group_files', {
                    'group_id': group_id,
                    'files': files,
                    'timestamp': datetime.now().isoformat()
                })
            
            except Exception as e:
                emit('error', {'message': f'Failed to get group files: {str(e)}'})
    
    def run(self, host='127.0.0.1', port=5000, debug=False):
        """Start the server"""
        print(f"🚀 Starting Secure Chat Server on {host}:{port}")
        print(f"🔒 Secret key configured: {'Yes' if self.app.config['SECRET_KEY'] else 'No'}")
        print(f"📁 Database: {self.db.db_path}")
        print(f"🌐 CORS enabled for WebSocket connections")
        print("=" * 50)
        
        try:
            self.socketio.run(self.app, host=host, port=port, debug=debug)
        except Exception as e:
            print(f"❌ Server failed to start: {str(e)}")
            raise 