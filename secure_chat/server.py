"""
Server Module
Flask server with WebSocket support for real-time secure messaging
"""

import os
import json
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import jwt

from .crypto_core import CryptoCore
from .database import Database


class SecureChatServer:
    """Flask server with WebSocket support"""
    
    def __init__(self, secret_key: str = None):
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = secret_key or secrets.token_hex(32)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.db = Database()
        self.crypto = CryptoCore()
        self.active_sessions = {}  # username -> socket_id mapping
        
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