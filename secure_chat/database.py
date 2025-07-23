"""
Database Layer Module
Handle user data and message storage with SQLite
"""

import sqlite3
import base64
from typing import Dict, List, Optional
import bcrypt
from datetime import datetime


class Database:
    """Handle user data and message storage"""
    
    def __init__(self, db_path: str = "secure_chat.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                identity_public_key TEXT NOT NULL,
                prekey_public TEXT,
                prekey_private TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                recipient_id INTEGER,
                encrypted_content TEXT NOT NULL,
                nonce TEXT NOT NULL,
                message_number INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id)
            )
        ''')
        
        # Sessions table for tracking active chat sessions
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER,
                user2_id INTEGER,
                root_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user1_id) REFERENCES users (id),
                FOREIGN KEY (user2_id) REFERENCES users (id)
            )
        ''')
        
        # Groups table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_by INTEGER,
                group_key TEXT NOT NULL,
                max_members INTEGER DEFAULT 50,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        ''')
        
        # Group members table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                user_id INTEGER,
                role TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(group_id, user_id)
            )
        ''')
        
        # Group messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                sender_id INTEGER,
                encrypted_content TEXT NOT NULL,
                nonce TEXT NOT NULL,
                message_number INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (sender_id) REFERENCES users (id)
            )
        ''')
        
        # Shared files table for encrypted file sharing
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                file_type TEXT,
                encrypted_key TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                uploader_id INTEGER,
                recipient_id INTEGER,
                group_id INTEGER,
                upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                download_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                expires_at TIMESTAMP,
                FOREIGN KEY (uploader_id) REFERENCES users (id),
                FOREIGN KEY (recipient_id) REFERENCES users (id),
                FOREIGN KEY (group_id) REFERENCES groups (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username: str, password: str, identity_public_key: str, 
                   prekey_public: str, prekey_private: str) -> bool:
        """Create new user account"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Hash password
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, identity_public_key, 
                                 prekey_public, prekey_private)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, identity_public_key, prekey_public, prekey_private))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user and return user data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            return {
                'id': user[0],
                'username': user[1],
                'identity_public_key': user[3],
                'prekey_public': user[4]
            }
        return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, identity_public_key, prekey_public FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'identity_public_key': user[2],
                'prekey_public': user[3]
            }
        return None
    
    def get_user_prekeys(self, username: str) -> Optional[Dict]:
        """Get user's prekeys for key exchange"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT prekey_public FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {'prekey_public': result[0]}
        return None
    
    def store_message(self, sender_id: int, recipient_id: int, encrypted_content: str,
                     nonce: str, message_number: int):
        """Store encrypted message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO messages (sender_id, recipient_id, encrypted_content, nonce, message_number)
            VALUES (?, ?, ?, ?, ?)
        ''', (sender_id, recipient_id, encrypted_content, nonce, message_number))
        
        conn.commit()
        conn.close()
    
    def get_messages(self, user1_id: int, user2_id: int, limit: int = 50) -> List[Dict]:
        """Get messages between two users"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT m.*, u1.username as sender_username, u2.username as recipient_username
            FROM messages m
            JOIN users u1 ON m.sender_id = u1.id
            JOIN users u2 ON m.recipient_id = u2.id
            WHERE (m.sender_id = ? AND m.recipient_id = ?) OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.timestamp DESC
            LIMIT ?
        ''', (user1_id, user2_id, user2_id, user1_id, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return [{
            'id': msg[0],
            'sender_id': msg[1],
            'recipient_id': msg[2],
            'encrypted_content': msg[3],
            'nonce': msg[4],
            'message_number': msg[5],
            'timestamp': msg[6],
            'sender_username': msg[7],
            'recipient_username': msg[8]
        } for msg in reversed(messages)]
    
    def create_session(self, user1_id: int, user2_id: int, root_key: str) -> bool:
        """Create a new chat session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if session already exists
            cursor.execute('''
                SELECT id FROM sessions 
                WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
            ''', (user1_id, user2_id, user2_id, user1_id))
            
            existing = cursor.fetchone()
            if existing:
                # Update existing session
                cursor.execute('''
                    UPDATE sessions SET root_key = ?, last_activity = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (root_key, existing[0]))
            else:
                # Create new session
                cursor.execute('''
                    INSERT INTO sessions (user1_id, user2_id, root_key)
                    VALUES (?, ?, ?)
                ''', (user1_id, user2_id, root_key))
            
            conn.commit()
            conn.close()
            return True
        except Exception:
            conn.close()
            return False
    
    def get_session(self, user1_id: int, user2_id: int) -> Optional[Dict]:
        """Get chat session between two users"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM sessions 
            WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        ''', (user1_id, user2_id, user2_id, user1_id))
        
        session = cursor.fetchone()
        conn.close()
        
        if session:
            return {
                'id': session[0],
                'user1_id': session[1],
                'user2_id': session[2],
                'root_key': session[3],
                'created_at': session[4],
                'last_activity': session[5]
            }
        return None
    
    def update_session_activity(self, user1_id: int, user2_id: int):
        """Update last activity for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sessions SET last_activity = CURRENT_TIMESTAMP
            WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
        ''', (user1_id, user2_id, user2_id, user1_id))
        
        conn.commit()
        conn.close()
    
    def get_all_users(self) -> List[Dict]:
        """Get all users (for testing/demo purposes)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, username, created_at FROM users ORDER BY username')
        users = cursor.fetchall()
        conn.close()
        
        return [{
            'id': user[0],
            'username': user[1],
            'created_at': user[2]
        } for user in users] 
    
    def create_group(self, name: str, description: str, created_by: int, group_key: str) -> Optional[int]:
        """Create a new group"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO groups (name, description, created_by, group_key)
                VALUES (?, ?, ?, ?)
            ''', (name, description, created_by, group_key))
            
            group_id = cursor.lastrowid
            
            # Add creator as admin
            cursor.execute('''
                INSERT INTO group_members (group_id, user_id, role)
                VALUES (?, ?, 'admin')
            ''', (group_id, created_by))
            
            conn.commit()
            conn.close()
            return group_id
        except sqlite3.IntegrityError:
            conn.close()
            return None
    
    def join_group(self, group_id: int, user_id: int) -> bool:
        """Add user to group"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if group exists and has space
            cursor.execute('SELECT max_members FROM groups WHERE id = ?', (group_id,))
            group_info = cursor.fetchone()
            if not group_info:
                conn.close()
                return False
            
            # Check current member count
            cursor.execute('SELECT COUNT(*) FROM group_members WHERE group_id = ?', (group_id,))
            member_count = cursor.fetchone()[0]
            
            if member_count >= group_info[0]:
                conn.close()
                return False
            
            cursor.execute('''
                INSERT INTO group_members (group_id, user_id, role)
                VALUES (?, ?, 'member')
            ''', (group_id, user_id))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False
    
    def leave_group(self, group_id: int, user_id: int) -> bool:
        """Remove user from group"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM group_members 
                WHERE group_id = ? AND user_id = ?
            ''', (group_id, user_id))
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            return affected_rows > 0
        except Exception:
            conn.close()
            return False
    
    def get_user_groups(self, user_id: int) -> List[Dict]:
        """Get all groups a user is member of"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT g.*, gm.role, gm.joined_at, u.username as creator_name,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            JOIN users u ON g.created_by = u.id
            WHERE gm.user_id = ?
            ORDER BY gm.joined_at DESC
        ''', (user_id,))
        
        groups = cursor.fetchall()
        conn.close()
        
        return [{
            'id': group[0],
            'name': group[1],
            'description': group[2],
            'created_by': group[3],
            'group_key': group[4],
            'max_members': group[5],
            'created_at': group[6],
            'role': group[7],
            'joined_at': group[8],
            'creator_name': group[9],
            'member_count': group[10]
        } for group in groups]
    
    def get_group_by_id(self, group_id: int) -> Optional[Dict]:
        """Get group information by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT g.*, u.username as creator_name,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
            FROM groups g
            JOIN users u ON g.created_by = u.id
            WHERE g.id = ?
        ''', (group_id,))
        
        group = cursor.fetchone()
        conn.close()
        
        if group:
            return {
                'id': group[0],
                'name': group[1],
                'description': group[2],
                'created_by': group[3],
                'group_key': group[4],
                'max_members': group[5],
                'created_at': group[6],
                'creator_name': group[7],
                'member_count': group[8]
            }
        return None
    
    def get_group_members(self, group_id: int) -> List[Dict]:
        """Get all members of a group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username, gm.role, gm.joined_at
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            WHERE gm.group_id = ?
            ORDER BY gm.joined_at ASC
        ''', (group_id,))
        
        members = cursor.fetchall()
        conn.close()
        
        return [{
            'user_id': member[0],
            'username': member[1],
            'role': member[2],
            'joined_at': member[3]
        } for member in members]
    
    def is_group_member(self, group_id: int, user_id: int) -> bool:
        """Check if user is member of group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 1 FROM group_members 
            WHERE group_id = ? AND user_id = ?
        ''', (group_id, user_id))
        
        result = cursor.fetchone()
        conn.close()
        return result is not None
    
    def store_group_message(self, group_id: int, sender_id: int, encrypted_content: str,
                           nonce: str, message_number: int):
        """Store encrypted group message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO group_messages (group_id, sender_id, encrypted_content, nonce, message_number)
            VALUES (?, ?, ?, ?, ?)
        ''', (group_id, sender_id, encrypted_content, nonce, message_number))
        
        conn.commit()
        conn.close()
    
    def get_group_messages(self, group_id: int, limit: int = 50) -> List[Dict]:
        """Get recent messages from a group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT gm.*, u.username as sender_username
            FROM group_messages gm
            JOIN users u ON gm.sender_id = u.id
            WHERE gm.group_id = ?
            ORDER BY gm.timestamp DESC
            LIMIT ?
        ''', (group_id, limit))
        
        messages = cursor.fetchall()
        conn.close()
        
        return [{
            'id': msg[0],
            'group_id': msg[1],
            'sender_id': msg[2],
            'encrypted_content': msg[3],
            'nonce': msg[4],
            'message_number': msg[5],
            'timestamp': msg[6],
            'sender_username': msg[7]
        } for msg in reversed(messages)]
    
    def search_groups(self, query: str, limit: int = 10) -> List[Dict]:
        """Search for groups by name"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT g.*, u.username as creator_name,
                   (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
            FROM groups g
            JOIN users u ON g.created_by = u.id
            WHERE g.name LIKE ?
            ORDER BY g.created_at DESC
            LIMIT ?
        ''', (f'%{query}%', limit))
        
        groups = cursor.fetchall()
        conn.close()
        
        return [{
            'id': group[0],
            'name': group[1],
            'description': group[2],
            'created_by': group[3],
            'group_key': group[4],
            'max_members': group[5],
            'created_at': group[6],
            'creator_name': group[7],
            'member_count': group[8]
        } for group in groups] 
    
    def store_file_metadata(self, filename: str, original_filename: str, file_size: int,
                           file_type: str, encrypted_key: str, file_hash: str,
                           uploader_id: int, recipient_id: int = None, group_id: int = None,
                           expires_hours: int = None) -> Optional[int]:
        """Store file metadata in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            expires_at = None
            if expires_hours:
                from datetime import datetime, timedelta
                expires_at = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
            
            cursor.execute('''
                INSERT INTO shared_files (filename, original_filename, file_size, file_type,
                                        encrypted_key, file_hash, uploader_id, recipient_id, 
                                        group_id, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (filename, original_filename, file_size, file_type, encrypted_key, file_hash,
                  uploader_id, recipient_id, group_id, expires_at))
            
            file_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return file_id
        
        except Exception as e:
            print(f"Error storing file metadata: {e}")
            conn.close()
            return None
    
    def get_file_metadata(self, file_id: int) -> Optional[Dict]:
        """Get file metadata by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sf.*, u.username as uploader_name
            FROM shared_files sf
            JOIN users u ON sf.uploader_id = u.id
            WHERE sf.id = ? AND sf.is_active = 1
        ''', (file_id,))
        
        file_data = cursor.fetchone()
        conn.close()
        
        if file_data:
            return {
                'id': file_data[0],
                'filename': file_data[1],
                'original_filename': file_data[2],
                'file_size': file_data[3],
                'file_type': file_data[4],
                'encrypted_key': file_data[5],
                'file_hash': file_data[6],
                'uploader_id': file_data[7],
                'recipient_id': file_data[8],
                'group_id': file_data[9],
                'upload_timestamp': file_data[10],
                'download_count': file_data[11],
                'is_active': file_data[12],
                'expires_at': file_data[13],
                'uploader_name': file_data[14]
            }
        return None
    
    def get_user_files(self, user_id: int, include_received: bool = True) -> List[Dict]:
        """Get files uploaded by or shared with a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if include_received:
            cursor.execute('''
                SELECT sf.*, u.username as uploader_name
                FROM shared_files sf
                JOIN users u ON sf.uploader_id = u.id
                WHERE (sf.uploader_id = ? OR sf.recipient_id = ?) 
                AND sf.is_active = 1
                ORDER BY sf.upload_timestamp DESC
            ''', (user_id, user_id))
        else:
            cursor.execute('''
                SELECT sf.*, u.username as uploader_name
                FROM shared_files sf
                JOIN users u ON sf.uploader_id = u.id
                WHERE sf.uploader_id = ? AND sf.is_active = 1
                ORDER BY sf.upload_timestamp DESC
            ''', (user_id,))
        
        files = cursor.fetchall()
        conn.close()
        
        return [{
            'id': file_data[0],
            'filename': file_data[1],
            'original_filename': file_data[2],
            'file_size': file_data[3],
            'file_type': file_data[4],
            'encrypted_key': file_data[5],
            'file_hash': file_data[6],
            'uploader_id': file_data[7],
            'recipient_id': file_data[8],
            'group_id': file_data[9],
            'upload_timestamp': file_data[10],
            'download_count': file_data[11],
            'is_active': file_data[12],
            'expires_at': file_data[13],
            'uploader_name': file_data[14]
        } for file_data in files]
    
    def get_group_files(self, group_id: int) -> List[Dict]:
        """Get files shared in a group"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sf.*, u.username as uploader_name
            FROM shared_files sf
            JOIN users u ON sf.uploader_id = u.id
            WHERE sf.group_id = ? AND sf.is_active = 1
            ORDER BY sf.upload_timestamp DESC
        ''', (group_id,))
        
        files = cursor.fetchall()
        conn.close()
        
        return [{
            'id': file_data[0],
            'filename': file_data[1],
            'original_filename': file_data[2],
            'file_size': file_data[3],
            'file_type': file_data[4],
            'encrypted_key': file_data[5],
            'file_hash': file_data[6],
            'uploader_id': file_data[7],
            'recipient_id': file_data[8],
            'group_id': file_data[9],
            'upload_timestamp': file_data[10],
            'download_count': file_data[11],
            'is_active': file_data[12],
            'expires_at': file_data[13],
            'uploader_name': file_data[14]
        } for file_data in files]
    
    def increment_download_count(self, file_id: int):
        """Increment download counter for a file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE shared_files 
            SET download_count = download_count + 1 
            WHERE id = ?
        ''', (file_id,))
        
        conn.commit()
        conn.close()
    
    def deactivate_file(self, file_id: int, user_id: int) -> bool:
        """Deactivate/delete a file (only uploader can do this)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE shared_files 
                SET is_active = 0 
                WHERE id = ? AND uploader_id = ?
            ''', (file_id, user_id))
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            return affected_rows > 0
        
        except Exception:
            conn.close()
            return False
    
    def cleanup_expired_files(self) -> int:
        """Remove expired files and return count"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        from datetime import datetime
        now = datetime.now().isoformat()
        
        cursor.execute('''
            UPDATE shared_files 
            SET is_active = 0 
            WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1
        ''', (now,))
        
        expired_count = cursor.rowcount
        conn.commit()
        conn.close()
        return expired_count
    
    def can_access_file(self, file_id: int, user_id: int) -> bool:
        """Check if user can access a specific file"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if user is uploader, recipient, or member of the group
        cursor.execute('''
            SELECT sf.id
            FROM shared_files sf
            LEFT JOIN group_members gm ON sf.group_id = gm.group_id
            WHERE sf.id = ? AND sf.is_active = 1 
            AND (sf.uploader_id = ? OR sf.recipient_id = ? OR gm.user_id = ?)
        ''', (file_id, user_id, user_id, user_id))
        
        result = cursor.fetchone()
        conn.close()
        return result is not None 