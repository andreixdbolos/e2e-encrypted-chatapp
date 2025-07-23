"""
Security Module
Message validation, replay attack protection, and security auditing
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import hashlib
import secrets


class MessageValidator:
    """Validate message integrity and authenticity"""
    
    @staticmethod
    def validate_message_format(encrypted_data: Dict) -> bool:
        """Validate encrypted message structure"""
        required_fields = ['ciphertext', 'nonce', 'message_number']
        
        if not isinstance(encrypted_data, dict):
            return False
        
        # Check required fields exist
        if not all(field in encrypted_data for field in required_fields):
            return False
        
        # Validate field types and formats
        try:
            # Check message number is valid integer
            msg_num = encrypted_data['message_number']
            if not isinstance(msg_num, int) or msg_num < 0:
                return False
            
            # Check ciphertext and nonce are valid base64 strings
            import base64
            base64.b64decode(encrypted_data['ciphertext'])
            base64.b64decode(encrypted_data['nonce'])
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def check_replay_attack(message_number: int, expected_number: int) -> bool:
        """Simple replay attack detection"""
        return message_number >= expected_number
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        if not username or not isinstance(username, str):
            return False
        
        # Check length
        if len(username) < 3 or len(username) > 30:
            return False
        
        # Check allowed characters (alphanumeric, underscore, hyphen)
        import re
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', username))
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, bool]:
        """Validate password strength"""
        checks = {
            'length': len(password) >= 8,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'digit': any(c.isdigit() for c in password),
            'special': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        }
        
        checks['strong'] = sum(checks.values()) >= 4
        return checks
    
    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """Sanitize text input"""
        if not text:
            return ""
        
        # Remove null bytes and control characters
        text = text.replace('\x00', '').replace('\r', '')
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length]
        
        return text.strip()


class RateLimiter:
    """Rate limiting for API endpoints and messages"""
    
    def __init__(self):
        self.request_counts = {}  # IP/user -> [(timestamp, endpoint), ...]
        self.cleanup_interval = timedelta(minutes=5)
        self.last_cleanup = datetime.now()
    
    def is_allowed(self, identifier: str, endpoint: str, max_requests: int = 10, window_minutes: int = 1) -> bool:
        """Check if request is allowed based on rate limits"""
        now = datetime.now()
        
        # Cleanup old entries periodically
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries()
            self.last_cleanup = now
        
        # Get request history for this identifier
        if identifier not in self.request_counts:
            self.request_counts[identifier] = []
        
        # Filter requests within the time window for this endpoint
        window_start = now - timedelta(minutes=window_minutes)
        recent_requests = [
            (timestamp, ep) for timestamp, ep in self.request_counts[identifier]
            if timestamp >= window_start and ep == endpoint
        ]
        
        # Check if limit exceeded
        if len(recent_requests) >= max_requests:
            return False
        
        # Add this request
        self.request_counts[identifier].append((now, endpoint))
        return True
    
    def _cleanup_old_entries(self):
        """Remove old entries to prevent memory bloat"""
        cutoff = datetime.now() - timedelta(hours=1)
        
        for identifier in list(self.request_counts.keys()):
            self.request_counts[identifier] = [
                (timestamp, endpoint) for timestamp, endpoint in self.request_counts[identifier]
                if timestamp >= cutoff
            ]
            
            # Remove empty entries
            if not self.request_counts[identifier]:
                del self.request_counts[identifier]


class SecurityAuditor:
    """Security auditing and logging"""
    
    def __init__(self, max_log_entries: int = 10000):
        self.security_log = []
        self.max_log_entries = max_log_entries
        self.suspicious_activity = {}  # IP/user -> count
        
    def log_security_event(self, event_type: str, details: str, severity: str = "INFO", 
                          user: str = None, ip: str = None):
        """Log security-related events"""
        timestamp = datetime.now().isoformat()
        event = {
            'timestamp': timestamp,
            'type': event_type,
            'details': details,
            'severity': severity,
            'user': user,
            'ip': ip,
            'event_id': self._generate_event_id()
        }
        
        # Add to log
        self.security_log.append(event)
        
        # Maintain log size
        if len(self.security_log) > self.max_log_entries:
            self.security_log = self.security_log[-self.max_log_entries:]
        
        # Track suspicious activity
        if severity in ['WARNING', 'ERROR', 'CRITICAL']:
            identifier = user or ip or 'unknown'
            self.suspicious_activity[identifier] = self.suspicious_activity.get(identifier, 0) + 1
        
        # Print to console for immediate visibility
        print(f"🔒 SECURITY [{severity}] [{timestamp}]: {event_type} - {details}")
        
        return event['event_id']
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        return hashlib.sha256(
            f"{datetime.now().timestamp()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
    
    def get_security_report(self, hours: int = 24) -> Dict:
        """Get security audit report for specified time period"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        # Filter events within time period
        recent_events = [
            event for event in self.security_log
            if datetime.fromisoformat(event['timestamp']) >= cutoff
        ]
        
        # Count events by type and severity
        event_types = {}
        severity_counts = {}
        
        for event in recent_events:
            event_type = event['type']
            severity = event['severity']
            
            event_types[event_type] = event_types.get(event_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Identify top suspicious actors
        suspicious_actors = sorted(
            self.suspicious_activity.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            'report_generated': datetime.now().isoformat(),
            'time_period_hours': hours,
            'total_events': len(recent_events),
            'event_types': event_types,
            'severity_counts': severity_counts,
            'suspicious_actors': suspicious_actors,
            'recent_events': recent_events[-50:]  # Last 50 events
        }
    
    def get_events_by_user(self, username: str, hours: int = 24) -> List[Dict]:
        """Get security events for specific user"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        return [
            event for event in self.security_log
            if event.get('user') == username and 
               datetime.fromisoformat(event['timestamp']) >= cutoff
        ]
    
    def check_suspicious_activity(self, identifier: str, threshold: int = 10) -> bool:
        """Check if an actor has exceeded suspicious activity threshold"""
        return self.suspicious_activity.get(identifier, 0) >= threshold


class SessionManager:
    """Manage user sessions and security"""
    
    def __init__(self):
        self.active_sessions = {}  # session_id -> session_data
        self.user_sessions = {}   # username -> set of session_ids
        self.session_timeout = timedelta(hours=24)
    
    def create_session(self, username: str, ip: str = None) -> str:
        """Create new session"""
        session_id = secrets.token_urlsafe(32)
        
        session_data = {
            'username': username,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'ip': ip,
            'message_count': 0
        }
        
        # Store session
        self.active_sessions[session_id] = session_data
        
        # Track user sessions
        if username not in self.user_sessions:
            self.user_sessions[username] = set()
        self.user_sessions[username].add(session_id)
        
        return session_id
    
    def validate_session(self, session_id: str) -> Optional[Dict]:
        """Validate and return session data"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id]
        
        # Check timeout
        if datetime.now() - session['last_activity'] > self.session_timeout:
            self.invalidate_session(session_id)
            return None
        
        # Update activity
        session['last_activity'] = datetime.now()
        return session
    
    def invalidate_session(self, session_id: str):
        """Invalidate session"""
        if session_id in self.active_sessions:
            username = self.active_sessions[session_id]['username']
            del self.active_sessions[session_id]
            
            if username in self.user_sessions:
                self.user_sessions[username].discard(session_id)
                if not self.user_sessions[username]:
                    del self.user_sessions[username]
    
    def invalidate_user_sessions(self, username: str):
        """Invalidate all sessions for a user"""
        if username in self.user_sessions:
            session_ids = list(self.user_sessions[username])
            for session_id in session_ids:
                self.invalidate_session(session_id)
    
    def get_user_session_count(self, username: str) -> int:
        """Get number of active sessions for user"""
        return len(self.user_sessions.get(username, set()))
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        now = datetime.now()
        expired_sessions = []
        
        for session_id, session_data in self.active_sessions.items():
            if now - session_data['last_activity'] > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)
        
        return len(expired_sessions)


class InputSanitizer:
    """Sanitize and validate user inputs"""
    
    @staticmethod
    def sanitize_message(message: str) -> str:
        """Sanitize chat message"""
        if not message:
            return ""
        
        # Remove null bytes and dangerous characters
        message = message.replace('\x00', '').replace('\r', '')
        
        # Limit length
        max_length = 5000  # 5KB message limit
        if len(message) > max_length:
            message = message[:max_length]
        
        return message.strip()
    
    @staticmethod
    def sanitize_username(username: str) -> str:
        """Sanitize username"""
        if not username:
            return ""
        
        # Remove whitespace and convert to lowercase
        username = username.strip().lower()
        
        # Remove non-alphanumeric characters except underscore and hyphen
        import re
        username = re.sub(r'[^a-z0-9_-]', '', username)
        
        # Limit length
        if len(username) > 30:
            username = username[:30]
        
        return username
    
    @staticmethod
    def detect_spam(message: str) -> bool:
        """Simple spam detection"""
        if not message:
            return False
        
        # Check for excessive repetition
        words = message.lower().split()
        if len(words) >= 5:  # Changed from > 10 to >= 5
            unique_words = set(words)
            if len(unique_words) / len(words) < 0.3:  # Less than 30% unique words
                return True
        
        # Check for excessive uppercase
        if len(message) > 20 and sum(c.isupper() for c in message) / len(message) > 0.7:
            return True
        
        # Check for suspicious patterns
        spam_patterns = [
            'click here', 'free money', 'urgent', 'congratulations',
            'winner', 'lottery', 'million dollars'
        ]
        
        message_lower = message.lower()
        spam_score = sum(1 for pattern in spam_patterns if pattern in message_lower)
        
        return spam_score >= 2


# Global instances for use across the application
message_validator = MessageValidator()
rate_limiter = RateLimiter()
security_auditor = SecurityAuditor()
session_manager = SessionManager()
input_sanitizer = InputSanitizer() 