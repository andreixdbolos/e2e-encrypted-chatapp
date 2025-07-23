"""
Secure Chat Application Package
Signal-inspired end-to-end encrypted messaging system

This package provides a complete secure messaging solution with:
- End-to-end encryption using ChaCha20-Poly1305
- Forward secrecy with Double Ratchet inspired protocol
- Real-time messaging via WebSocket
- Modern GUI client with dark theme
- Comprehensive security features
- Extensive testing and monitoring
"""

__version__ = "1.0.0"
__author__ = "Secure Chat Development Team"
__description__ = "Signal-inspired E2E encrypted messaging application"

# Core components
from .crypto_core import CryptoCore
from .database import Database
from .server import SecureChatServer
from .client import SecureChatClient
from .security import (
    MessageValidator, SecurityAuditor, RateLimiter,
    InputSanitizer, SessionManager
)
from .tests import SecureChatTester, create_comprehensive_demo

# Package exports
__all__ = [
    'CryptoCore',
    'Database', 
    'SecureChatServer',
    'SecureChatClient',
    'MessageValidator',
    'SecurityAuditor',
    'RateLimiter',
    'InputSanitizer',
    'SessionManager',
    'SecureChatTester',
    'create_comprehensive_demo'
]


def get_version():
    """Get package version"""
    return __version__


def get_info():
    """Get package information"""
    return {
        'name': 'secure_chat',
        'version': __version__,
        'description': __description__,
        'author': __author__,
        'features': [
            'End-to-end encryption (ChaCha20-Poly1305)',
            'Forward secrecy (Double Ratchet inspired)',
            'Real-time messaging (WebSocket)',
            'Security monitoring and auditing',
            'Modern GUI interface',
            'Comprehensive testing suite'
        ]
    } 