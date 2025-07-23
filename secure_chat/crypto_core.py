import secrets
import base64
from typing import Dict, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class CryptoCore:
    """Implements simplified Double Ratchet Algorithm for E2E encryption"""
    
    def __init__(self):
        self.identity_key = None
        self.ephemeral_key = None
        self.root_key = None
        
        # Separate chains for sending and receiving
        self.sending_chain_key = None
        self.receiving_chain_key = None
        self.sending_message_number = 0
        self.receiving_message_number = 0
        
        # For backwards compatibility
        self.chain_key = None
        self.message_number = 0
        
        # Group encryption support
        self.group_keys = {}  # group_id -> group_key
        self.group_message_numbers = {}  # group_id -> message_number
    
    def generate_identity_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Curve25519 identity key pair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    def generate_prekey(self) -> Tuple[bytes, bytes]:
        """Generate prekey for X3DH key agreement"""
        return self.generate_identity_keypair()
    
    def x3dh_key_agreement(self, identity_private: bytes, prekey_public: bytes) -> bytes:
        """Simplified X3DH key agreement"""
        identity_key = x25519.X25519PrivateKey.from_private_bytes(identity_private)
        prekey = x25519.X25519PublicKey.from_public_bytes(prekey_public)
        
        shared_secret = identity_key.exchange(prekey)
        
        # Use HKDF to derive root key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'SecureChat-RootKey',
        )
        
        return hkdf.derive(shared_secret)
    
    def ratchet_encrypt(self, plaintext: str, associated_data: bytes = b'') -> Dict:
        """Encrypt message using current sending chain key"""
        if not self.sending_chain_key:
            raise ValueError("Sending chain key not initialized")
        
        # Derive message key from sending chain key
        message_key = self._derive_message_key(self.sending_chain_key, self.sending_message_number)
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(message_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), associated_data)
        
        # Store current message number before advancing
        current_msg_num = self.sending_message_number
        
        # Advance sending chain key
        self.sending_chain_key = self._advance_chain_key(self.sending_chain_key)
        self.sending_message_number += 1
        
        # Update legacy fields for compatibility
        self.chain_key = self.sending_chain_key
        self.message_number = self.sending_message_number
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'message_number': current_msg_num
        }
    
    def ratchet_decrypt(self, encrypted_data: Dict, associated_data: bytes = b'') -> str:
        """Decrypt message using receiving chain key"""
        if not self.receiving_chain_key:
            raise ValueError("Receiving chain key not initialized")
            
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        message_number = encrypted_data['message_number']
        
        # For proper message ordering, we should check if this is the expected message number
        if message_number < self.receiving_message_number:
            # This is an old message, potentially a replay attack
            raise ValueError(f"Replay attack detected: received message {message_number}, expected >= {self.receiving_message_number}")
        
        # If this is a future message, we need to advance our receiving chain to catch up
        receiving_chain_key = self.receiving_chain_key
        for i in range(message_number - self.receiving_message_number):
            receiving_chain_key = self._advance_chain_key(receiving_chain_key)
        
        # Derive message key
        message_key = self._derive_message_key(receiving_chain_key, message_number)
        
        # Decrypt
        cipher = ChaCha20Poly1305(message_key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
        
        # Update receiving chain state
        self.receiving_chain_key = self._advance_chain_key(receiving_chain_key)
        self.receiving_message_number = message_number + 1
        
        # Update legacy fields for compatibility
        self.chain_key = self.receiving_chain_key
        self.message_number = self.receiving_message_number
        
        return plaintext.decode()
    
    def _derive_message_key(self, chain_key: bytes, message_number: int) -> bytes:
        """Derive message key from chain key and message number"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=message_number.to_bytes(4, 'big'),
            info=b'SecureChat-MessageKey',
        )
        return hkdf.derive(chain_key)
    
    def _advance_chain_key(self, chain_key: bytes) -> bytes:
        """Advance chain key using HMAC"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(chain_key + b'advance')
        return digest.finalize()[:32]
    
    def initialize_session(self, root_key: bytes):
        """Initialize session with root key"""
        self.root_key = root_key
        
        # Initialize separate sending and receiving chains with the same root key
        # In a full Double Ratchet, these would be derived differently
        self.sending_chain_key = root_key
        self.receiving_chain_key = root_key
        self.sending_message_number = 0
        self.receiving_message_number = 0
        
        # Update legacy fields for compatibility
        self.chain_key = root_key
        self.message_number = 0 
    
    def generate_group_key(self) -> bytes:
        """Generate a new group encryption key"""
        return secrets.token_bytes(32)
    
    def add_group_key(self, group_id: int, group_key: bytes):
        """Add or update group key"""
        self.group_keys[group_id] = group_key
        if group_id not in self.group_message_numbers:
            self.group_message_numbers[group_id] = 0
    
    def remove_group_key(self, group_id: int):
        """Remove group key when leaving group"""
        if group_id in self.group_keys:
            del self.group_keys[group_id]
        if group_id in self.group_message_numbers:
            del self.group_message_numbers[group_id]
    
    def encrypt_group_message(self, group_id: int, plaintext: str, associated_data: bytes = b'') -> Dict:
        """Encrypt message for group using shared group key"""
        if group_id not in self.group_keys:
            raise ValueError(f"Group key not found for group {group_id}")
        
        group_key = self.group_keys[group_id]
        message_number = self.group_message_numbers[group_id]
        
        # Derive message key from group key and message number
        message_key = self._derive_group_message_key(group_key, message_number)
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(message_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, plaintext.encode(), associated_data)
        
        # Increment message number for this group
        self.group_message_numbers[group_id] += 1
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'message_number': message_number,
            'group_id': group_id
        }
    
    def decrypt_group_message(self, encrypted_data: Dict, associated_data: bytes = b'') -> str:
        """Decrypt group message using shared group key"""
        group_id = encrypted_data['group_id']
        
        if group_id not in self.group_keys:
            raise ValueError(f"Group key not found for group {group_id}")
        
        group_key = self.group_keys[group_id]
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        message_number = encrypted_data['message_number']
        
        # Derive message key from group key and message number
        message_key = self._derive_group_message_key(group_key, message_number)
        
        # Decrypt
        cipher = ChaCha20Poly1305(message_key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
        
        return plaintext.decode()
    
    def _derive_group_message_key(self, group_key: bytes, message_number: int) -> bytes:
        """Derive message key from group key and message number"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=message_number.to_bytes(4, 'big'),
            info=b'SecureChat-GroupMessageKey',
        )
        return hkdf.derive(group_key)
    
    def get_group_keys(self) -> Dict[int, bytes]:
        """Get all group keys (for debugging/testing)"""
        return self.group_keys.copy()
    
    def has_group_key(self, group_id: int) -> bool:
        """Check if we have the key for a specific group"""
        return group_id in self.group_keys 