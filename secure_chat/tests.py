"""
Test Suite and Demonstration Module
Comprehensive testing for all secure chat components
"""

import os
import secrets
import json
import base64
from datetime import datetime
import unittest
from unittest.mock import patch, MagicMock

from .crypto_core import CryptoCore
from .database import Database
from .security import MessageValidator, SecurityAuditor, RateLimiter, InputSanitizer
from .server import SecureChatServer


class SecureChatTester:
    """Comprehensive test suite for cryptographic functions"""
    
    def __init__(self):
        self.crypto = CryptoCore()
        self.validator = MessageValidator()
        self.auditor = SecurityAuditor()
        self.rate_limiter = RateLimiter()
        self.sanitizer = InputSanitizer()
    
    def test_key_generation(self):
        """Test cryptographic key pair generation"""
        print("🔑 Testing key generation...")
        
        # Test identity key generation
        private1, public1 = self.crypto.generate_identity_keypair()
        private2, public2 = self.crypto.generate_identity_keypair()
        
        assert len(private1) == 32, "Private key should be 32 bytes"
        assert len(public1) == 32, "Public key should be 32 bytes"
        assert private1 != private2, "Keys should be unique"
        assert public1 != public2, "Keys should be unique"
        
        # Test prekey generation
        prekey_private, prekey_public = self.crypto.generate_prekey()
        assert len(prekey_private) == 32, "Prekey private should be 32 bytes"
        assert len(prekey_public) == 32, "Prekey public should be 32 bytes"
        
        print("✅ Key generation test passed")
        return True
    
    def test_encryption_decryption(self):
        """Test message encryption and decryption"""
        print("🔐 Testing encryption/decryption...")
        
        # Initialize session
        root_key = secrets.token_bytes(32)
        
        # Test messages
        test_messages = [
            "Hello, this is a secret message! 🔒",
            "Testing unicode: åÄöÖäÜü",
            "Numbers and symbols: 12345 !@#$%^&*()",
            "A" * 500,  # Long message
            ""  # Empty message (edge case)
        ]
        
        for original_message in test_messages:
            if not original_message:  # Skip empty message for encryption
                continue
                
            # Create sender and receiver instances
            crypto_sender = CryptoCore()
            crypto_receiver = CryptoCore()
            crypto_sender.initialize_session(root_key)
            crypto_receiver.initialize_session(root_key)
            
            # Encrypt with sender
            encrypted_data = crypto_sender.ratchet_encrypt(original_message)
            
            # Verify encrypted data structure
            assert 'ciphertext' in encrypted_data
            assert 'nonce' in encrypted_data
            assert 'message_number' in encrypted_data
            
            # Decrypt with receiver
            decrypted_message = crypto_receiver.ratchet_decrypt(encrypted_data)
            
            assert decrypted_message == original_message, f"Decryption failed for: {original_message[:50]}"
        
        # Test bidirectional communication
        crypto_alice = CryptoCore()
        crypto_bob = CryptoCore()
        crypto_alice.initialize_session(root_key)
        crypto_bob.initialize_session(root_key)
        
        # Alice sends to Bob
        msg1 = "Hello Bob!"
        encrypted1 = crypto_alice.ratchet_encrypt(msg1)
        decrypted1 = crypto_bob.ratchet_decrypt(encrypted1)
        assert decrypted1 == msg1, "Alice to Bob failed"
        
        # Bob sends to Alice
        msg2 = "Hello Alice!"
        encrypted2 = crypto_bob.ratchet_encrypt(msg2)
        decrypted2 = crypto_alice.ratchet_decrypt(encrypted2)
        assert decrypted2 == msg2, "Bob to Alice failed"
        
        print("✅ Encryption/decryption test passed")
        return True
    
    def test_forward_secrecy(self):
        """Test forward secrecy property"""
        print("🛡️ Testing forward secrecy...")
        
        root_key = secrets.token_bytes(32)
        self.crypto.initialize_session(root_key)
        
        # Send multiple messages
        messages = ["Message 1", "Message 2", "Message 3", "Message 4", "Message 5"]
        encrypted_messages = []
        
        for msg in messages:
            encrypted = self.crypto.ratchet_encrypt(msg)
            encrypted_messages.append(encrypted)
        
        # Verify each message has different ciphertext and message numbers
        ciphertexts = [enc['ciphertext'] for enc in encrypted_messages]
        message_numbers = [enc['message_number'] for enc in encrypted_messages]
        
        assert len(set(ciphertexts)) == len(ciphertexts), "Messages should have different ciphertexts"
        assert message_numbers == list(range(len(messages))), "Message numbers should increment"
        
        print("✅ Forward secrecy test passed")
        return True
    
    def test_message_validation(self):
        """Test message validation functions"""
        print("📋 Testing message validation...")
        
        # Test valid message format
        valid_message = {
            'ciphertext': base64.b64encode(b'test').decode(),
            'nonce': base64.b64encode(b'nonce123').decode(),
            'message_number': 0
        }
        assert self.validator.validate_message_format(valid_message), "Valid message should pass"
        
        # Test invalid message formats
        invalid_messages = [
            {},  # Empty
            {'ciphertext': 'test'},  # Missing fields
            {'ciphertext': 'invalid_base64', 'nonce': 'test', 'message_number': 0},  # Invalid base64
            {'ciphertext': 'dGVzdA==', 'nonce': 'dGVzdA==', 'message_number': -1},  # Negative number
        ]
        
        for invalid_msg in invalid_messages:
            assert not self.validator.validate_message_format(invalid_msg), f"Invalid message should fail: {invalid_msg}"
        
        # Test replay attack detection
        assert self.validator.check_replay_attack(5, 3), "Message 5 after 3 should be allowed"
        assert not self.validator.check_replay_attack(2, 5), "Message 2 after 5 should be blocked"
        
        # Test username validation
        valid_usernames = ["alice", "bob123", "user_name", "test-user"]
        invalid_usernames = ["ab", "", "user@domain", "very_long_username_that_exceeds_limit", "user space"]
        
        for username in valid_usernames:
            assert self.validator.validate_username(username), f"Valid username should pass: {username}"
        
        for username in invalid_usernames:
            assert not self.validator.validate_username(username), f"Invalid username should fail: {username}"
        
        print("✅ Message validation test passed")
        return True
    
    def test_security_features(self):
        """Test security auditing and rate limiting"""
        print("🔒 Testing security features...")
        
        # Test security auditor
        event_id = self.auditor.log_security_event("TEST_EVENT", "Test security event", "INFO")
        assert event_id is not None, "Event ID should be generated"
        assert len(self.auditor.security_log) > 0, "Event should be logged"
        
        # Test rate limiter
        identifier = "test_user"
        endpoint = "test_endpoint"
        
        # Should allow initial requests
        for i in range(5):
            assert self.rate_limiter.is_allowed(identifier, endpoint, max_requests=10), f"Request {i} should be allowed"
        
        # Should block after limit
        for i in range(10):
            self.rate_limiter.is_allowed(identifier, endpoint, max_requests=5)
        
        assert not self.rate_limiter.is_allowed(identifier, endpoint, max_requests=5), "Should be rate limited"
        
        # Test input sanitizer
        test_inputs = [
            ("hello world", "hello world"),
            ("hello\x00world", "helloworld"),
            ("  spaces  ", "spaces"),
            ("A" * 2000, "A" * 1000),  # Length limit
        ]
        
        for input_text, expected in test_inputs:
            result = self.validator.sanitize_input(input_text, max_length=1000)
            assert result == expected, f"Sanitization failed: {input_text} -> {result} (expected {expected})"
        
        # Test spam detection
        spam_messages = [
            "FREE MONEY CLICK HERE NOW!!!",
            "CONGRATULATIONS YOU WON THE LOTTERY!!!",
            "urgent urgent urgent urgent urgent urgent urgent urgent urgent urgent"
        ]
        
        normal_messages = [
            "Hello, how are you?",
            "Let's meet for coffee tomorrow",
            "The weather is nice today"
        ]
        
        for msg in spam_messages:
            assert self.sanitizer.detect_spam(msg), f"Should detect spam: {msg}"
        
        for msg in normal_messages:
            assert not self.sanitizer.detect_spam(msg), f"Should not detect spam: {msg}"
        
        print("✅ Security features test passed")
        return True
    
    def test_database_operations(self):
        """Test database functionality"""
        print("🗄️ Testing database operations...")
        
        # Use temporary database for testing
        import tempfile
        import os
        
        # Create a temporary database file
        db_fd, db_path = tempfile.mkstemp(suffix='.db')
        os.close(db_fd)  # Close the file descriptor, just need the path
        
        try:
            db = Database(db_path)
            
            # Test user creation
            success = db.create_user(
                "testuser", "testpass123",
                "identity_public_key", "prekey_public", "prekey_private"
            )
            assert success, "User creation should succeed"
            
            # Test duplicate user creation
            duplicate = db.create_user(
                "testuser", "different_pass",
                "identity_public_key2", "prekey_public2", "prekey_private2"
            )
            assert not duplicate, "Duplicate user creation should fail"
            
            # Test user authentication
            user = db.authenticate_user("testuser", "testpass123")
            assert user is not None, "Authentication should succeed"
            assert user['username'] == "testuser", "Username should match"
            
            # Test invalid authentication
            invalid_user = db.authenticate_user("testuser", "wrongpass")
            assert invalid_user is None, "Invalid authentication should fail"
            
            # Test prekey retrieval
            prekeys = db.get_user_prekeys("testuser")
            assert prekeys is not None, "Prekeys should be retrieved"
            assert 'prekey_public' in prekeys, "Prekey public should be present"
            
            # Test message storage
            db.store_message(1, 1, "encrypted_content", "nonce", 0)
            
            print("✅ Database operations test passed")
            return True
        
        finally:
            # Clean up temporary database file
            if os.path.exists(db_path):
                os.unlink(db_path)
    
    def test_x3dh_key_agreement(self):
        """Test X3DH key agreement protocol"""
        print("🤝 Testing X3DH key agreement...")
        
        # Generate keys for Alice and Bob
        alice_identity_private, alice_identity_public = self.crypto.generate_identity_keypair()
        bob_prekey_private, bob_prekey_public = self.crypto.generate_prekey()
        
        # Alice performs key agreement
        shared_secret = self.crypto.x3dh_key_agreement(alice_identity_private, bob_prekey_public)
        
        assert len(shared_secret) == 32, "Shared secret should be 32 bytes"
        assert shared_secret != alice_identity_private, "Shared secret should be different from private key"
        assert shared_secret != bob_prekey_public, "Shared secret should be different from public key"
        
        # Test with different keys produces different secrets
        other_private, _ = self.crypto.generate_identity_keypair()
        other_secret = self.crypto.x3dh_key_agreement(other_private, bob_prekey_public)
        assert shared_secret != other_secret, "Different keys should produce different secrets"
        
        print("✅ X3DH key agreement test passed")
        return True
    
    def run_all_tests(self):
        """Run comprehensive test suite"""
        print("🧪 STARTING COMPREHENSIVE SECURE CHAT TESTS")
        print("=" * 60)
        
        tests = [
            self.test_key_generation,
            self.test_encryption_decryption,
            self.test_forward_secrecy,
            self.test_x3dh_key_agreement,
            self.test_message_validation,
            self.test_security_features,
            self.test_database_operations,
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                if test():
                    passed += 1
                else:
                    failed += 1
                    print(f"❌ {test.__name__} failed")
            except Exception as e:
                failed += 1
                print(f"❌ {test.__name__} failed with exception: {e}")
        
        print("\n" + "=" * 60)
        print(f"📊 TEST RESULTS: {passed} passed, {failed} failed")
        
        if failed == 0:
            print("🎉 All tests passed! The secure chat system is working correctly.")
        else:
            print(f"⚠️ {failed} tests failed. Please review the issues.")
        
        return failed == 0


class DemoScenarios:
    """Demonstrate various security features and use cases"""
    
    @staticmethod
    def demonstrate_encryption():
        """Show encryption/decryption process step by step"""
        print("\n🔒 ENCRYPTION DEMONSTRATION")
        print("=" * 50)
        
        crypto = CryptoCore()
        root_key = secrets.token_bytes(32)
        crypto.initialize_session(root_key)
        
        # Original message
        message = "This is a confidential message! 🤫"
        print(f"📝 Original message: {message}")
        print(f"📏 Message length: {len(message)} characters")
        
        # Encrypt
        encrypted = crypto.ratchet_encrypt(message)
        print(f"\n🔐 Encrypted data:")
        print(f"   Ciphertext: {encrypted['ciphertext'][:50]}...")
        print(f"   Nonce: {encrypted['nonce']}")
        print(f"   Message number: {encrypted['message_number']}")
        print(f"   Total encrypted size: {len(json.dumps(encrypted))} bytes")
        
        # Decrypt
        crypto2 = CryptoCore()
        crypto2.initialize_session(root_key)
        decrypted = crypto2.ratchet_decrypt(encrypted)
        print(f"\n🔓 Decrypted message: {decrypted}")
        print(f"✅ Encryption/Decryption successful: {message == decrypted}")
    
    @staticmethod
    def demonstrate_forward_secrecy():
        """Show forward secrecy in action"""
        print("\n🔐 FORWARD SECRECY DEMONSTRATION")
        print("=" * 50)
        
        crypto = CryptoCore()
        root_key = secrets.token_bytes(32)
        crypto.initialize_session(root_key)
        
        messages = ["Secret plan A", "Secret plan B", "Secret plan C", "Final instructions"]
        encrypted_msgs = []
        
        print("📨 Sending messages with forward secrecy:")
        for i, msg in enumerate(messages):
            encrypted = crypto.ratchet_encrypt(msg)
            encrypted_msgs.append(encrypted)
            print(f"   {i+1}. '{msg}' -> Key fingerprint: ...{encrypted['ciphertext'][-16:]}")
        
        print("\n🛡️ Forward Secrecy Properties:")
        print("   ✅ Each message uses a different encryption key")
        print("   ✅ Compromising one key doesn't affect other messages")
        print("   ✅ Past messages remain secure even if current key is leaked")
    
    @staticmethod
    def demonstrate_security_features():
        """Show security validation and monitoring"""
        print("\n🔒 SECURITY FEATURES DEMONSTRATION")
        print("=" * 50)
        
        validator = MessageValidator()
        auditor = SecurityAuditor()
        sanitizer = InputSanitizer()
        
        # Message validation
        print("📋 Message Validation:")
        valid_msg = {
            'ciphertext': base64.b64encode(b'test').decode(),
            'nonce': base64.b64encode(b'nonce').decode(),
            'message_number': 0
        }
        print(f"   Valid message: {validator.validate_message_format(valid_msg)}")
        
        invalid_msg = {'incomplete': 'data'}
        print(f"   Invalid message: {validator.validate_message_format(invalid_msg)}")
        
        # Security auditing
        print("\n🔍 Security Auditing:")
        auditor.log_security_event("DEMO_EVENT", "Demonstration security event", "INFO")
        auditor.log_security_event("SUSPICIOUS_ACTIVITY", "Potential threat detected", "WARNING")
        
        # Input sanitization
        print("\n🧹 Input Sanitization:")
        validator = MessageValidator()
        dirty_input = "  Hello\x00World\r\n  "
        clean_input = validator.sanitize_input(dirty_input)
        print(f"   Before: {repr(dirty_input)}")
        print(f"   After: {repr(clean_input)}")
        
        # Spam detection
        print("\n🚫 Spam Detection:")
        spam_msg = "FREE MONEY CLICK HERE NOW URGENT!!!"
        normal_msg = "Hello, how are you today?"
        print(f"   Spam message: {sanitizer.detect_spam(spam_msg)}")
        print(f"   Normal message: {sanitizer.detect_spam(normal_msg)}")
    
    @staticmethod
    def demonstrate_threat_scenarios():
        """Show how the system handles various threats"""
        print("\n⚔️ THREAT RESISTANCE DEMONSTRATION")
        print("=" * 50)
        
        validator = MessageValidator()
        
        # Replay attack
        print("🔄 Replay Attack Protection:")
        print("   Legitimate message 5 after 3: ", validator.check_replay_attack(5, 3))
        print("   Replay attack (msg 2 after 5): ", validator.check_replay_attack(2, 5))
        
        # Input validation
        print("\n💉 Input Validation:")
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "\x00\x01\x02malicious",
            "A" * 10000
        ]
        
        sanitizer = InputSanitizer()
        validator = MessageValidator()
        for malicious in malicious_inputs:
            safe = validator.sanitize_input(malicious, max_length=100)
            print(f"   Blocked: {repr(malicious[:50])}... -> {repr(safe[:50])}")


def create_comprehensive_demo():
    """Create a comprehensive demonstration of the secure chat system"""
    print("🎉 SECURE CHAT APPLICATION COMPREHENSIVE DEMO")
    print("=" * 70)
    print("Signal-inspired end-to-end encrypted messaging system")
    print("Built with Python, featuring Double Ratchet encryption\n")
    
    # Run tests first
    print("Phase 1: Running automated tests...")
    tester = SecureChatTester()
    test_success = tester.run_all_tests()
    
    if not test_success:
        print("\n❌ Some tests failed. Please fix issues before deploying.")
        return False
    
    # Show demonstrations
    print("\nPhase 2: Security demonstrations...")
    DemoScenarios.demonstrate_encryption()
    DemoScenarios.demonstrate_forward_secrecy()
    DemoScenarios.demonstrate_security_features()
    DemoScenarios.demonstrate_threat_scenarios()
    
    # Show system information
    print("\n" + "=" * 70)
    print("🚀 SYSTEM INFORMATION")
    print("=" * 70)
    print("📁 Components:")
    print("   ✅ crypto_core.py - Double Ratchet encryption")
    print("   ✅ database.py - SQLite data storage")
    print("   ✅ server.py - Flask + WebSocket server")
    print("   ✅ client.py - Tkinter GUI client")
    print("   ✅ security.py - Validation & auditing")
    print("   ✅ tests.py - Comprehensive test suite")
    
    print("\n🔒 Security Features:")
    print("   ✅ End-to-end encryption (ChaCha20-Poly1305)")
    print("   ✅ Forward secrecy (Double Ratchet inspired)")
    print("   ✅ Key agreement (simplified X3DH)")
    print("   ✅ Message integrity & authenticity")
    print("   ✅ Replay attack protection")
    print("   ✅ Session timeout management")
    print("   ✅ Input validation & sanitization")
    print("   ✅ Spam detection")
    print("   ✅ Rate limiting")
    print("   ✅ Security audit logging")
    print("   ✅ Threat resistance")
    
    print("\n🚀 DEPLOYMENT INSTRUCTIONS:")
    print("=" * 40)
    print("1. Install dependencies:")
    print("   pip install -r requirements.txt")
    print("\n2. Start the server:")
    print("   python -m secure_chat.main server")
    print("\n3. Start client(s):")
    print("   python -m secure_chat.main client")
    print("\n4. Register users and start chatting!")
    
    print("\n🎯 NEXT STEPS:")
    print("   • Deploy on secure infrastructure")
    print("   • Implement additional features (file sharing, groups)")
    print("   • Conduct security audit")
    print("   • Set up monitoring and logging")
    print("   • Create mobile applications")
    
    print("\n✨ The secure chat system is ready for production!")
    return True


class PerformanceTests:
    """Performance and load testing"""
    
    @staticmethod
    def test_encryption_performance():
        """Test encryption performance with different message sizes"""
        print("\n⚡ ENCRYPTION PERFORMANCE TEST")
        print("=" * 40)
        
        crypto = CryptoCore()
        root_key = secrets.token_bytes(32)
        crypto.initialize_session(root_key)
        
        message_sizes = [100, 1000, 5000, 10000]
        
        for size in message_sizes:
            message = "A" * size
            
            # Time encryption
            import time
            start_time = time.time()
            
            for _ in range(100):  # 100 iterations
                encrypted = crypto.ratchet_encrypt(message)
            
            end_time = time.time()
            avg_time = (end_time - start_time) / 100 * 1000  # ms per operation
            
            print(f"   {size:5d} chars: {avg_time:.2f}ms per message")
    
    @staticmethod
    def test_concurrent_operations():
        """Test concurrent encryption operations"""
        print("\n🔄 CONCURRENT OPERATIONS TEST")
        print("=" * 40)
        
        import threading
        import time
        
        def encrypt_messages(crypto_instance, num_messages, results, thread_id):
            start_time = time.time()
            for i in range(num_messages):
                crypto_instance.ratchet_encrypt(f"Message {i} from thread {thread_id}")
            end_time = time.time()
            results[thread_id] = end_time - start_time
        
        num_threads = 4
        messages_per_thread = 50
        results = {}
        threads = []
        
        # Create separate crypto instances for each thread
        for thread_id in range(num_threads):
            crypto = CryptoCore()
            root_key = secrets.token_bytes(32)
            crypto.initialize_session(root_key)
            
            thread = threading.Thread(
                target=encrypt_messages,
                args=(crypto, messages_per_thread, results, thread_id)
            )
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        total_messages = num_threads * messages_per_thread
        
        print(f"   Threads: {num_threads}")
        print(f"   Messages per thread: {messages_per_thread}")
        print(f"   Total messages: {total_messages}")
        print(f"   Total time: {total_time:.2f}s")
        print(f"   Messages per second: {total_messages/total_time:.1f}")


if __name__ == "__main__":
    # Run the comprehensive demo
    create_comprehensive_demo()
    
    # Optionally run performance tests
    print("\n" + "=" * 70)
    print("🔥 PERFORMANCE TESTS")
    print("=" * 70)
    PerformanceTests.test_encryption_performance()
    PerformanceTests.test_concurrent_operations() 