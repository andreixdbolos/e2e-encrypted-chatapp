"""
Main Entry Point for Secure Chat Application
Handles command-line interface and application startup
"""

import sys
import os
import argparse
from typing import Optional

# Import application components
from .server import SecureChatServer
from .client import SecureChatClient
from .tests import SecureChatTester, create_comprehensive_demo, PerformanceTests


def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                    🔒 SECURE CHAT                         ║
    ║              Signal-Inspired E2E Encryption               ║
    ║                                                           ║
    ║  Features:                                                ║
    ║  • End-to-End Encryption (ChaCha20-Poly1305)            ║
    ║  • Forward Secrecy (Double Ratchet)                     ║
    ║  • Real-time messaging (WebSocket)                       ║
    ║  • Security auditing & monitoring                        ║
    ║  • Modern GUI client                                     ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Start the secure chat server"""
    print("🚀 Starting Secure Chat Server...")
    print(f"📡 Server will listen on {host}:{port}")
    print(f"🔧 Debug mode: {'Enabled' if debug else 'Disabled'}")
    print("=" * 50)
    
    try:
        server = SecureChatServer()
        server.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\n⏹️ Server stopped by user")
    except Exception as e:
        print(f"❌ Server failed to start: {str(e)}")
        sys.exit(1)


def run_client(server_url: str = "http://127.0.0.1:5000"):
    """Start the secure chat client"""
    print("🚀 Starting Secure Chat Client...")
    print(f"🌐 Connecting to server: {server_url}")
    print("=" * 50)
    
    try:
        client = SecureChatClient(server_url=server_url)
        client.run()
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please install required packages:")
        print("pip install tkinter python-socketio requests")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting client: {e}")
        sys.exit(1)


def run_tests(verbose: bool = False):
    """Run the test suite"""
    print("🧪 Running Secure Chat Test Suite...")
    print("=" * 50)
    
    try:
        tester = SecureChatTester()
        success = tester.run_all_tests()
        
        if verbose:
            print("\n🔥 Running performance tests...")
            PerformanceTests.test_encryption_performance()
            PerformanceTests.test_concurrent_operations()
        
        if success:
            print("\n🎉 All tests passed successfully!")
            return True
        else:
            print("\n❌ Some tests failed. Please review the output.")
            return False
            
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def run_demo():
    """Run comprehensive demonstration"""
    print("🎯 Running Secure Chat Demonstration...")
    print("=" * 50)
    
    try:
        return create_comprehensive_demo()
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        return False


def show_status():
    """Show system status and information"""
    print("📊 SECURE CHAT SYSTEM STATUS")
    print("=" * 50)
    
    # Check dependencies
    missing_deps = []
    required_packages = [
        'flask', 'flask_socketio', 'python_socketio', 'requests',
        'bcrypt', 'PyJWT', 'cryptography', 'tkinter'
    ]
    
    for package in required_packages:
        try:
            if package == 'tkinter':
                import tkinter
            elif package == 'python_socketio':
                import socketio
            elif package == 'flask_socketio':
                import flask_socketio
            elif package == 'PyJWT':
                import jwt
            else:
                __import__(package)
        except ImportError:
            missing_deps.append(package)
    
    if missing_deps:
        print("❌ Missing dependencies:")
        for dep in missing_deps:
            print(f"   • {dep}")
        print("\nInstall missing packages:")
        print("pip install " + " ".join(missing_deps))
    else:
        print("✅ All dependencies installed")
    
    # Show component status
    print("\n📁 Components:")
    components = [
        ('crypto_core.py', '🔐 Cryptographic core'),
        ('database.py', '🗄️ Database layer'),
        ('server.py', '📡 WebSocket server'),
        ('client.py', '💬 GUI client'),
        ('security.py', '🛡️ Security features'),
        ('tests.py', '🧪 Test suite'),
        ('main.py', '🚀 Main entry point')
    ]
    
    for filename, description in components:
        filepath = os.path.join(os.path.dirname(__file__), filename)
        if os.path.exists(filepath):
            print(f"   ✅ {description}")
        else:
            print(f"   ❌ {description} (missing)")
    
    print("\n🔒 Security Features:")
    features = [
        "End-to-end encryption (ChaCha20-Poly1305)",
        "Forward secrecy (Double Ratchet inspired)",
        "Key agreement (simplified X3DH)",
        "Message integrity & authenticity",
        "Replay attack protection",
        "Session timeout management",
        "Input validation & sanitization",
        "Spam detection",
        "Rate limiting",
        "Security audit logging"
    ]
    
    for feature in features:
        print(f"   ✅ {feature}")


def create_parser():
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="Secure Chat Application - Signal-inspired E2E encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s server                    # Start server on localhost:5000
  %(prog)s server --host 0.0.0.0    # Start server on all interfaces
  %(prog)s client                    # Start GUI client
  %(prog)s test                      # Run test suite
  %(prog)s demo                      # Run comprehensive demo
  %(prog)s status                    # Show system status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start the server')
    server_parser.add_argument('--host', default='127.0.0.1', 
                              help='Host to bind server (default: 127.0.0.1)')
    server_parser.add_argument('--port', type=int, default=5000,
                              help='Port to bind server (default: 5000)')
    server_parser.add_argument('--debug', action='store_true',
                              help='Enable debug mode')
    
    # Client command
    client_parser = subparsers.add_parser('client', help='Start the GUI client')
    client_parser.add_argument('--server', default='http://127.0.0.1:5000',
                              help='Server URL (default: http://127.0.0.1:5000)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run test suite')
    test_parser.add_argument('--verbose', action='store_true',
                            help='Run additional performance tests')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run comprehensive demonstration')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    
    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        print("\nFor a quick start, try:")
        print("  python -m secure_chat.main demo    # Run demonstration")
        print("  python -m secure_chat.main status  # Check system status")
        return
    
    args = parser.parse_args()
    
    # Print banner for all commands except status
    if args.command != 'status':
        print_banner()
    
    # Execute command
    try:
        if args.command == 'server':
            run_server(host=args.host, port=args.port, debug=args.debug)
        
        elif args.command == 'client':
            run_client(server_url=args.server)
        
        elif args.command == 'test':
            success = run_tests(verbose=args.verbose)
            sys.exit(0 if success else 1)
        
        elif args.command == 'demo':
            success = run_demo()
            sys.exit(0 if success else 1)
        
        elif args.command == 'status':
            show_status()
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\n⏹️ Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 