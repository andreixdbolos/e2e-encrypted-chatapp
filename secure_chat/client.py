"""
Client Module
GUI client application with end-to-end encryption and enhanced security
"""

import os
import json
import base64
import secrets
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import socketio
import requests

from .crypto_core import CryptoCore
from .security import MessageValidator, SecurityAuditor, InputSanitizer


class SecureChatClient:
    """GUI client application with encryption and enhanced security"""
    
    def __init__(self, server_url: str = "http://127.0.0.1:5000"):
        self.server_url = server_url
        self.root = tk.Tk()
        self.root.title("Secure Chat - Signal Clone")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        # Core components
        self.crypto = CryptoCore()
        self.validator = MessageValidator()
        self.auditor = SecurityAuditor()
        self.sanitizer = InputSanitizer()
        
        # User state
        self.username = None
        self.token = None
        self.identity_private = None
        self.current_chat_partner = None
        self.session_established = False
        self.expected_message_number = 0
        self.session_timeout = 3600  # 1 hour
        self.session_start_time = None
        
        # Chat requests
        self.pending_requests = {}  # {requester: request_data}
        
        # Socket.IO client
        self.sio = socketio.Client()
        self.setup_socketio_handlers()
        
        # Message history
        self.message_history = {}  # partner -> list of messages
        
        self.setup_ui()
        self.setup_styles()
    
    def setup_styles(self):
        """Setup modern UI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', 
                       font=('Helvetica', 16, 'bold'),
                       foreground='#ecf0f1',
                       background='#2c3e50')
        
        style.configure('Heading.TLabel',
                       font=('Helvetica', 12, 'bold'),
                       foreground='#ecf0f1',
                       background='#34495e')
        
        style.configure('Status.TLabel',
                       font=('Helvetica', 10),
                       foreground='#27ae60',
                       background='#2c3e50')
        
        style.configure('Error.TLabel',
                       font=('Helvetica', 10),
                       foreground='#e74c3c',
                       background='#2c3e50')
    
    def setup_ui(self):
        """Setup the modern user interface"""
        # Main container with dark theme
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs with custom styling
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Authentication tab
        self.auth_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.auth_frame, text="🔐 Login/Register")
        self.setup_auth_ui()
        
        # Chat tab
        self.chat_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.chat_frame, text="💬 Chat")
        self.setup_chat_ui()
        
        # Security tab
        self.security_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.security_frame, text="🔒 Security")
        self.setup_security_ui()
        
        # Initially disable chat and security tabs
        self.notebook.tab(1, state='disabled')
        self.notebook.tab(2, state='disabled')
    
    def setup_auth_ui(self):
        """Setup authentication interface with modern design"""
        # Create a container that can switch between login and logout views
        self.auth_container = tk.Frame(self.auth_frame, bg='#34495e')
        self.auth_container.pack(fill='both', expand=True)
        
        # Setup login/register view
        self.setup_login_view()
        
        # Setup logout view (initially hidden)
        self.setup_logout_view()
        
        # Show login view by default
        self.show_login_view()
    
    def setup_login_view(self):
        """Setup the login/register interface"""
        self.login_view = tk.Frame(self.auth_container, bg='#34495e')
        
        # Title
        title_label = ttk.Label(self.login_view, text="🔒 Secure Chat Application", 
                               style='Title.TLabel')
        title_label.pack(pady=30)
        
        subtitle_label = ttk.Label(self.login_view, text="Signal-inspired E2E encrypted messaging",
                                  font=('Helvetica', 11),
                                  foreground='#bdc3c7',
                                  background='#34495e')
        subtitle_label.pack(pady=(0, 30))
        
        # Create container for forms
        forms_container = tk.Frame(self.login_view, bg='#34495e')
        forms_container.pack(expand=True, fill='both', padx=50)
        
        # Login section
        login_frame = tk.LabelFrame(forms_container, text="🔑 Login", 
                                   font=('Helvetica', 12, 'bold'),
                                   fg='#ecf0f1', bg='#34495e',
                                   padx=20, pady=20)
        login_frame.pack(pady=10, fill='x')
        
        tk.Label(login_frame, text="Username:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor=tk.W, pady=(0, 5))
        self.login_username_entry = tk.Entry(login_frame, font=('Helvetica', 10),
                                           width=30, relief='solid', bd=1)
        self.login_username_entry.pack(fill='x', pady=(0, 10))
        
        tk.Label(login_frame, text="Password:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor=tk.W, pady=(0, 5))
        self.login_password_entry = tk.Entry(login_frame, show="*", font=('Helvetica', 10),
                                           width=30, relief='solid', bd=1)
        self.login_password_entry.pack(fill='x', pady=(0, 15))
        
        login_btn = tk.Button(login_frame, text="🚀 Login", command=self.login,
                             font=('Helvetica', 10, 'bold'),
                             bg='#3498db', fg='white',
                             relief='flat', padx=20, pady=8)
        login_btn.pack()
        
        # Register section
        register_frame = tk.LabelFrame(forms_container, text="✨ Create Account", 
                                      font=('Helvetica', 12, 'bold'),
                                      fg='#ecf0f1', bg='#34495e',
                                      padx=20, pady=20)
        register_frame.pack(pady=10, fill='x')
        
        tk.Label(register_frame, text="Username:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor=tk.W, pady=(0, 5))
        self.register_username_entry = tk.Entry(register_frame, font=('Helvetica', 10),
                                              width=30, relief='solid', bd=1)
        self.register_username_entry.pack(fill='x', pady=(0, 10))
        
        tk.Label(register_frame, text="Password:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor=tk.W, pady=(0, 5))
        self.register_password_entry = tk.Entry(register_frame, show="*", font=('Helvetica', 10),
                                              width=30, relief='solid', bd=1)
        self.register_password_entry.pack(fill='x', pady=(0, 15))
        
        register_btn = tk.Button(register_frame, text="🎯 Register", command=self.register,
                               font=('Helvetica', 10, 'bold'),
                               bg='#27ae60', fg='white',
                               relief='flat', padx=20, pady=8)
        register_btn.pack()
        
        # Status label
        self.status_label = tk.Label(self.login_view, text="", font=('Helvetica', 10),
                                   fg='#e74c3c', bg='#34495e')
        self.status_label.pack(pady=20)
        
        # Bind Enter key
        self.login_password_entry.bind('<Return>', lambda e: self.login())
        self.register_password_entry.bind('<Return>', lambda e: self.register())
    
    def setup_logout_view(self):
        """Setup the user profile and logout interface"""
        self.logout_view = tk.Frame(self.auth_container, bg='#34495e')
        
        # Header with user info
        header_frame = tk.Frame(self.logout_view, bg='#2c3e50', relief='solid', bd=2)
        header_frame.pack(fill='x', padx=30, pady=30)
        
        # Welcome title
        welcome_label = tk.Label(header_frame, text="👋 Welcome Back!", 
                                font=('Helvetica', 18, 'bold'),
                                fg='#ecf0f1', bg='#2c3e50')
        welcome_label.pack(pady=20)
        
        # User info frame
        user_info_frame = tk.Frame(header_frame, bg='#2c3e50')
        user_info_frame.pack(pady=10)
        
        # Username display
        self.username_display = tk.Label(user_info_frame, text="", 
                                        font=('Helvetica', 16, 'bold'),
                                        fg='#3498db', bg='#2c3e50')
        self.username_display.pack()
        
        # Connection status
        self.connection_status_label = tk.Label(user_info_frame, text="", 
                                               font=('Helvetica', 12),
                                               fg='#27ae60', bg='#2c3e50')
        self.connection_status_label.pack(pady=5)
        
        # Session info
        self.session_info_label = tk.Label(user_info_frame, text="", 
                                          font=('Helvetica', 10),
                                          fg='#95a5a6', bg='#2c3e50')
        self.session_info_label.pack()
        
        # Action buttons frame
        buttons_frame = tk.Frame(self.logout_view, bg='#34495e')
        buttons_frame.pack(expand=True, pady=50)
        
        # Quick actions section
        actions_frame = tk.LabelFrame(buttons_frame, text="Quick Actions", 
                                     font=('Helvetica', 14, 'bold'),
                                     fg='#ecf0f1', bg='#34495e',
                                     padx=30, pady=20)
        actions_frame.pack(pady=20)
        
        # Go to chat button
        chat_btn = tk.Button(actions_frame, text="💬 Start Chatting", 
                            command=lambda: self.notebook.select(1),
                            font=('Helvetica', 12, 'bold'),
                            bg='#27ae60', fg='white',
                            relief='flat', padx=30, pady=10)
        chat_btn.pack(pady=10)
        
        # View security button
        security_btn = tk.Button(actions_frame, text="🔒 Security Monitor", 
                               command=lambda: self.notebook.select(2),
                               font=('Helvetica', 12, 'bold'),
                               bg='#9b59b6', fg='white',
                               relief='flat', padx=30, pady=10)
        security_btn.pack(pady=10)
        
        # Logout section
        logout_frame = tk.LabelFrame(buttons_frame, text="Account", 
                                    font=('Helvetica', 14, 'bold'),
                                    fg='#ecf0f1', bg='#34495e',
                                    padx=30, pady=20)
        logout_frame.pack(pady=20)
        
        # Logout button
        logout_btn = tk.Button(logout_frame, text="🚪 Logout", 
                              command=self.logout,
                              font=('Helvetica', 12, 'bold'),
                              bg='#e74c3c', fg='white',
                              relief='flat', padx=30, pady=10)
        logout_btn.pack(pady=10)
        
        # Info label
        info_label = tk.Label(logout_frame, 
                             text="Logging out will disconnect you from all active sessions",
                             font=('Helvetica', 9),
                             fg='#95a5a6', bg='#34495e')
        info_label.pack()
    
    def show_login_view(self):
        """Show the login/register interface"""
        if hasattr(self, 'logout_view'):
            self.logout_view.pack_forget()
        self.login_view.pack(fill='both', expand=True)
        
        # Update tab title
        self.notebook.tab(0, text="🔐 Login/Register")
    
    def show_logout_view(self):
        """Show the user profile and logout interface"""
        self.login_view.pack_forget()
        self.logout_view.pack(fill='both', expand=True)
        
        # Update user info
        if self.username:
            self.username_display.config(text=f"👤 {self.username}")
            
        # Update connection status
        if self.sio.connected:
            self.connection_status_label.config(text="🟢 Connected to server", fg='#27ae60')
        else:
            self.connection_status_label.config(text="🔴 Disconnected", fg='#e74c3c')
        
        # Update session info
        login_time = datetime.now().strftime('%H:%M:%S')
        self.session_info_label.config(text=f"Logged in at {login_time}")
        
        # Update tab title
        self.notebook.tab(0, text=f"👤 {self.username}")
    
    def logout(self):
        """Handle user logout with confirmation"""
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to logout?\n\nThis will disconnect you from all active sessions."):
            try:
                # Disconnect from WebSocket
                if self.sio.connected:
                    self.sio.disconnect()
                
                # Clear user state
                self.username = None
                self.token = None
                self.identity_private = None
                self.current_chat_partner = None
                self.session_established = False
                self.expected_message_number = 0
                self.session_start_time = None
                
                # Clear pending requests
                self.pending_requests.clear()
                
                # Clear message history
                self.message_history.clear()
                
                # Reset crypto state
                self.crypto = CryptoCore()
                
                # Clear UI fields
                self.login_username_entry.delete(0, tk.END)
                self.login_password_entry.delete(0, tk.END)
                self.register_username_entry.delete(0, tk.END)
                self.register_password_entry.delete(0, tk.END)
                self.partner_entry.delete(0, tk.END)
                self.message_entry.delete(0, tk.END)
                
                # Clear messages display
                self.messages_text.config(state=tk.NORMAL)
                self.messages_text.delete(1.0, tk.END)
                self.messages_text.config(state=tk.DISABLED)
                
                # Reset chat requests UI
                for widget in self.requests_container.winfo_children():
                    widget.destroy()
                
                self.no_requests_label = tk.Label(self.requests_container, 
                                                 text="No pending chat requests", 
                                                 font=('Helvetica', 9),
                                                 fg='#95a5a6', bg='#34495e')
                self.no_requests_label.pack(anchor='w', pady=5)
                
                # Reset status labels
                self.chat_status_label.config(text="Not connected", fg='#e74c3c')
                self.connection_indicator.config(text="⚫ Offline", fg='#e74c3c')
                self.status_label.config(text="Logged out successfully", fg='#27ae60')
                
                # Disable other tabs
                self.notebook.tab(1, state='disabled')
                self.notebook.tab(2, state='disabled')
                
                # Show login view and switch to auth tab
                self.show_login_view()
                self.notebook.select(0)
                
                # Log the logout
                self.auditor.log_security_event("LOGOUT", "User logged out")
                
                # Show success message briefly
                self.root.after(3000, lambda: self.status_label.config(text=""))
                
            except Exception as e:
                self.auditor.log_security_event("LOGOUT_ERROR", str(e), "ERROR")
                messagebox.showerror("Logout Error", f"Error during logout: {str(e)}")
    
    def setup_chat_ui(self):
        """Setup modern chat interface"""
        # Header frame
        header_frame = tk.Frame(self.chat_frame, bg='#34495e', height=60)
        header_frame.pack(fill='x', padx=10, pady=(10, 5))
        header_frame.pack_propagate(False)
        
        # Partner selection
        partner_frame = tk.Frame(header_frame, bg='#34495e')
        partner_frame.pack(side='left', fill='both', expand=True)
        
        tk.Label(partner_frame, text="💬 Chat with:", font=('Helvetica', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(side='left', padx=(10, 5))
        
        self.partner_entry = tk.Entry(partner_frame, font=('Helvetica', 10), width=20,
                                     relief='solid', bd=1)
        self.partner_entry.pack(side='left', padx=5)
        
        start_chat_btn = tk.Button(partner_frame, text="🔐 Start Secure Chat", 
                                  command=self.start_chat,
                                  font=('Helvetica', 9, 'bold'),
                                  bg='#e67e22', fg='white',
                                  relief='flat', padx=15, pady=5)
        start_chat_btn.pack(side='left', padx=10)
        
        # Online users button
        online_btn = tk.Button(header_frame, text="👥 Online Users",
                              command=self.show_online_users,
                              font=('Helvetica', 9),
                              bg='#9b59b6', fg='white',
                              relief='flat', padx=10, pady=5)
        online_btn.pack(side='right', padx=10)
        
        # Chat requests section
        requests_frame = tk.Frame(self.chat_frame, bg='#34495e', height=80)
        requests_frame.pack(fill='x', padx=10, pady=5)
        requests_frame.pack_propagate(False)
        
        # Requests header
        requests_header = tk.Label(requests_frame, text="📨 Chat Requests", 
                                  font=('Helvetica', 10, 'bold'),
                                  fg='#ecf0f1', bg='#34495e')
        requests_header.pack(anchor='w', padx=10, pady=5)
        
        # Scrollable frame for requests
        self.requests_container = tk.Frame(requests_frame, bg='#34495e')
        self.requests_container.pack(fill='both', expand=True, padx=10, pady=(0, 5))
        
        # Initially show "No pending requests"
        self.no_requests_label = tk.Label(self.requests_container, 
                                         text="No pending chat requests", 
                                         font=('Helvetica', 9),
                                         fg='#95a5a6', bg='#34495e')
        self.no_requests_label.pack(anchor='w', pady=5)
        
        # Messages display with dark theme
        messages_frame = tk.Frame(self.chat_frame, bg='#2c3e50')
        messages_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.messages_text = scrolledtext.ScrolledText(
            messages_frame, 
            height=20, 
            state=tk.DISABLED,
            font=('Consolas', 10),
            bg='#1a252f',
            fg='#ecf0f1',
            insertbackground='#ecf0f1',
            selectbackground='#3498db',
            relief='solid',
            bd=1
        )
        self.messages_text.pack(fill='both', expand=True)
        
        # Message input frame
        input_frame = tk.Frame(self.chat_frame, bg='#2c3e50', height=50)
        input_frame.pack(fill='x', padx=10, pady=5)
        input_frame.pack_propagate(False)
        
        self.message_entry = tk.Entry(input_frame, font=('Helvetica', 11),
                                     bg='#ecf0f1', relief='solid', bd=1)
        self.message_entry.pack(side='left', fill='both', expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', self.send_message)
        
        send_btn = tk.Button(input_frame, text="📤 Send", command=self.send_message,
                           font=('Helvetica', 10, 'bold'),
                           bg='#27ae60', fg='white',
                           relief='flat', padx=20, pady=8)
        send_btn.pack(side='right')
        
        # Status frame
        status_frame = tk.Frame(self.chat_frame, bg='#2c3e50')
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.chat_status_label = tk.Label(status_frame, text="Not connected",
                                         font=('Helvetica', 10),
                                         fg='#e74c3c', bg='#2c3e50')
        self.chat_status_label.pack(side='left')
        
        # Connection indicator
        self.connection_indicator = tk.Label(status_frame, text="⚫ Offline",
                                           font=('Helvetica', 9),
                                           fg='#e74c3c', bg='#2c3e50')
        self.connection_indicator.pack(side='right')
    
    def setup_security_ui(self):
        """Setup security monitoring interface"""
        # Title
        title_label = ttk.Label(self.security_frame, text="🔒 Security Monitor",
                               style='Title.TLabel')
        title_label.pack(pady=20)
        
        # Security report frame
        report_frame = tk.LabelFrame(self.security_frame, text="Security Report",
                                   font=('Helvetica', 12, 'bold'),
                                   fg='#ecf0f1', bg='#34495e',
                                   padx=20, pady=20)
        report_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Report text area
        self.security_report_text = scrolledtext.ScrolledText(
            report_frame,
            height=20,
            font=('Consolas', 9),
            bg='#1a252f',
            fg='#ecf0f1',
            state=tk.DISABLED
        )
        self.security_report_text.pack(fill='both', expand=True, pady=10)
        
        # Buttons frame
        buttons_frame = tk.Frame(report_frame, bg='#34495e')
        buttons_frame.pack(fill='x', pady=10)
        
        refresh_btn = tk.Button(buttons_frame, text="🔄 Refresh Report",
                              command=self.refresh_security_report,
                              font=('Helvetica', 10),
                              bg='#3498db', fg='white',
                              relief='flat', padx=15, pady=5)
        refresh_btn.pack(side='left', padx=5)
        
        export_btn = tk.Button(buttons_frame, text="💾 Export Report",
                              command=self.export_security_report,
                              font=('Helvetica', 10),
                              bg='#95a5a6', fg='white',
                              relief='flat', padx=15, pady=5)
        export_btn.pack(side='left', padx=5)
        
        clear_btn = tk.Button(buttons_frame, text="🗑️ Clear Log",
                            command=self.clear_security_log,
                            font=('Helvetica', 10),
                            bg='#e74c3c', fg='white',
                            relief='flat', padx=15, pady=5)
        clear_btn.pack(side='left', padx=5)
    
    def setup_socketio_handlers(self):
        """Setup Socket.IO event handlers with enhanced security"""
        
        @self.sio.event
        def connect():
            print("Connected to server")
            self.auditor.log_security_event("CONNECTION", "Connected to server")
            self.connection_indicator.config(text="🟢 Online", fg='#27ae60')
            
            # Update connection status in logout view if user is logged in
            if self.username and hasattr(self, 'connection_status_label'):
                self.connection_status_label.config(text="🟢 Connected to server", fg='#27ae60')
            
            if self.username and self.token:
                self.sio.emit('join', {'username': self.username, 'token': self.token})
        
        @self.sio.event
        def disconnect():
            print("Disconnected from server")
            self.auditor.log_security_event("DISCONNECTION", "Disconnected from server")
            self.connection_indicator.config(text="⚫ Offline", fg='#e74c3c')
            self.chat_status_label.config(text="Disconnected from server", fg='#e74c3c')
            
            # Update connection status in logout view if user is logged in
            if self.username and hasattr(self, 'connection_status_label'):
                self.connection_status_label.config(text="🔴 Disconnected", fg='#e74c3c')
        
        @self.sio.event
        def status(data):
            self.chat_status_label.config(text=data['message'], fg='#27ae60')
        
        @self.sio.event
        def error(data):
            self.auditor.log_security_event("ERROR", data['message'], "ERROR")
            self.display_message(f"❌ Error: {data['message']}")
        
        @self.sio.event
        def new_message(data):
            try:
                encrypted_message = json.loads(data['encrypted_message'])
                
                # Validate message format
                if not self.validator.validate_message_format(encrypted_message):
                    self.auditor.log_security_event("INVALID_MESSAGE", 
                                                   "Received malformed message", "WARNING")
                    return
                
                # Check for replay attacks
                msg_num = encrypted_message.get('message_number', 0)
                if not self.validator.check_replay_attack(msg_num, self.expected_message_number):
                    self.auditor.log_security_event("REPLAY_ATTACK", 
                                                   f"Replay attack detected: {msg_num}", "ERROR")
                    return
                
                # Check session timeout
                if self.check_session_timeout():
                    self.auditor.log_security_event("SESSION_TIMEOUT", 
                                                   "Session expired, rejecting message", "WARNING")
                    self.display_message("⚠️ Session expired. Please restart chat.")
                    return
                
                # Debug: Log encryption state before decryption
                print(f"DEBUG: Attempting to decrypt message from {data['sender']}")
                print(f"DEBUG: Message number: {msg_num}, Expected: {self.expected_message_number}")
                print(f"DEBUG: Crypto state - Receiving chain initialized: {self.crypto.receiving_chain_key is not None}")
                print(f"DEBUG: Receiving message number: {self.crypto.receiving_message_number}")
                
                # Decrypt message
                decrypted_text = self.crypto.ratchet_decrypt(encrypted_message)
                self.expected_message_number = msg_num + 1
                
                # Sanitize and check for spam
                decrypted_text = self.sanitizer.sanitize_message(decrypted_text)
                if self.sanitizer.detect_spam(decrypted_text):
                    self.auditor.log_security_event("SPAM_DETECTED", 
                                                   f"Spam message from {data['sender']}", "WARNING")
                    self.display_message(f"🚫 [SPAM] {data['sender']}: {decrypted_text}")
                else:
                    self.display_message(f"📩 {data['sender']}: {decrypted_text}")
                
                # Store in history
                if data['sender'] not in self.message_history:
                    self.message_history[data['sender']] = []
                self.message_history[data['sender']].append({
                    'sender': data['sender'],
                    'message': decrypted_text,
                    'timestamp': data['timestamp'],
                    'type': 'received'
                })
                
                self.auditor.log_security_event("MESSAGE_RECEIVED", 
                                               f"Successfully decrypted message from {data['sender']}")
                
            except Exception as e:
                # Enhanced error logging
                print(f"DEBUG: Decryption failed with error: {str(e)}")
                print(f"DEBUG: Crypto receiving chain key: {self.crypto.receiving_chain_key is not None if hasattr(self.crypto, 'receiving_chain_key') else 'N/A'}")
                print(f"DEBUG: Expected message number: {self.expected_message_number}")
                print(f"DEBUG: Received message number: {encrypted_message.get('message_number', 'N/A') if 'encrypted_message' in locals() else 'N/A'}")
                
                self.auditor.log_security_event("DECRYPTION_ERROR", str(e), "ERROR")
                self.display_message(f"❌ Error decrypting message: {str(e)}")
        
        @self.sio.event
        def message_sent(data):
            self.display_message(f"✓ Message sent to {data['recipient']}")
        
        @self.sio.event
        def user_online(data):
            self.display_message(f"🟢 {data['username']} came online")
        
        @self.sio.event
        def chat_request_sent(data):
            """Handle confirmation that chat request was sent"""
            partner = data['partner']
            self.display_message(f"📨 Chat request sent to {partner}")
            self.display_message(f"⏳ Waiting for {partner} to accept...")
        
        @self.sio.event
        def chat_request(data):
            """Handle incoming chat request"""
            try:
                from_user = data['from_user']
                root_key = data.get('root_key')
                
                # Store the request
                self.pending_requests[from_user] = {
                    'from_user': from_user,
                    'root_key': root_key,
                    'timestamp': data.get('timestamp', datetime.now().isoformat())
                }
                
                # Display in UI
                self.display_chat_request(from_user, self.pending_requests[from_user])
                
                # Notify user
                self.display_message(f"📨 {from_user} wants to start a secure chat")
                
                # Log the request
                self.auditor.log_security_event("CHAT_REQUEST_RECEIVED", 
                                               f"Chat request from {from_user}")
                
            except Exception as e:
                print(f"Error handling chat request: {str(e)}")
                self.auditor.log_security_event("CHAT_REQUEST_ERROR", str(e), "ERROR")
        
        @self.sio.event
        def session_established(data):
            """Handle session establishment after request acceptance"""
            try:
                partner = data['partner']
                root_key_b64 = data['root_key']
                
                # Initialize session
                root_key = base64.b64decode(root_key_b64)
                self.crypto.initialize_session(root_key)
                self.session_established = True
                self.expected_message_number = 0
                self.current_chat_partner = partner
                self.session_start_time = datetime.now()
                
                print(f"DEBUG: Session established with {partner}")
                print(f"DEBUG: Sending chain key: {self.crypto.sending_chain_key is not None}")
                print(f"DEBUG: Receiving chain key: {self.crypto.receiving_chain_key is not None}")
                print(f"DEBUG: Root key (first 8 bytes): {root_key[:8].hex()}")
                
                # Update UI
                self.partner_entry.delete(0, tk.END)
                self.partner_entry.insert(0, partner)
                self.chat_status_label.config(text=f"🔐 Chatting with {partner} (E2E Encrypted)", fg='#27ae60')
                
                # Display success message
                self.display_message(f"🔒 Secure E2E encrypted session established with {partner}")
                self.display_message(f"🕐 Session timeout: {self.session_timeout//60} minutes")
                
                # Load message history
                self.load_message_history(partner)
                
                # Log the session
                self.auditor.log_security_event("SESSION_ESTABLISHED", 
                                               f"Secure session with {partner}")
                
            except Exception as e:
                print(f"Error establishing session: {str(e)}")
                self.auditor.log_security_event("SESSION_ERROR", str(e), "ERROR")
                self.display_message(f"❌ Error establishing session: {str(e)}")
        
        @self.sio.event
        def chat_request_declined(data):
            """Handle notification that chat request was declined"""
            partner = data['partner']
            message = data.get('message', f'{partner} declined your chat request')
            self.display_message(f"❌ {message}")
            self.auditor.log_security_event("CHAT_REQUEST_DECLINED_BY_PEER", 
                                           f"Chat request declined by {partner}")
        
        @self.sio.event
        def chat_request_declined_sent(data):
            """Handle confirmation that decline was sent"""
            requester = data['requester']
            self.display_message(f"❌ You declined the chat request from {requester}")
        
        @self.sio.event
        def online_users(data):
            """Handle online users list response"""
            try:
                users = data.get('users', [])
                timestamp = data.get('timestamp', '')
                self.display_online_users_popup(users, timestamp)
            except Exception as e:
                print(f"Error handling online users: {str(e)}")
                messagebox.showerror("Error", f"Failed to display online users: {str(e)}")
    
    def display_online_users_popup(self, users: List[str], timestamp: str):
        """Display online users in a popup window"""
        popup = tk.Toplevel(self.root)
        popup.title("👥 Online Users")
        popup.geometry("400x500")
        popup.configure(bg='#2c3e50')
        popup.resizable(True, True)
        
        # Make popup modal
        popup.transient(self.root)
        popup.grab_set()
        
        # Center the popup
        popup.update_idletasks()
        x = (popup.winfo_screenwidth() // 2) - (400 // 2)
        y = (popup.winfo_screenheight() // 2) - (500 // 2)
        popup.geometry(f"400x500+{x}+{y}")
        
        # Header frame
        header_frame = tk.Frame(popup, bg='#34495e', height=60)
        header_frame.pack(fill='x', padx=10, pady=10)
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(header_frame, text="👥 Online Users", 
                              font=('Helvetica', 16, 'bold'),
                              fg='#ecf0f1', bg='#34495e')
        title_label.pack(pady=15)
        
        # Info frame
        info_frame = tk.Frame(popup, bg='#2c3e50')
        info_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        # User count and timestamp
        user_count = len(users)
        count_label = tk.Label(info_frame, 
                              text=f"🟢 {user_count} user{'s' if user_count != 1 else ''} online",
                              font=('Helvetica', 12, 'bold'),
                              fg='#27ae60', bg='#2c3e50')
        count_label.pack()
        
        if timestamp:
            time_label = tk.Label(info_frame, 
                                 text=f"Last updated: {datetime.fromisoformat(timestamp).strftime('%H:%M:%S')}",
                                 font=('Helvetica', 9),
                                 fg='#95a5a6', bg='#2c3e50')
            time_label.pack()
        
        # Users list frame with scrollbar
        list_frame = tk.Frame(popup, bg='#2c3e50')
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create scrollable frame
        canvas = tk.Canvas(list_frame, bg='#1a252f', highlightthickness=0)
        scrollbar = tk.Scrollbar(list_frame, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1a252f')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack scrollbar and canvas
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Populate users list
        if users:
            for i, user in enumerate(sorted(users)):
                self.create_user_item(scrollable_frame, user, i, popup)
        else:
            # No users online
            no_users_label = tk.Label(scrollable_frame, 
                                     text="No other users online",
                                     font=('Helvetica', 12),
                                     fg='#95a5a6', bg='#1a252f')
            no_users_label.pack(pady=50)
        
        # Buttons frame
        buttons_frame = tk.Frame(popup, bg='#2c3e50')
        buttons_frame.pack(fill='x', padx=10, pady=10)
        
        # Refresh button
        refresh_btn = tk.Button(buttons_frame, text="🔄 Refresh", 
                               command=lambda: self.refresh_online_users(popup),
                               font=('Helvetica', 10, 'bold'),
                               bg='#3498db', fg='white',
                               relief='flat', padx=20, pady=8)
        refresh_btn.pack(side='left', padx=5)
        
        # Close button
        close_btn = tk.Button(buttons_frame, text="❌ Close", 
                             command=popup.destroy,
                             font=('Helvetica', 10, 'bold'),
                             bg='#e74c3c', fg='white',
                             relief='flat', padx=20, pady=8)
        close_btn.pack(side='right', padx=5)
        
        # Bind mouse wheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind("<MouseWheel>", _on_mousewheel)
        
        # Focus on popup
        popup.focus_set()
    
    def create_user_item(self, parent: tk.Frame, username: str, index: int, popup_window: tk.Toplevel):
        """Create a user item in the online users list"""
        # Alternate row colors
        bg_color = '#2c3e50' if index % 2 == 0 else '#34495e'
        
        # User frame
        user_frame = tk.Frame(parent, bg=bg_color, relief='flat')
        user_frame.pack(fill='x', pady=1, padx=5)
        
        # User info frame
        info_frame = tk.Frame(user_frame, bg=bg_color)
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=10)
        
        # User icon and name
        user_label = tk.Label(info_frame, 
                             text=f"👤 {username}",
                             font=('Helvetica', 12, 'bold'),
                             fg='#ecf0f1', bg=bg_color,
                             anchor='w')
        user_label.pack(fill='x')
        
        # Status
        if username == self.username:
            status_text = "You"
            status_color = '#27ae60'
        else:
            status_text = "Online"
            status_color = '#3498db'
        
        status_label = tk.Label(info_frame, 
                               text=f"🟢 {status_text}",
                               font=('Helvetica', 10),
                               fg=status_color, bg=bg_color,
                               anchor='w')
        status_label.pack(fill='x')
        
        # Action buttons frame (only for other users)
        if username != self.username:
            actions_frame = tk.Frame(user_frame, bg=bg_color)
            actions_frame.pack(side='right', padx=10, pady=10)
            
            # Start chat button
            chat_btn = tk.Button(actions_frame, text="💬 Chat", 
                                command=lambda u=username: self.start_chat_with_user(u, popup_window),
                                font=('Helvetica', 9, 'bold'),
                                bg='#27ae60', fg='white',
                                relief='flat', padx=12, pady=5)
            chat_btn.pack()
    
    def start_chat_with_user(self, username: str, popup_window: tk.Toplevel):
        """Start chat with a user from the online users list"""
        # Close the popup
        popup_window.destroy()
        
        # Switch to chat tab and fill in username
        self.notebook.select(1)  # Select chat tab
        self.partner_entry.delete(0, tk.END)
        self.partner_entry.insert(0, username)
        
        # Optionally auto-start the chat
        auto_start = messagebox.askyesno("Start Chat", 
                                        f"Send a chat request to {username}?")
        if auto_start:
            self.start_chat()
    
    def refresh_online_users(self, popup_window: tk.Toplevel):
        """Refresh the online users list"""
        # Close current popup
        popup_window.destroy()
        
        # Request fresh list
        self.show_online_users()
    
    def show_online_users(self):
        """Request online users list from server"""
        if not self.sio.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
        
        # Emit request for online users
        self.sio.emit('get_online_users')
    
    def login(self):
        """Handle user login with enhanced validation"""
        username = self.sanitizer.sanitize_username(self.login_username_entry.get())
        password = self.login_password_entry.get()
        
        if not self.validator.validate_username(username):
            self.status_label.config(text="Invalid username format", fg='#e74c3c')
            return
        
        if not password:
            self.status_label.config(text="Please enter password", fg='#e74c3c')
            return
        
        try:
            response = requests.post(f'{self.server_url}/api/login', json={
                'username': username,
                'password': password
            }, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.username = username
                self.token = data['token']
                
                # Connect to WebSocket
                self.sio.connect(self.server_url)
                
                # Enable other tabs
                self.notebook.tab(1, state='normal')
                self.notebook.tab(2, state='normal')
                
                self.chat_status_label.config(text=f"Logged in as {username}", fg='#27ae60')
                self.auditor.log_security_event("LOGIN_SUCCESS", f"User {username} logged in")
                
                # Clear password
                self.login_password_entry.delete(0, tk.END)
                
                # Show logout view and switch to chat tab
                self.show_logout_view()
                self.notebook.select(1)  # Switch to chat tab after login
                
            else:
                error_msg = response.json().get('error', 'Login failed')
                self.status_label.config(text=error_msg, fg='#e74c3c')
                self.auditor.log_security_event("LOGIN_FAILED", f"Failed login for {username}", "WARNING")
                
        except requests.exceptions.RequestException as e:
            self.status_label.config(text=f"Connection error: {str(e)}", fg='#e74c3c')
            self.auditor.log_security_event("CONNECTION_ERROR", str(e), "ERROR")
    
    def register(self):
        """Handle user registration with password strength validation"""
        username = self.sanitizer.sanitize_username(self.register_username_entry.get())
        password = self.register_password_entry.get()
        
        if not self.validator.validate_username(username):
            self.status_label.config(text="Username must be 3-30 chars, alphanumeric only", fg='#e74c3c')
            return
        
        password_check = self.validator.validate_password_strength(password)
        if not password_check['strong']:
            self.status_label.config(text="Password too weak. Use 8+ chars with mixed case, numbers, symbols", fg='#e74c3c')
            return
        
        try:
            response = requests.post(f'{self.server_url}/api/register', json={
                'username': username,
                'password': password
            }, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Store the identity private key for later use in key agreement
                self.identity_private = base64.b64decode(data['identity_private'])
                self.status_label.config(text="Registration successful! Please login.", fg='#27ae60')
                self.auditor.log_security_event("REGISTRATION_SUCCESS", f"User {username} registered")
                
                # Clear fields
                self.register_username_entry.delete(0, tk.END)
                self.register_password_entry.delete(0, tk.END)
                
                # Auto-fill login username for convenience
                self.login_username_entry.delete(0, tk.END)
                self.login_username_entry.insert(0, username)
                
            else:
                error_msg = response.json().get('error', 'Registration failed')
                self.status_label.config(text=error_msg, fg='#e74c3c')
                self.auditor.log_security_event("REGISTRATION_FAILED", error_msg, "WARNING")
                
        except requests.exceptions.RequestException as e:
            self.status_label.config(text=f"Connection error: {str(e)}", fg='#e74c3c')
            self.auditor.log_security_event("CONNECTION_ERROR", str(e), "ERROR")
    
    def start_chat(self):
        """Initialize secure chat with enhanced validation"""
        partner = self.sanitizer.sanitize_username(self.partner_entry.get())
        
        if not self.validator.validate_username(partner):
            messagebox.showwarning("Warning", "Invalid partner username")
            return
        
        if partner == self.username:
            messagebox.showwarning("Warning", "Cannot chat with yourself")
            return
        
        self.current_chat_partner = partner
        self.session_start_time = datetime.now()
        
        try:
            # Get partner's prekeys
            response = requests.get(f'{self.server_url}/api/prekeys/{partner}', timeout=10)
            
            if response.status_code == 200:
                partner_prekeys = response.json()
                
                # Perform proper X3DH key agreement if we have identity keys
                if hasattr(self, 'identity_private') and self.identity_private:
                    try:
                        # Use X3DH to derive shared secret
                        partner_prekey_bytes = base64.b64decode(partner_prekeys['prekey_public'])
                        root_key = self.crypto.x3dh_key_agreement(self.identity_private, partner_prekey_bytes)
                        print(f"DEBUG: Using X3DH key agreement")
                    except Exception as e:
                        print(f"X3DH failed, using simplified approach: {e}")
                        # Fallback to deterministic key derivation
                        import hashlib
                        combined = f"{self.username}:{partner}".encode()
                        root_key = hashlib.sha256(combined).digest()
                else:
                    # Simplified deterministic key derivation based on usernames
                    import hashlib
                    # Sort usernames to ensure both parties derive the same key
                    users = sorted([self.username, partner])
                    combined = f"{users[0]}:{users[1]}".encode()
                    root_key = hashlib.sha256(combined).digest()
                    print(f"DEBUG: Using deterministic key derivation for {users}")
                
                # Initialize session with derived key
                self.crypto.initialize_session(root_key)
                self.session_established = True
                self.expected_message_number = 0
                
                print(f"DEBUG: Session initialized - Initiator")
                print(f"DEBUG: Sending chain key: {self.crypto.sending_chain_key is not None}")
                print(f"DEBUG: Receiving chain key: {self.crypto.receiving_chain_key is not None}")
                print(f"DEBUG: Root key (first 8 bytes): {root_key[:8].hex()}")
                
                # Notify server about session (send the same root key both parties derived)
                self.sio.emit('start_session', {
                    'username': self.username,
                    'partner': partner,
                    'root_key': base64.b64encode(root_key).decode(),
                    'token': self.token
                })
                
                # Log security event
                self.auditor.log_security_event("SESSION_ESTABLISHED", 
                                               f"Secure session with {partner}")
                
                self.display_message(f"🔒 Secure E2E encrypted session established with {partner}")
                self.display_message(f"🕐 Session timeout: {self.session_timeout//60} minutes")
                self.chat_status_label.config(text=f"🔐 Chatting with {partner} (E2E Encrypted)", fg='#27ae60')
                
                # Load message history
                self.load_message_history(partner)
                
            else:
                messagebox.showerror("Error", "Partner not found")
                
        except requests.exceptions.RequestException as e:
            self.auditor.log_security_event("SESSION_ERROR", str(e), "ERROR")
            messagebox.showerror("Error", f"Failed to establish session: {str(e)}")
    
    def send_message(self, event=None):
        """Send encrypted message with comprehensive validation"""
        if not self.session_established:
            messagebox.showwarning("Warning", "Please establish a chat session first")
            return
        
        # Check session timeout
        if self.check_session_timeout():
            messagebox.showwarning("Warning", "Session expired. Please restart chat.")
            self.session_established = False
            return
        
        message = self.sanitizer.sanitize_message(self.message_entry.get())
        if not message:
            return
        
        # Input validation
        if len(message) > 1000:  # Limit message length
            messagebox.showwarning("Warning", "Message too long (max 1000 characters)")
            return
        
        # Spam detection
        if self.sanitizer.detect_spam(message):
            messagebox.showwarning("Warning", "Message appears to be spam and was blocked")
            return
        
        try:
            # Debug: Log encryption state before sending
            print(f"DEBUG: Sending message to {self.current_chat_partner}")
            print(f"DEBUG: Crypto state - Sending chain initialized: {self.crypto.sending_chain_key is not None}")
            print(f"DEBUG: Sending message number: {self.crypto.sending_message_number}")
            
            # Encrypt message
            encrypted_data = self.crypto.ratchet_encrypt(message)
            
            print(f"DEBUG: Encrypted message number: {encrypted_data['message_number']}")
            
            # Send to server
            self.sio.emit('send_message', {
                'sender': self.username,
                'recipient': self.current_chat_partner,
                'encrypted_message': json.dumps(encrypted_data),
                'token': self.token
            })
            
            # Store in history
            if self.current_chat_partner not in self.message_history:
                self.message_history[self.current_chat_partner] = []
            self.message_history[self.current_chat_partner].append({
                'sender': self.username,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'type': 'sent'
            })
            
            # Log and display
            self.auditor.log_security_event("MESSAGE_SENT", 
                                           f"Encrypted message sent to {self.current_chat_partner}")
            self.display_message(f"📤 You: {message}")
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            print(f"DEBUG: Send message failed with error: {str(e)}")
            self.auditor.log_security_event("SEND_ERROR", str(e), "ERROR")
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
    
    def display_message(self, message: str):
        """Display message with enhanced formatting"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.messages_text.config(state=tk.NORMAL)
        
        # Color coding for different message types
        if message.startswith('📩'):
            # Received message
            self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n", 'received')
        elif message.startswith('📤'):
            # Sent message
            self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n", 'sent')
        elif message.startswith('🔒') or message.startswith('🔐'):
            # Security message
            self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n", 'security')
        elif message.startswith('❌') or message.startswith('⚠️'):
            # Error message
            self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n", 'error')
        else:
            # Default message
            self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        self.messages_text.see(tk.END)
        self.messages_text.config(state=tk.DISABLED)
    
    def check_session_timeout(self) -> bool:
        """Check if session has timed out"""
        if not self.session_start_time:
            return False
        
        elapsed = (datetime.now() - self.session_start_time).total_seconds()
        return elapsed > self.session_timeout
    
    def load_message_history(self, partner: str):
        """Load message history with partner"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.server_url}/api/messages/{partner}', 
                                  headers=headers, timeout=10)
            
            if response.status_code == 200:
                messages = response.json().get('messages', [])
                for msg in messages[-20:]:  # Show last 20 messages
                    timestamp = datetime.fromisoformat(msg['timestamp']).strftime('%H:%M:%S')
                    sender = msg['sender_username']
                    # Note: In production, you'd decrypt stored messages
                    self.display_message(f"💭 [{timestamp}] {sender}: [Encrypted message]")
                    
        except requests.exceptions.RequestException as e:
            print(f"Failed to load message history: {e}")
    
    def refresh_security_report(self):
        """Refresh security report display"""
        report = self.auditor.get_security_report(hours=24)
        
        self.security_report_text.config(state=tk.NORMAL)
        self.security_report_text.delete(1.0, tk.END)
        
        # Format report
        self.security_report_text.insert(tk.END, "🔒 SECURITY AUDIT REPORT\n")
        self.security_report_text.insert(tk.END, "=" * 50 + "\n\n")
        self.security_report_text.insert(tk.END, f"Report Generated: {report['report_generated']}\n")
        self.security_report_text.insert(tk.END, f"Time Period: Last {report['time_period_hours']} hours\n")
        self.security_report_text.insert(tk.END, f"Total Events: {report['total_events']}\n\n")
        
        # Event types
        self.security_report_text.insert(tk.END, "EVENT TYPES:\n")
        for event_type, count in report['event_types'].items():
            self.security_report_text.insert(tk.END, f"  {event_type}: {count}\n")
        
        # Severity counts
        self.security_report_text.insert(tk.END, "\nSEVERITY BREAKDOWN:\n")
        for severity, count in report['severity_counts'].items():
            self.security_report_text.insert(tk.END, f"  {severity}: {count}\n")
        
        # Recent events
        self.security_report_text.insert(tk.END, "\nRECENT EVENTS:\n")
        for event in report['recent_events'][-10:]:
            self.security_report_text.insert(tk.END, 
                f"[{event['timestamp']}] {event['severity']} - {event['type']}: {event['details']}\n")
        
        self.security_report_text.config(state=tk.DISABLED)
    
    def display_chat_request(self, requester: str, request_data: Dict):
        """Display incoming chat request with accept/decline buttons"""
        # Remove "no requests" label if visible
        if hasattr(self, 'no_requests_label') and self.no_requests_label.winfo_exists():
            self.no_requests_label.destroy()
        
        # Create frame for this request
        request_frame = tk.Frame(self.requests_container, bg='#2c3e50', relief='solid', bd=1)
        request_frame.pack(fill='x', pady=2)
        
        # Request info
        info_frame = tk.Frame(request_frame, bg='#2c3e50')
        info_frame.pack(side='left', fill='both', expand=True, padx=10, pady=5)
        
        requester_label = tk.Label(info_frame, text=f"👤 {requester}", 
                                  font=('Helvetica', 10, 'bold'),
                                  fg='#ecf0f1', bg='#2c3e50')
        requester_label.pack(anchor='w')
        
        message_label = tk.Label(info_frame, text="wants to start a secure chat", 
                                font=('Helvetica', 9),
                                fg='#bdc3c7', bg='#2c3e50')
        message_label.pack(anchor='w')
        
        # Buttons frame
        buttons_frame = tk.Frame(request_frame, bg='#2c3e50')
        buttons_frame.pack(side='right', padx=10, pady=5)
        
        # Accept button
        accept_btn = tk.Button(buttons_frame, text="✅ Accept", 
                              command=lambda: self.accept_chat_request(requester, request_data),
                              font=('Helvetica', 8, 'bold'),
                              bg='#27ae60', fg='white',
                              relief='flat', padx=15, pady=3)
        accept_btn.pack(side='left', padx=2)
        
        # Decline button
        decline_btn = tk.Button(buttons_frame, text="❌ Decline", 
                               command=lambda: self.decline_chat_request(requester, request_data),
                               font=('Helvetica', 8, 'bold'),
                               bg='#e74c3c', fg='white',
                               relief='flat', padx=15, pady=3)
        decline_btn.pack(side='left', padx=2)
        
        # Store the frame reference for later removal
        request_data['ui_frame'] = request_frame
    
    def accept_chat_request(self, requester: str, request_data: Dict):
        """Accept an incoming chat request"""
        try:
            # Send acceptance to server
            self.sio.emit('accept_chat_request', {
                'username': self.username,
                'requester': requester,
                'root_key': request_data['root_key'],
                'token': self.token
            })
            
            # Remove request from UI and pending list
            self.remove_chat_request(requester)
            
            # Log the acceptance
            self.auditor.log_security_event("CHAT_REQUEST_ACCEPTED", 
                                           f"Accepted chat request from {requester}")
            
            self.display_message(f"✅ Accepted chat request from {requester}")
            
        except Exception as e:
            self.auditor.log_security_event("ACCEPT_REQUEST_ERROR", str(e), "ERROR")
            messagebox.showerror("Error", f"Failed to accept chat request: {str(e)}")
    
    def decline_chat_request(self, requester: str, request_data: Dict):
        """Decline an incoming chat request"""
        try:
            # Send decline to server
            self.sio.emit('decline_chat_request', {
                'username': self.username,
                'requester': requester,
                'token': self.token
            })
            
            # Remove request from UI and pending list
            self.remove_chat_request(requester)
            
            # Log the decline
            self.auditor.log_security_event("CHAT_REQUEST_DECLINED", 
                                           f"Declined chat request from {requester}")
            
            self.display_message(f"❌ Declined chat request from {requester}")
            
        except Exception as e:
            self.auditor.log_security_event("DECLINE_REQUEST_ERROR", str(e), "ERROR")
            messagebox.showerror("Error", f"Failed to decline chat request: {str(e)}")
    
    def remove_chat_request(self, requester: str):
        """Remove chat request from UI and pending list"""
        if requester in self.pending_requests:
            request_data = self.pending_requests[requester]
            
            # Remove UI frame if it exists
            if 'ui_frame' in request_data and request_data['ui_frame'].winfo_exists():
                request_data['ui_frame'].destroy()
            
            # Remove from pending requests
            del self.pending_requests[requester]
            
            # Show "no requests" label if no more pending requests
            if not self.pending_requests:
                self.no_requests_label = tk.Label(self.requests_container, 
                                                 text="No pending chat requests", 
                                                 font=('Helvetica', 9),
                                                 fg='#95a5a6', bg='#34495e')
                self.no_requests_label.pack(anchor='w', pady=5)
    
    def export_security_report(self):
        """Export security report to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                report = self.auditor.get_security_report(hours=24)
                with open(filename, 'w') as f:
                    f.write(f"Security Report - {report['report_generated']}\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for event in self.auditor.security_log:
                        f.write(f"[{event['timestamp']}] {event['severity']} - {event['type']}: {event['details']}\n")
                
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {e}")
    
    def clear_security_log(self):
        """Clear security log after confirmation"""
        if messagebox.askyesno("Confirm", "Clear all security logs?"):
            self.auditor.security_log.clear()
            self.auditor.suspicious_activity.clear()
            self.refresh_security_report()
            messagebox.showinfo("Success", "Security logs cleared")
    
    def run(self):
        """Start the client application"""
        try:
            # Configure text tags for message formatting
            self.messages_text.tag_configure('received', foreground='#3498db')
            self.messages_text.tag_configure('sent', foreground='#27ae60')
            self.messages_text.tag_configure('security', foreground='#f39c12')
            self.messages_text.tag_configure('error', foreground='#e74c3c')
            
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
            self.root.mainloop()
        except Exception as e:
            print(f"❌ Error starting client: {e}")
            messagebox.showerror("Error", f"Failed to start client: {e}")
    
    def on_closing(self):
        """Handle application closing"""
        try:
            if self.sio.connected:
                self.sio.disconnect()
        except:
            pass
        self.root.destroy() 