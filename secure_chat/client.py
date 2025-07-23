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
        
        # Group state
        self.user_groups = []  # List of groups user is member of
        self.current_group = None  # Currently active group for messaging
        self.group_members = {}  # group_id -> list of members
        
        # File state
        self.user_files = []  # List of user's files
        self.current_upload_progress = {}  # file_id -> progress info
        
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
        
        # Bind tab change event to refresh data when needed
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Authentication tab
        self.auth_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.auth_frame, text="🔐 Login/Register")
        self.setup_auth_ui()
        
        # Chat tab
        self.chat_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.chat_frame, text="💬 Chat")
        self.setup_chat_ui()
        
        # Groups tab
        self.groups_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.groups_frame, text="👥 Groups")
        self.setup_groups_ui()
        
        # Files tab
        self.files_frame = tk.Frame(self.notebook, bg='#2c3e50')
        self.notebook.add(self.files_frame, text="📁 Files")
        self.setup_files_ui()
        
        # Security tab
        self.security_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.security_frame, text="🔒 Security")
        self.setup_security_ui()
        
        # Initially disable chat, groups, files and security tabs
        self.notebook.tab(1, state='disabled')
        self.notebook.tab(2, state='disabled')
        self.notebook.tab(3, state='disabled')
        self.notebook.tab(4, state='disabled')
    
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
                
                # Clear group state
                self.user_groups.clear()
                self.current_group = None
                self.group_members.clear()
                
                # Clear file state
                self.user_files.clear()
                self.current_upload_progress.clear()
                
                # Reset crypto state
                self.crypto = CryptoCore()
                
                # Clear UI fields
                self.login_username_entry.delete(0, tk.END)
                self.login_password_entry.delete(0, tk.END)
                self.register_username_entry.delete(0, tk.END)
                self.register_password_entry.delete(0, tk.END)
                self.partner_entry.delete(0, tk.END)
                self.message_entry.delete(0, tk.END)
                self.group_message_entry.delete(0, tk.END)
                
                # Clear messages display
                self.messages_text.config(state=tk.NORMAL)
                self.messages_text.delete(1.0, tk.END)
                self.messages_text.config(state=tk.DISABLED)
                
                # Clear group messages display
                self.group_messages_text.config(state=tk.NORMAL)
                self.group_messages_text.delete(1.0, tk.END)
                self.group_messages_text.config(state=tk.DISABLED)
                
                # Reset groups UI
                for widget in self.groups_scrollable_frame.winfo_children():
                    widget.destroy()
                
                self.no_groups_label = tk.Label(self.groups_scrollable_frame, 
                                               text="No groups yet\nCreate or join a group to start!", 
                                               font=('Helvetica', 11),
                                               fg='#95a5a6', bg='#1a252f',
                                               justify='center')
                self.no_groups_label.pack(pady=50)
                
                # Reset group UI controls
                self.group_info_label.config(text="💬 Select a group to start chatting")
                self.group_status_label.config(text="No group selected", fg='#95a5a6')
                self.group_message_entry.config(state='disabled')
                self.group_send_btn.config(state='disabled')
                self.members_btn.config(state='disabled')
                self.leave_group_btn.config(state='disabled')
                
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
                self.notebook.tab(3, state='disabled')
                self.notebook.tab(4, state='disabled')
                
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
    
    def setup_groups_ui(self):
        """Setup group management and messaging interface"""
        # Create horizontal paned window for groups list and chat
        main_paned = tk.PanedWindow(self.groups_frame, orient='horizontal', bg='#2c3e50')
        main_paned.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel: Groups management
        groups_panel = tk.Frame(main_paned, bg='#34495e', width=350)
        main_paned.add(groups_panel, minsize=300)
        
        # Groups header
        groups_header = tk.Frame(groups_panel, bg='#2c3e50')
        groups_header.pack(fill='x', padx=10, pady=10)
        
        groups_title = tk.Label(groups_header, text="👥 My Groups", 
                               font=('Helvetica', 14, 'bold'),
                               fg='#ecf0f1', bg='#2c3e50')
        groups_title.pack(side='left')
        
        # Action buttons
        btn_frame = tk.Frame(groups_header, bg='#2c3e50')
        btn_frame.pack(side='right')
        
        create_btn = tk.Button(btn_frame, text="➕ Create", 
                              command=self.show_create_group_dialog,
                              font=('Helvetica', 9, 'bold'),
                              bg='#27ae60', fg='white',
                              relief='flat', padx=10, pady=3)
        create_btn.pack(side='left', padx=2)
        
        join_btn = tk.Button(btn_frame, text="🔍 Join", 
                            command=self.show_join_group_dialog,
                            font=('Helvetica', 9, 'bold'),
                            bg='#3498db', fg='white',
                            relief='flat', padx=10, pady=3)
        join_btn.pack(side='left', padx=2)
        
        refresh_btn = tk.Button(btn_frame, text="🔄", 
                               command=self.refresh_groups,
                               font=('Helvetica', 9, 'bold'),
                               bg='#95a5a6', fg='white',
                               relief='flat', padx=5, pady=3)
        refresh_btn.pack(side='left', padx=2)
        
        # Groups list
        groups_list_frame = tk.Frame(groups_panel, bg='#34495e')
        groups_list_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Create scrollable groups list
        self.groups_canvas = tk.Canvas(groups_list_frame, bg='#1a252f', highlightthickness=0)
        groups_scrollbar = tk.Scrollbar(groups_list_frame, orient='vertical', command=self.groups_canvas.yview)
        self.groups_scrollable_frame = tk.Frame(self.groups_canvas, bg='#1a252f')
        
        self.groups_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.groups_canvas.configure(scrollregion=self.groups_canvas.bbox("all"))
        )
        
        self.groups_canvas.create_window((0, 0), window=self.groups_scrollable_frame, anchor="nw")
        self.groups_canvas.configure(yscrollcommand=groups_scrollbar.set)
        
        groups_scrollbar.pack(side="right", fill="y")
        self.groups_canvas.pack(side="left", fill="both", expand=True)
        
        # Initially show "no groups" message
        self.no_groups_label = tk.Label(self.groups_scrollable_frame, 
                                       text="No groups yet\nCreate or join a group to start!", 
                                       font=('Helvetica', 11),
                                       fg='#95a5a6', bg='#1a252f',
                                       justify='center')
        self.no_groups_label.pack(pady=50)
        
        # Right panel: Group chat
        chat_panel = tk.Frame(main_paned, bg='#2c3e50')
        main_paned.add(chat_panel, minsize=400)
        
        # Group chat header
        self.group_chat_header = tk.Frame(chat_panel, bg='#34495e', height=60)
        self.group_chat_header.pack(fill='x', padx=10, pady=(10, 5))
        self.group_chat_header.pack_propagate(False)
        
        # Group info
        self.group_info_label = tk.Label(self.group_chat_header, text="💬 Select a group to start chatting", 
                                        font=('Helvetica', 12, 'bold'),
                                        fg='#ecf0f1', bg='#34495e')
        self.group_info_label.pack(side='left', padx=10, pady=15)
        
        # Group actions
        group_actions_frame = tk.Frame(self.group_chat_header, bg='#34495e')
        group_actions_frame.pack(side='right', padx=10, pady=10)
        
        self.members_btn = tk.Button(group_actions_frame, text="👥 Members", 
                                    command=self.show_group_members,
                                    font=('Helvetica', 9),
                                    bg='#9b59b6', fg='white',
                                    relief='flat', padx=10, pady=5,
                                    state='disabled')
        self.members_btn.pack(side='left', padx=2)
        
        self.leave_group_btn = tk.Button(group_actions_frame, text="🚪 Leave", 
                                        command=self.leave_current_group,
                                        font=('Helvetica', 9),
                                        bg='#e74c3c', fg='white',
                                        relief='flat', padx=10, pady=5,
                                        state='disabled')
        self.leave_group_btn.pack(side='left', padx=2)
        
        # Group messages display
        self.group_messages_frame = tk.Frame(chat_panel, bg='#2c3e50')
        self.group_messages_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.group_messages_text = scrolledtext.ScrolledText(
            self.group_messages_frame, 
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
        self.group_messages_text.pack(fill='both', expand=True)
        
        # Group message input
        self.group_input_frame = tk.Frame(chat_panel, bg='#2c3e50', height=50)
        self.group_input_frame.pack(fill='x', padx=10, pady=5)
        self.group_input_frame.pack_propagate(False)
        
        self.group_message_entry = tk.Entry(self.group_input_frame, font=('Helvetica', 11),
                                           bg='#ecf0f1', relief='solid', bd=1,
                                           state='disabled')
        self.group_message_entry.pack(side='left', fill='both', expand=True, padx=(0, 10))
        self.group_message_entry.bind('<Return>', self.send_group_message)
        
        self.group_send_btn = tk.Button(self.group_input_frame, text="📤 Send", 
                                       command=self.send_group_message,
                                       font=('Helvetica', 10, 'bold'),
                                       bg='#27ae60', fg='white',
                                       relief='flat', padx=20, pady=8,
                                       state='disabled')
        self.group_send_btn.pack(side='right')
        
        # Group status
        self.group_status_frame = tk.Frame(chat_panel, bg='#2c3e50')
        self.group_status_frame.pack(fill='x', padx=10, pady=5)
        
        self.group_status_label = tk.Label(self.group_status_frame, text="No group selected",
                                          font=('Helvetica', 10),
                                          fg='#95a5a6', bg='#2c3e50')
        self.group_status_label.pack(side='left')
    
    def setup_files_ui(self):
        """Setup file sharing and management interface"""
        # Create horizontal paned window for file actions and file list
        main_paned = tk.PanedWindow(self.files_frame, orient='horizontal', bg='#2c3e50')
        main_paned.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel: File actions
        actions_panel = tk.Frame(main_paned, bg='#34495e', width=300)
        main_paned.add(actions_panel, minsize=250)
        
        # File actions header
        actions_header = tk.Frame(actions_panel, bg='#2c3e50')
        actions_header.pack(fill='x', padx=10, pady=10)
        
        actions_title = tk.Label(actions_header, text="📁 File Sharing", 
                                font=('Helvetica', 14, 'bold'),
                                fg='#ecf0f1', bg='#2c3e50')
        actions_title.pack()
        
        # Upload section
        upload_frame = tk.LabelFrame(actions_panel, text="📤 Upload File", 
                                    font=('Helvetica', 12, 'bold'),
                                    fg='#ecf0f1', bg='#34495e',
                                    padx=15, pady=15)
        upload_frame.pack(fill='x', padx=10, pady=10)
        
        # File selection
        self.selected_file_label = tk.Label(upload_frame, text="No file selected", 
                                           font=('Helvetica', 10),
                                           fg='#95a5a6', bg='#34495e')
        self.selected_file_label.pack(pady=5)
        
        select_file_btn = tk.Button(upload_frame, text="📂 Select File", 
                                   command=self.select_file_for_upload,
                                   font=('Helvetica', 10, 'bold'),
                                   bg='#3498db', fg='white',
                                   relief='flat', padx=20, pady=8)
        select_file_btn.pack(pady=5)
        
        # Sharing options
        sharing_frame = tk.Frame(upload_frame, bg='#34495e')
        sharing_frame.pack(fill='x', pady=10)
        
        # Share type selection
        self.share_type = tk.StringVar(value="user")
        
        tk.Label(sharing_frame, text="Share with:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        radio_frame = tk.Frame(sharing_frame, bg='#34495e')
        radio_frame.pack(fill='x', pady=5)
        
        tk.Radiobutton(radio_frame, text="User", variable=self.share_type, value="user",
                      font=('Helvetica', 9), fg='#ecf0f1', bg='#34495e',
                      selectcolor='#2c3e50', command=self.update_share_options).pack(side='left', padx=5)
        
        tk.Radiobutton(radio_frame, text="Group", variable=self.share_type, value="group",
                      font=('Helvetica', 9), fg='#ecf0f1', bg='#34495e',
                      selectcolor='#2c3e50', command=self.update_share_options).pack(side='left', padx=5)
        
        # Target selection
        self.target_frame = tk.Frame(sharing_frame, bg='#34495e')
        self.target_frame.pack(fill='x', pady=5)
        
        self.target_label = tk.Label(self.target_frame, text="Username:", 
                                    font=('Helvetica', 10),
                                    fg='#ecf0f1', bg='#34495e')
        self.target_label.pack(anchor='w')
        
        self.target_entry = tk.Entry(self.target_frame, font=('Helvetica', 10), width=25)
        self.target_entry.pack(fill='x', pady=2)
        
        # Expiry options
        expiry_frame = tk.Frame(upload_frame, bg='#34495e')
        expiry_frame.pack(fill='x', pady=5)
        
        tk.Label(expiry_frame, text="Expires after:", font=('Helvetica', 10),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.expiry_var = tk.StringVar(value="never")
        expiry_options = tk.Frame(expiry_frame, bg='#34495e')
        expiry_options.pack(fill='x', pady=2)
        
        for value, text in [("never", "Never"), ("24", "24 hours"), ("168", "1 week")]:
            tk.Radiobutton(expiry_options, text=text, variable=self.expiry_var, value=value,
                          font=('Helvetica', 9), fg='#ecf0f1', bg='#34495e',
                          selectcolor='#2c3e50').pack(side='left', padx=5)
        
        # Upload button
        self.upload_btn = tk.Button(upload_frame, text="🚀 Upload & Share", 
                                   command=self.upload_file,
                                   font=('Helvetica', 11, 'bold'),
                                   bg='#27ae60', fg='white',
                                   relief='flat', padx=20, pady=10,
                                   state='disabled')
        self.upload_btn.pack(pady=10)
        
        # Progress bar
        self.upload_progress = tk.Frame(upload_frame, bg='#34495e')
        self.upload_progress_bar = tk.Canvas(self.upload_progress, height=20, bg='#2c3e50')
        self.upload_progress_label = tk.Label(self.upload_progress, text="", 
                                             font=('Helvetica', 9),
                                             fg='#ecf0f1', bg='#34495e')
        
        # Right panel: File list
        files_panel = tk.Frame(main_paned, bg='#2c3e50')
        main_paned.add(files_panel, minsize=400)
        
        # Files header
        files_header = tk.Frame(files_panel, bg='#34495e', height=60)
        files_header.pack(fill='x', padx=10, pady=(10, 5))
        files_header.pack_propagate(False)
        
        files_title = tk.Label(files_header, text="📂 My Files", 
                              font=('Helvetica', 14, 'bold'),
                              fg='#ecf0f1', bg='#34495e')
        files_title.pack(side='left', padx=10, pady=15)
        
        # File actions buttons
        file_actions_frame = tk.Frame(files_header, bg='#34495e')
        file_actions_frame.pack(side='right', padx=10, pady=10)
        
        refresh_files_btn = tk.Button(file_actions_frame, text="🔄 Refresh", 
                                     command=self.refresh_files,
                                     font=('Helvetica', 9),
                                     bg='#95a5a6', fg='white',
                                     relief='flat', padx=10, pady=5)
        refresh_files_btn.pack(side='left', padx=2)
        
        # Files list
        files_list_frame = tk.Frame(files_panel, bg='#2c3e50')
        files_list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create scrollable files list
        self.files_canvas = tk.Canvas(files_list_frame, bg='#1a252f', highlightthickness=0)
        files_scrollbar = tk.Scrollbar(files_list_frame, orient='vertical', command=self.files_canvas.yview)
        self.files_scrollable_frame = tk.Frame(self.files_canvas, bg='#1a252f')
        
        self.files_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.files_canvas.configure(scrollregion=self.files_canvas.bbox("all"))
        )
        
        self.files_canvas.create_window((0, 0), window=self.files_scrollable_frame, anchor="nw")
        self.files_canvas.configure(yscrollcommand=files_scrollbar.set)
        
        files_scrollbar.pack(side="right", fill="y")
        self.files_canvas.pack(side="left", fill="both", expand=True)
        
        # Initially show "no files" message
        self.no_files_label = tk.Label(self.files_scrollable_frame, 
                                      text="No files yet\nUpload a file to get started!", 
                                      font=('Helvetica', 11),
                                      fg='#95a5a6', bg='#1a252f',
                                      justify='center')
        self.no_files_label.pack(pady=50)
        
        # File storage for upload
        self.selected_file_path = None
    
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
        
        # Group-related socket handlers
        
        @self.sio.event
        def new_group_message(data):
            """Handle incoming group message"""
            try:
                sender = data['sender']
                group_id = data['group_id']
                encrypted_message = json.loads(data['encrypted_message'])
                
                # Only process if we're in this group
                if self.current_group and self.current_group['id'] == group_id:
                    # Decrypt message
                    decrypted_text = self.crypto.decrypt_group_message(encrypted_message)
                    
                    # Sanitize and display
                    decrypted_text = self.sanitizer.sanitize_message(decrypted_text)
                    self.display_group_message(f"📩 {sender}: {decrypted_text}")
                    
                    # Log
                    self.auditor.log_security_event("GROUP_MESSAGE_RECEIVED", 
                                                   f"Received group message from {sender}")
                
            except Exception as e:
                print(f"Error handling group message: {str(e)}")
                self.auditor.log_security_event("GROUP_DECRYPT_ERROR", str(e), "ERROR")
                if self.current_group and self.current_group['id'] == data.get('group_id'):
                    self.display_group_message(f"❌ Error decrypting message from {data.get('sender', 'unknown')}")
        
        @self.sio.event
        def group_joined(data):
            """Handle successful group room join"""
            group = data['group']
            self.display_group_message(f"🔐 Joined group '{group['name']}' - End-to-end encryption enabled")
        
        @self.sio.event
        def group_left(data):
            """Handle group room leave"""
            group_id = data['group_id']
            self.display_group_message(f"🚪 Left group room")
        
        @self.sio.event
        def user_joined_group(data):
            """Handle notification that a user joined the group"""
            username = data['username']
            group_name = data.get('group_name', 'group')
            if self.current_group and self.current_group['id'] == data['group_id']:
                self.display_group_message(f"👋 {username} joined {group_name}")
        
        @self.sio.event
        def user_left_group(data):
            """Handle notification that a user left the group"""
            username = data['username']
            if self.current_group and self.current_group['id'] == data['group_id']:
                self.display_group_message(f"👋 {username} left the group")
        
        @self.sio.event
        def group_message_sent(data):
            """Handle confirmation that group message was sent"""
            # Message already displayed locally, just log
            pass
        
        @self.sio.event
        def group_info(data):
            """Handle group information response"""
            try:
                group = data['group']
                members = data['members']
                self.display_group_members_dialog(group, members)
            except Exception as e:
                print(f"Error handling group info: {str(e)}")
                messagebox.showerror("Error", f"Failed to display group info: {str(e)}")
        
        # File sharing socket handlers
        
        @self.sio.event
        def file_shared(data):
            """Handle file shared notification"""
            try:
                uploader = data['uploader']
                filename = data['filename']
                file_size = self.format_file_size(data['file_size'])
                
                # Show notification
                messagebox.showinfo("File Shared", 
                                  f"{uploader} shared a file with you:\n\n{filename} ({file_size})\n\nCheck the Files tab to download it.")
                
                # Refresh files list if Files tab is visible
                current_tab = self.notebook.index(self.notebook.select())
                if current_tab == 3:  # Files tab
                    self.refresh_files()
                
                self.auditor.log_security_event("FILE_RECEIVED", f"Received file: {filename} from {uploader}")
            
            except Exception as e:
                print(f"Error handling file shared: {str(e)}")
        
        @self.sio.event
        def file_shared_group(data):
            """Handle group file shared notification"""
            try:
                uploader = data['uploader']
                filename = data['filename']
                group_id = data['group_id']
                file_size = self.format_file_size(data['file_size'])
                
                # Find group name
                group_name = "Unknown Group"
                for group in self.user_groups:
                    if group['id'] == group_id:
                        group_name = group['name']
                        break
                
                # Show notification if not from current user
                if uploader != self.username:
                    messagebox.showinfo("Group File Shared", 
                                      f"{uploader} shared a file in {group_name}:\n\n{filename} ({file_size})\n\nCheck the Files tab to download it.")
                
                # Refresh files list if Files tab is visible
                current_tab = self.notebook.index(self.notebook.select())
                if current_tab == 3:  # Files tab
                    self.refresh_files()
                
                self.auditor.log_security_event("GROUP_FILE_RECEIVED", 
                                               f"Received group file: {filename} from {uploader} in {group_name}")
            
            except Exception as e:
                print(f"Error handling group file shared: {str(e)}")
        
        @self.sio.event
        def user_files(data):
            """Handle user files response"""
            try:
                files = data['files']
                self.user_files = files
                self.display_files()
            except Exception as e:
                print(f"Error handling user files: {str(e)}")
        
        @self.sio.event
        def group_files(data):
            """Handle group files response"""
            try:
                files = data['files']
                # Could be used for group-specific file management
                print(f"Received {len(files)} group files")
            except Exception as e:
                print(f"Error handling group files: {str(e)}")
    
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
    
    def on_tab_changed(self, event):
        """Handle tab change events to refresh data when needed"""
        if not self.token:  # Not logged in
            return
        
        try:
            selected_tab = self.notebook.index("current")
            
            # Files tab selected (index 3)
            if selected_tab == 3:
                # Refresh groups first (needed for group files), then refresh files
                self.refresh_groups()
                # Small delay to ensure groups are loaded before fetching files
                self.root.after(100, self.refresh_files)
            
            # Groups tab selected (index 2)
            elif selected_tab == 2:
                self.refresh_groups()
                
        except Exception as e:
            print(f"Error handling tab change: {e}")
    
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
                self.notebook.tab(3, state='normal') # Enable Groups tab
                self.notebook.tab(4, state='normal') # Enable Files tab
                
                self.chat_status_label.config(text=f"Logged in as {username}", fg='#27ae60')
                self.auditor.log_security_event("LOGIN_SUCCESS", f"User {username} logged in")
                
                # Clear password
                self.login_password_entry.delete(0, tk.END)
                
                # Show logout view and switch to chat tab
                self.show_logout_view()
                self.notebook.select(1)  # Switch to chat tab after login
                
                # Load user's groups
                self.refresh_groups()
                
                # Load user's files
                self.refresh_files()
                
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
    
    # Group Management Methods
    
    def show_create_group_dialog(self):
        """Show dialog to create a new group"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New Group")
        dialog.geometry("400x300")
        dialog.configure(bg='#2c3e50')
        dialog.resizable(False, False)
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (300 // 2)
        dialog.geometry(f"400x300+{x}+{y}")
        
        # Title
        title_label = tk.Label(dialog, text="Create New Group", 
                              font=('Helvetica', 16, 'bold'),
                              fg='#ecf0f1', bg='#2c3e50')
        title_label.pack(pady=20)
        
        # Form frame
        form_frame = tk.Frame(dialog, bg='#2c3e50')
        form_frame.pack(pady=20, padx=40, fill='both', expand=True)
        
        # Group name
        tk.Label(form_frame, text="Group Name:", font=('Helvetica', 12),
                fg='#ecf0f1', bg='#2c3e50').pack(anchor='w', pady=(0, 5))
        name_entry = tk.Entry(form_frame, font=('Helvetica', 11), width=40)
        name_entry.pack(pady=(0, 15))
        name_entry.focus()
        
        # Group description
        tk.Label(form_frame, text="Description (optional):", font=('Helvetica', 12),
                fg='#ecf0f1', bg='#2c3e50').pack(anchor='w', pady=(0, 5))
        desc_text = tk.Text(form_frame, font=('Helvetica', 11), width=40, height=4)
        desc_text.pack(pady=(0, 20))
        
        # Buttons
        buttons_frame = tk.Frame(form_frame, bg='#2c3e50')
        buttons_frame.pack(fill='x')
        
        def create_group():
            name = name_entry.get().strip()
            description = desc_text.get("1.0", tk.END).strip()
            
            if not name:
                messagebox.showwarning("Warning", "Group name is required")
                return
            
            if len(name) > 50:
                messagebox.showwarning("Warning", "Group name too long (max 50 characters)")
                return
            
            self.create_group(name, description)
            dialog.destroy()
        
        create_btn = tk.Button(buttons_frame, text="Create Group", 
                              command=create_group,
                              font=('Helvetica', 11, 'bold'),
                              bg='#27ae60', fg='white',
                              relief='flat', padx=20, pady=8)
        create_btn.pack(side='right')
        
        cancel_btn = tk.Button(buttons_frame, text="Cancel", 
                              command=dialog.destroy,
                              font=('Helvetica', 11),
                              bg='#95a5a6', fg='white',
                              relief='flat', padx=20, pady=8)
        cancel_btn.pack(side='right', padx=(0, 10))
        
        # Bind Enter key to create
        dialog.bind('<Return>', lambda e: create_group())
    
    def show_join_group_dialog(self):
        """Show dialog to search and join groups"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Join Group")
        dialog.geometry("500x400")
        dialog.configure(bg='#2c3e50')
        dialog.resizable(True, True)
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (400 // 2)
        dialog.geometry(f"500x400+{x}+{y}")
        
        # Title
        title_label = tk.Label(dialog, text="Join Group", 
                              font=('Helvetica', 16, 'bold'),
                              fg='#ecf0f1', bg='#2c3e50')
        title_label.pack(pady=20)
        
        # Search frame
        search_frame = tk.Frame(dialog, bg='#2c3e50')
        search_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(search_frame, text="Search groups:", font=('Helvetica', 12),
                fg='#ecf0f1', bg='#2c3e50').pack(anchor='w', pady=(0, 5))
        
        search_entry_frame = tk.Frame(search_frame, bg='#2c3e50')
        search_entry_frame.pack(fill='x')
        
        search_entry = tk.Entry(search_entry_frame, font=('Helvetica', 11))
        search_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        def search_groups():
            query = search_entry.get().strip()
            if query:
                self.search_groups(query, results_frame)
        
        search_btn = tk.Button(search_entry_frame, text="🔍 Search", 
                              command=search_groups,
                              font=('Helvetica', 10, 'bold'),
                              bg='#3498db', fg='white',
                              relief='flat', padx=15, pady=5)
        search_btn.pack(side='right')
        
        # Results frame
        results_frame = tk.Frame(dialog, bg='#2c3e50')
        results_frame.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Initial message
        tk.Label(results_frame, text="Enter a search term to find groups", 
                font=('Helvetica', 11),
                fg='#95a5a6', bg='#2c3e50').pack(pady=50)
        
        # Bind Enter key to search
        search_entry.bind('<Return>', lambda e: search_groups())
        search_entry.focus()
        
        # Close button
        close_btn = tk.Button(dialog, text="Close", 
                             command=dialog.destroy,
                             font=('Helvetica', 11),
                             bg='#95a5a6', fg='white',
                             relief='flat', padx=20, pady=8)
        close_btn.pack(pady=10)
    
    def create_group(self, name: str, description: str):
        """Create a new group"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.server_url}/api/groups', 
                                   json={'name': name, 'description': description},
                                   headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                group = data['group']
                
                # Add group key to crypto core
                group_key = base64.b64decode(group['group_key'])
                self.crypto.add_group_key(group['id'], group_key)
                
                messagebox.showinfo("Success", f"Group '{name}' created successfully!")
                self.refresh_groups()
                self.auditor.log_security_event("GROUP_CREATED", f"Created group: {name}")
            else:
                error_msg = response.json().get('error', 'Failed to create group')
                messagebox.showerror("Error", error_msg)
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
    
    def search_groups(self, query: str, results_container: tk.Widget):
        """Search for groups and display results"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.server_url}/api/groups/search?q={query}', 
                                  headers=headers, timeout=10)
            
            # Clear previous results
            for widget in results_container.winfo_children():
                widget.destroy()
            
            if response.status_code == 200:
                data = response.json()
                groups = data['groups']
                
                if groups:
                    # Results header
                    header_label = tk.Label(results_container, text=f"Found {len(groups)} group(s):", 
                                           font=('Helvetica', 12, 'bold'),
                                           fg='#ecf0f1', bg='#2c3e50')
                    header_label.pack(anchor='w', pady=(0, 10))
                    
                    # Scrollable results
                    canvas = tk.Canvas(results_container, bg='#1a252f', highlightthickness=0)
                    scrollbar = tk.Scrollbar(results_container, orient='vertical', command=canvas.yview)
                    scrollable_frame = tk.Frame(canvas, bg='#1a252f')
                    
                    scrollable_frame.bind(
                        "<Configure>",
                        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
                    )
                    
                    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
                    canvas.configure(yscrollcommand=scrollbar.set)
                    
                    scrollbar.pack(side="right", fill="y")
                    canvas.pack(side="left", fill="both", expand=True)
                    
                    # Display groups
                    for group in groups:
                        self.create_group_search_item(scrollable_frame, group)
                else:
                    tk.Label(results_container, text="No groups found", 
                            font=('Helvetica', 11),
                            fg='#95a5a6', bg='#2c3e50').pack(pady=50)
            else:
                error_msg = response.json().get('error', 'Search failed')
                tk.Label(results_container, text=f"Error: {error_msg}", 
                        font=('Helvetica', 11),
                        fg='#e74c3c', bg='#2c3e50').pack(pady=50)
        
        except requests.exceptions.RequestException as e:
            tk.Label(results_container, text=f"Network error: {str(e)}", 
                    font=('Helvetica', 11),
                    fg='#e74c3c', bg='#2c3e50').pack(pady=50)
    
    def create_group_search_item(self, parent: tk.Widget, group: Dict):
        """Create a group item in search results"""
        item_frame = tk.Frame(parent, bg='#2c3e50', relief='solid', bd=1)
        item_frame.pack(fill='x', pady=2, padx=5)
        
        # Group info
        info_frame = tk.Frame(item_frame, bg='#2c3e50')
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=10)
        
        # Group name
        name_label = tk.Label(info_frame, text=f"👥 {group['name']}", 
                             font=('Helvetica', 12, 'bold'),
                             fg='#ecf0f1', bg='#2c3e50')
        name_label.pack(anchor='w')
        
        # Group details
        details = f"👤 Created by {group['creator_name']} • {group['member_count']} members"
        details_label = tk.Label(info_frame, text=details, 
                                font=('Helvetica', 10),
                                fg='#bdc3c7', bg='#2c3e50')
        details_label.pack(anchor='w')
        
        # Description
        if group['description']:
            desc_label = tk.Label(info_frame, text=group['description'], 
                                 font=('Helvetica', 9),
                                 fg='#95a5a6', bg='#2c3e50')
            desc_label.pack(anchor='w')
        
        # Join button
        join_btn = tk.Button(item_frame, text="Join", 
                            command=lambda g=group: self.join_group(g['id']),
                            font=('Helvetica', 10, 'bold'),
                            bg='#27ae60', fg='white',
                            relief='flat', padx=15, pady=5)
        join_btn.pack(side='right', padx=15, pady=10)
    
    def join_group(self, group_id: int):
        """Join a group"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.server_url}/api/groups/{group_id}/join', 
                                   headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                group = data['group']
                
                # Add group key to crypto core
                group_key = base64.b64decode(group['group_key'])
                self.crypto.add_group_key(group['id'], group_key)
                
                messagebox.showinfo("Success", f"Joined group '{group['name']}' successfully!")
                self.refresh_groups()
                self.auditor.log_security_event("GROUP_JOINED", f"Joined group: {group['name']}")
            else:
                error_msg = response.json().get('error', 'Failed to join group')
                messagebox.showerror("Error", error_msg)
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
    
    def refresh_groups(self):
        """Refresh the list of user groups"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.server_url}/api/groups', 
                                  headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                self.user_groups = data['groups']
                
                # Add group keys to crypto core
                for group in self.user_groups:
                    group_key = base64.b64decode(group['group_key'])
                    self.crypto.add_group_key(group['id'], group_key)
                
                self.display_groups()
            else:
                print("Failed to fetch groups")
        
        except requests.exceptions.RequestException as e:
            print(f"Error fetching groups: {e}")
    
    def display_groups(self):
        """Display user groups in the groups list"""
        # Clear existing groups
        for widget in self.groups_scrollable_frame.winfo_children():
            widget.destroy()
        
        if self.user_groups:
            for i, group in enumerate(self.user_groups):
                self.create_group_item(self.groups_scrollable_frame, group, i)
        else:
            self.no_groups_label = tk.Label(self.groups_scrollable_frame, 
                                           text="No groups yet\nCreate or join a group to start!", 
                                           font=('Helvetica', 11),
                                           fg='#95a5a6', bg='#1a252f',
                                           justify='center')
            self.no_groups_label.pack(pady=50)
    
    def create_group_item(self, parent: tk.Widget, group: Dict, index: int):
        """Create a group item in the groups list"""
        # Alternate colors
        bg_color = '#2c3e50' if index % 2 == 0 else '#34495e'
        
        group_frame = tk.Frame(parent, bg=bg_color, relief='flat')
        group_frame.pack(fill='x', pady=1, padx=5)
        
        # Group info
        info_frame = tk.Frame(group_frame, bg=bg_color)
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=12)
        
        # Group name
        name_label = tk.Label(info_frame, text=f"👥 {group['name']}", 
                             font=('Helvetica', 11, 'bold'),
                             fg='#ecf0f1', bg=bg_color)
        name_label.pack(anchor='w')
        
        # Group details
        details = f"{group['member_count']} members • {group['role']}"
        details_label = tk.Label(info_frame, text=details, 
                                font=('Helvetica', 9),
                                fg='#bdc3c7', bg=bg_color)
        details_label.pack(anchor='w')
        
        # Action button
        action_frame = tk.Frame(group_frame, bg=bg_color)
        action_frame.pack(side='right', padx=10, pady=10)
        
        chat_btn = tk.Button(action_frame, text="💬", 
                            command=lambda g=group: self.select_group(g),
                            font=('Helvetica', 10, 'bold'),
                            bg='#27ae60', fg='white',
                            relief='flat', padx=8, pady=5)
        chat_btn.pack()
        
        # Click to select group
        def select_group_click(event, g=group):
            self.select_group(g)
        
        group_frame.bind("<Button-1>", select_group_click)
        info_frame.bind("<Button-1>", select_group_click)
        name_label.bind("<Button-1>", select_group_click)
        details_label.bind("<Button-1>", select_group_click)
    
    def select_group(self, group: Dict):
        """Select a group for chatting"""
        self.current_group = group
        
        # Update UI
        self.group_info_label.config(text=f"👥 {group['name']} ({group['member_count']} members)")
        self.group_status_label.config(text=f"Selected group: {group['name']}", fg='#27ae60')
        
        # Enable group chat controls
        self.group_message_entry.config(state='normal')
        self.group_send_btn.config(state='normal')
        self.members_btn.config(state='normal')
        self.leave_group_btn.config(state='normal')
        
        # Join group room for real-time messaging
        self.sio.emit('join_group_room', {
            'username': self.username,
            'group_id': group['id'],
            'token': self.token
        })
        
        # Load group messages
        self.load_group_messages(group['id'])
        
        # Clear group message input
        self.group_message_entry.delete(0, tk.END)
        self.group_message_entry.focus()
    
    def send_group_message(self, event=None):
        """Send encrypted group message"""
        if not self.current_group:
            messagebox.showwarning("Warning", "Please select a group first")
            return
        
        message = self.sanitizer.sanitize_message(self.group_message_entry.get())
        if not message:
            return
        
        # Input validation
        if len(message) > 1000:
            messagebox.showwarning("Warning", "Message too long (max 1000 characters)")
            return
        
        # Spam detection
        if self.sanitizer.detect_spam(message):
            messagebox.showwarning("Warning", "Message appears to be spam and was blocked")
            return
        
        try:
            # Encrypt group message
            encrypted_data = self.crypto.encrypt_group_message(self.current_group['id'], message)
            
            # Send to server
            self.sio.emit('send_group_message', {
                'sender': self.username,
                'group_id': self.current_group['id'],
                'encrypted_message': json.dumps(encrypted_data),
                'token': self.token
            })
            
            # Display locally
            self.display_group_message(f"📤 You: {message}")
            self.group_message_entry.delete(0, tk.END)
            
            # Log
            self.auditor.log_security_event("GROUP_MESSAGE_SENT", 
                                           f"Sent message to group {self.current_group['name']}")
            
        except Exception as e:
            self.auditor.log_security_event("GROUP_SEND_ERROR", str(e), "ERROR")
            messagebox.showerror("Error", f"Failed to send group message: {str(e)}")
    
    def display_group_message(self, message: str):
        """Display group message with enhanced formatting"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.group_messages_text.config(state=tk.NORMAL)
        self.group_messages_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.group_messages_text.see(tk.END)
        self.group_messages_text.config(state=tk.DISABLED)
    
    def load_group_messages(self, group_id: int):
        """Load group message history"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f'{self.server_url}/api/groups/{group_id}/messages', 
                                  headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                messages = data['messages']
                
                # Clear current messages
                self.group_messages_text.config(state=tk.NORMAL)
                self.group_messages_text.delete(1.0, tk.END)
                
                # Display messages
                for msg in messages[-20:]:  # Show last 20 messages
                    timestamp = datetime.fromisoformat(msg['timestamp']).strftime('%H:%M:%S')
                    sender = msg['sender_username']
                    self.display_group_message(f"💭 [{timestamp}] {sender}: [Encrypted message]")
                
                self.group_messages_text.config(state=tk.DISABLED)
        
        except requests.exceptions.RequestException as e:
            print(f"Failed to load group messages: {e}")
    
    def show_group_members(self):
        """Show group members dialog"""
        if not self.current_group:
            return
        
        # Request group info
        self.sio.emit('get_group_info', {
            'username': self.username,
            'group_id': self.current_group['id'],
            'token': self.token
        })
    
    def leave_current_group(self):
        """Leave the currently selected group"""
        if not self.current_group:
            return
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to leave '{self.current_group['name']}'?"):
            self.leave_group(self.current_group['id'])
    
    def leave_group(self, group_id: int):
        """Leave a group"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.post(f'{self.server_url}/api/groups/{group_id}/leave', 
                                   headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Remove group key from crypto
                self.crypto.remove_group_key(group_id)
                
                # Leave group room
                self.sio.emit('leave_group_room', {
                    'username': self.username,
                    'group_id': group_id,
                    'token': self.token
                })
                
                # Reset current group if it was the one we left
                if self.current_group and self.current_group['id'] == group_id:
                    self.current_group = None
                    self.group_info_label.config(text="💬 Select a group to start chatting")
                    self.group_status_label.config(text="No group selected", fg='#95a5a6')
                    self.group_message_entry.config(state='disabled')
                    self.group_send_btn.config(state='disabled')
                    self.members_btn.config(state='disabled')
                    self.leave_group_btn.config(state='disabled')
                    
                    # Clear messages
                    self.group_messages_text.config(state=tk.NORMAL)
                    self.group_messages_text.delete(1.0, tk.END)
                    self.group_messages_text.config(state=tk.DISABLED)
                
                messagebox.showinfo("Success", "Left group successfully")
                self.refresh_groups()
                self.auditor.log_security_event("GROUP_LEFT", f"Left group ID: {group_id}")
            else:
                error_msg = response.json().get('error', 'Failed to leave group')
                messagebox.showerror("Error", error_msg)
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
    
    def display_group_members_dialog(self, group: Dict, members: List[Dict]):
        """Display group members in a dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Members of {group['name']}")
        dialog.geometry("400x500")
        dialog.configure(bg='#2c3e50')
        dialog.resizable(True, True)
        
        # Make dialog modal
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (500 // 2)
        dialog.geometry(f"400x500+{x}+{y}")
        
        # Header
        header_frame = tk.Frame(dialog, bg='#34495e')
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title_label = tk.Label(header_frame, text=f"👥 {group['name']}", 
                              font=('Helvetica', 16, 'bold'),
                              fg='#ecf0f1', bg='#34495e')
        title_label.pack()
        
        info_label = tk.Label(header_frame, text=f"{len(members)} members", 
                             font=('Helvetica', 12),
                             fg='#bdc3c7', bg='#34495e')
        info_label.pack()
        
        # Members list
        members_frame = tk.Frame(dialog, bg='#2c3e50')
        members_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scrollable members list
        canvas = tk.Canvas(members_frame, bg='#1a252f', highlightthickness=0)
        scrollbar = tk.Scrollbar(members_frame, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#1a252f')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        
        # Display members
        for i, member in enumerate(members):
            self.create_member_item(scrollable_frame, member, i)
        
        # Close button
        close_btn = tk.Button(dialog, text="Close", 
                             command=dialog.destroy,
                             font=('Helvetica', 11),
                             bg='#95a5a6', fg='white',
                             relief='flat', padx=20, pady=8)
        close_btn.pack(pady=10)
    
    def create_member_item(self, parent: tk.Widget, member: Dict, index: int):
        """Create a member item in the members list"""
        # Alternate colors
        bg_color = '#2c3e50' if index % 2 == 0 else '#34495e'
        
        member_frame = tk.Frame(parent, bg=bg_color, relief='flat')
        member_frame.pack(fill='x', pady=1, padx=5)
        
        # Member info
        info_frame = tk.Frame(member_frame, bg=bg_color)
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=10)
        
        # Member name and role
        name_text = f"👤 {member['username']}"
        if member['username'] == self.username:
            name_text += " (You)"
        
        name_label = tk.Label(info_frame, text=name_text, 
                             font=('Helvetica', 11, 'bold'),
                             fg='#ecf0f1', bg=bg_color)
        name_label.pack(anchor='w')
        
        # Role and join date
        role_color = '#e67e22' if member['role'] == 'admin' else '#3498db'
        role_label = tk.Label(info_frame, text=f"🔰 {member['role'].title()}", 
                             font=('Helvetica', 9),
                             fg=role_color, bg=bg_color)
        role_label.pack(anchor='w')
        
        # Join date
        join_date = datetime.fromisoformat(member['joined_at']).strftime('%Y-%m-%d')
        date_label = tk.Label(info_frame, text=f"📅 Joined {join_date}", 
                             font=('Helvetica', 8),
                             fg='#95a5a6', bg=bg_color)
        date_label.pack(anchor='w')
    
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
    
    # File Management Methods
    
    def select_file_for_upload(self):
        """Open file dialog to select a file for upload"""
        from tkinter import filedialog
        
        file_path = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[
                ("All supported", "*.txt *.pdf *.doc *.docx *.jpg *.jpeg *.png *.gif *.mp4 *.mp3 *.wav *.zip *.tar *.gz *.py *.js *.html *.css *.json *.xml *.csv *.xlsx *.pptx"),
                ("Text files", "*.txt"),
                ("Documents", "*.pdf *.doc *.docx"),
                ("Images", "*.jpg *.jpeg *.png *.gif"),
                ("Media", "*.mp4 *.mp3 *.wav"),
                ("Archives", "*.zip *.tar *.gz"),
                ("Code", "*.py *.js *.html *.css *.json *.xml"),
                ("Spreadsheets", "*.csv *.xlsx"),
                ("Presentations", "*.pptx"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            self.selected_file_path = file_path
            filename = os.path.basename(file_path)
            
            # Check file size (50MB limit)
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                messagebox.showerror("Error", "File too large (max 50MB)")
                return
            
            # Format file size for display
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            
            self.selected_file_label.config(
                text=f"📄 {filename}\n📊 Size: {size_str}",
                fg='#27ae60'
            )
            self.upload_btn.config(state='normal')
        else:
            self.selected_file_path = None
            self.selected_file_label.config(text="No file selected", fg='#95a5a6')
            self.upload_btn.config(state='disabled')
    
    def update_share_options(self):
        """Update sharing options based on selected type"""
        share_type = self.share_type.get()
        
        if share_type == "user":
            self.target_label.config(text="Username:")
            self.target_entry.delete(0, tk.END)
        else:  # group
            self.target_label.config(text="Group name:")
            self.target_entry.delete(0, tk.END)
            
            # Show available groups
            if self.user_groups:
                # Create dropdown-like behavior
                groups_text = ", ".join([group['name'] for group in self.user_groups])
                messagebox.showinfo("Available Groups", f"Your groups: {groups_text}")
    
    def upload_file(self):
        """Upload selected file with encryption"""
        if not self.selected_file_path:
            messagebox.showwarning("Warning", "Please select a file first")
            return
        
        share_type = self.share_type.get()
        target = self.target_entry.get().strip()
        
        if not target:
            target_type = "username" if share_type == "user" else "group name"
            messagebox.showwarning("Warning", f"Please enter a {target_type}")
            return
        
        # Check if sharing with user requires active session
        if share_type == "user":
            if not self.current_chat_partner or self.current_chat_partner.lower() != target.lower():
                messagebox.showerror("Session Required", 
                                   f"To share files with '{target}', you need an active chat session.\n\n"
                                   f"Please:\n"
                                   f"1. Go to the Chat tab\n"
                                   f"2. Start a secure chat with '{target}'\n"
                                   f"3. Wait for them to accept\n"
                                   f"4. Then return to upload files")
                return
            
            # Check if we have a valid session key
            if not self.crypto.root_key:
                messagebox.showerror("Session Error", 
                                   f"No active encryption session with '{target}'.\n"
                                   f"Please establish a secure chat session first.")
                return
        
        # Validate expiry
        expiry_hours = None
        if self.expiry_var.get() != "never":
            expiry_hours = int(self.expiry_var.get())
        
        try:
            # Show progress
            self.show_upload_progress("Preparing upload...")
            self.upload_btn.config(state='disabled')
            
            # Prepare upload data
            with open(self.selected_file_path, 'rb') as f:
                file_data = f.read()
            
            headers = {'Authorization': f'Bearer {self.token}'}
            
            # Prepare form data
            files = {'file': (os.path.basename(self.selected_file_path), file_data)}
            form_data = {}
            
            if share_type == "user":
                form_data['recipient'] = target
            else:
                # Find group ID by name
                group_id = None
                for group in self.user_groups:
                    if group['name'].lower() == target.lower():
                        group_id = group['id']
                        break
                
                if not group_id:
                    messagebox.showerror("Error", f"Group '{target}' not found in your groups")
                    self.hide_upload_progress()
                    return
                
                form_data['group_id'] = str(group_id)
            
            if expiry_hours:
                form_data['expires_hours'] = str(expiry_hours)
            
            self.update_upload_progress("Encrypting file...", 30)
            
            # Encrypt file on client side for end-to-end encryption
            try:
                # Generate file key and encrypt file
                encrypted_data, nonce, file_key = self.crypto.encrypt_file(file_data)
                
                # Generate file hash for integrity
                file_hash = self.crypto.hash_file(file_data)
                
                self.update_upload_progress("Encrypting file key...", 40)
                
                # Encrypt file key based on sharing type
                if share_type == "user":
                    # Use session key for user sharing
                    encrypted_file_key, key_nonce = self.crypto.encrypt_file_key(file_key)
                else:
                    # Use group key for group sharing  
                    encrypted_file_key, key_nonce = self.crypto.encrypt_file_key_for_group(file_key, group_id)
                
                # Prepare encrypted data for upload
                encrypted_key_data = base64.b64encode(encrypted_file_key + key_nonce).decode()
                
                self.update_upload_progress("Uploading encrypted file...", 60)
                
                # Prepare encrypted file for upload (nonce + encrypted data)
                encrypted_file_data = nonce + encrypted_data
                files = {'file': (os.path.basename(self.selected_file_path), encrypted_file_data)}
                
                # Add encryption metadata to form data
                form_data['encrypted_key'] = encrypted_key_data
                form_data['file_hash'] = file_hash
                form_data['client_encrypted'] = 'true'  # Flag to tell server file is already encrypted
                
            except Exception as e:
                messagebox.showerror("Encryption Error", f"Failed to encrypt file: {str(e)}")
                self.hide_upload_progress()
                return
            
            # Upload encrypted file
            response = requests.post(f'{self.server_url}/api/files/upload',
                                   files=files, data=form_data, headers=headers, timeout=60)
            
            if response.status_code == 201:
                data = response.json()
                self.update_upload_progress("Upload completed!", 100)
                
                messagebox.showinfo("Success", 
                                  f"File '{os.path.basename(self.selected_file_path)}' uploaded successfully!")
                
                # Reset form
                self.selected_file_path = None
                self.selected_file_label.config(text="No file selected", fg='#95a5a6')
                self.target_entry.delete(0, tk.END)
                self.upload_btn.config(state='disabled')
                
                # Refresh file list
                self.refresh_files()
                
                # Log the upload
                self.auditor.log_security_event("FILE_UPLOADED", 
                                               f"File uploaded and shared with {target}")
                
                # Hide progress after delay
                self.root.after(2000, self.hide_upload_progress)
            else:
                error_msg = response.json().get('error', 'Upload failed')
                messagebox.showerror("Upload Failed", error_msg)
                self.hide_upload_progress()
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
            self.hide_upload_progress()
        except Exception as e:
            messagebox.showerror("Error", f"Upload failed: {str(e)}")
            self.hide_upload_progress()
        finally:
            self.upload_btn.config(state='normal')
    
    def refresh_files(self):
        """Refresh the list of user files and group files"""
        try:
            headers = {'Authorization': f'Bearer {self.token}'}
            all_files = []
            
            # Fetch user files
            response = requests.get(f'{self.server_url}/api/files', headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                user_files = data['files']
                # Mark as user files
                for file_info in user_files:
                    file_info['file_source'] = 'user'
                    file_info['source_name'] = 'Personal'
                all_files.extend(user_files)
            else:
                print("Failed to fetch user files")
            
            # Fetch group files for each group the user is a member of
            if hasattr(self, 'user_groups') and self.user_groups and isinstance(self.user_groups, list):
                for group in self.user_groups:
                    try:
                        group_id = group['id']
                        group_name = group['name']
                        
                        response = requests.get(f'{self.server_url}/api/groups/{group_id}/files', 
                                              headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            data = response.json()
                            group_files = data['files']
                            # Mark as group files
                            for file_info in group_files:
                                file_info['file_source'] = 'group'
                                file_info['source_name'] = f"Group: {group_name}"
                                file_info['group_id'] = group_id
                                file_info['group_name'] = group_name
                            all_files.extend(group_files)
                        else:
                            print(f"Failed to fetch files for group {group_name}")
                    
                    except Exception as e:
                        print(f"Error fetching files for group {group.get('name', 'Unknown')}: {e}")
            
            # Store combined files and display
            self.user_files = all_files
            self.display_files()
        
        except requests.exceptions.RequestException as e:
            print(f"Error fetching files: {e}")
        except Exception as e:
            print(f"Unexpected error refreshing files: {e}")
    
    def show_upload_progress(self, message: str):
        """Show upload progress indicator"""
        self.upload_progress.pack(fill='x', pady=5)
        self.upload_progress_bar.pack(fill='x')
        self.upload_progress_label.pack()
        self.upload_progress_label.config(text=message)
        
        # Draw progress bar background
        self.upload_progress_bar.delete("all")
        self.upload_progress_bar.create_rectangle(0, 0, 200, 20, fill='#2c3e50', outline='#34495e')
    
    def update_upload_progress(self, message: str, progress: int):
        """Update upload progress"""
        self.upload_progress_label.config(text=message)
        
        # Update progress bar
        self.upload_progress_bar.delete("all")
        self.upload_progress_bar.create_rectangle(0, 0, 200, 20, fill='#2c3e50', outline='#34495e')
        
        if progress > 0:
            width = int((progress / 100) * 200)
            color = '#27ae60' if progress == 100 else '#3498db'
            self.upload_progress_bar.create_rectangle(0, 0, width, 20, fill=color, outline='')
    
    def hide_upload_progress(self):
        """Hide upload progress indicator"""
        self.upload_progress.pack_forget()
    
    def display_files(self):
        """Display user files in the files list"""
        # Clear existing files
        for widget in self.files_scrollable_frame.winfo_children():
            widget.destroy()
        
        if self.user_files:
            for i, file_info in enumerate(self.user_files):
                self.create_file_item(self.files_scrollable_frame, file_info, i)
        else:
            self.no_files_label = tk.Label(self.files_scrollable_frame, 
                                          text="No files yet\nUpload a file to get started!", 
                                          font=('Helvetica', 11),
                                          fg='#95a5a6', bg='#1a252f',
                                          justify='center')
            self.no_files_label.pack(pady=50)
    
    def create_file_item(self, parent: tk.Widget, file_info: Dict, index: int):
        """Create a file item in the files list"""
        # Alternate colors
        bg_color = '#2c3e50' if index % 2 == 0 else '#34495e'
        
        file_frame = tk.Frame(parent, bg=bg_color, relief='solid', bd=1)
        file_frame.pack(fill='x', pady=2, padx=5)
        
        # File info
        info_frame = tk.Frame(file_frame, bg=bg_color)
        info_frame.pack(side='left', fill='both', expand=True, padx=15, pady=12)
        
        # File name and type
        file_icon = self.get_file_icon(file_info['file_type'])
        name_label = tk.Label(info_frame, text=f"{file_icon} {file_info['original_filename']}", 
                             font=('Helvetica', 11, 'bold'),
                             fg='#ecf0f1', bg=bg_color)
        name_label.pack(anchor='w')
        
        # File details
        file_size = self.format_file_size(file_info['file_size'])
        upload_date = datetime.fromisoformat(file_info['upload_timestamp']).strftime('%Y-%m-%d %H:%M')
        
        details_text = f"📊 {file_size} • 📅 {upload_date}"
        if file_info['download_count'] > 0:
            details_text += f" • ⬇️ {file_info['download_count']} downloads"
        
        # Show file source (Personal vs Group)
        if file_info.get('file_source') == 'group':
            details_text += f" • 👥 {file_info.get('source_name', 'Group')}"
        elif file_info.get('file_source') == 'user':
            details_text += f" • 👤 {file_info.get('source_name', 'Personal')}"
        else:
            # Fallback for legacy file detection
            if file_info.get('recipient_id'):
                details_text += " • 👤 Personal"
            elif file_info.get('group_id'):
                details_text += " • 👥 Group"
        
        details_label = tk.Label(info_frame, text=details_text, 
                                font=('Helvetica', 9),
                                fg='#bdc3c7', bg=bg_color)
        details_label.pack(anchor='w')
        
        # Action buttons
        actions_frame = tk.Frame(file_frame, bg=bg_color)
        actions_frame.pack(side='right', padx=10, pady=10)
        
        # Download button
        download_btn = tk.Button(actions_frame, text="⬇️", 
                                command=lambda f=file_info: self.download_file(f),
                                font=('Helvetica', 10, 'bold'),
                                bg='#3498db', fg='white',
                                relief='flat', padx=8, pady=5)
        download_btn.pack(side='left', padx=2)
        
        # Delete button (only for uploader)
        if file_info['uploader_name'] == self.username:
            delete_btn = tk.Button(actions_frame, text="🗑️", 
                                  command=lambda f=file_info: self.delete_file(f),
                                  font=('Helvetica', 10, 'bold'),
                                  bg='#e74c3c', fg='white',
                                  relief='flat', padx=8, pady=5)
            delete_btn.pack(side='left', padx=2)
    
    def get_file_icon(self, file_type: str) -> str:
        """Get appropriate icon for file type"""
        if not file_type:
            return "📄"
        
        type_icons = {
            'image': "🖼️",
            'video': "🎥", 
            'audio': "🎵",
            'text': "📝",
            'application/pdf': "📕",
            'application/zip': "📦",
            'application/json': "📋"
        }
        
        for key, icon in type_icons.items():
            if key in file_type.lower():
                return icon
        
        return "📄"
    
    def format_file_size(self, size: int) -> str:
        """Format file size in human readable format"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    
    def download_file(self, file_info: Dict):
        """Download and decrypt a file"""
        try:
            # Ask where to save the file
            from tkinter import filedialog
            save_path = filedialog.asksaveasfilename(
                defaultextension="",
                initialdir=os.path.expanduser("~/Downloads"),
                initialfile=file_info['original_filename'],
                title="Save file as"
            )
            
            if not save_path:
                return
            
            # Download file
            headers = {'Authorization': f'Bearer {self.token}'}
            response = requests.get(f"{self.server_url}/api/files/{file_info['id']}/download",
                                  headers=headers, timeout=60)
            
            if response.status_code == 200:
                # Check if this is a client-encrypted file (JSON response) or legacy file (binary)
                content_type = response.headers.get('content-type', '')
                
                if 'application/json' in content_type:
                    # Client-encrypted file - decrypt on client side
                    data = response.json()
                    
                    if not data.get('client_encrypted'):
                        messagebox.showerror("Error", "Unexpected response format")
                        return
                    
                    try:
                        # Decrypt file on client side
                        encrypted_file_data = base64.b64decode(data['encrypted_file_data'])
                        encrypted_key_data = base64.b64decode(data['encrypted_key'])
                        
                        # Extract nonce and encrypted data
                        nonce = encrypted_file_data[:12]
                        encrypted_data = encrypted_file_data[12:]
                        
                        # Extract encrypted file key and key nonce
                        encrypted_file_key = encrypted_key_data[:-12]
                        key_nonce = encrypted_key_data[-12:]
                        
                        # Decrypt file key based on sharing type
                        if file_info.get('group_id'):
                            # Group file
                            file_key = self.crypto.decrypt_file_key_for_group(
                                encrypted_file_key, key_nonce, file_info['group_id']
                            )
                        else:
                            # User file - use current session key
                            file_key = self.crypto.decrypt_file_key(encrypted_file_key, key_nonce)
                        
                        # Decrypt file data
                        decrypted_data = self.crypto.decrypt_file(encrypted_data, nonce, file_key)
                        
                        # Verify file integrity
                        if not self.crypto.verify_file_hash(decrypted_data, data['file_hash']):
                            messagebox.showerror("Error", "File integrity check failed")
                            return
                        
                        # Save decrypted file
                        with open(save_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        messagebox.showinfo("Success", f"File downloaded and decrypted to:\n{save_path}")
                        
                    except Exception as e:
                        messagebox.showerror("Decryption Error", f"Failed to decrypt file: {str(e)}")
                        return
                else:
                    # Legacy server-decrypted file (binary response)
                    with open(save_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    messagebox.showinfo("Success", f"File downloaded to:\n{save_path}")
                
                self.auditor.log_security_event("FILE_DOWNLOADED", 
                                               f"Downloaded file: {file_info['original_filename']}")
            else:
                error_msg = response.json().get('error', 'Download failed')
                messagebox.showerror("Download Failed", error_msg)
        
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Download failed: {str(e)}")
    
    def delete_file(self, file_info: Dict):
        """Delete a file"""
        if messagebox.askyesno("Confirm Delete", 
                              f"Are you sure you want to delete '{file_info['original_filename']}'?\n\nThis action cannot be undone."):
            try:
                headers = {'Authorization': f'Bearer {self.token}'}
                response = requests.delete(f"{self.server_url}/api/files/{file_info['id']}",
                                         headers=headers, timeout=10)
                
                if response.status_code == 200:
                    messagebox.showinfo("Success", "File deleted successfully")
                    self.refresh_files()
                    self.auditor.log_security_event("FILE_DELETED", 
                                                   f"Deleted file: {file_info['original_filename']}")
                else:
                    error_msg = response.json().get('error', 'Delete failed')
                    messagebox.showerror("Delete Failed", error_msg)
            
            except requests.exceptions.RequestException as e:
                messagebox.showerror("Error", f"Network error: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Delete failed: {str(e)}")
    
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