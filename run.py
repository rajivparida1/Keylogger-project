import pystray
from PIL import Image, ImageDraw
import threading
import tkinter as tk
from gui import KeyloggerGUI
import os
import time


def create_professional_icon():
    # Create a 64x64 transparent image
    icon_size = 64
    image = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
    dc = ImageDraw.Draw(image)
    
    # Draw a modern key-shaped icon
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

def create_tray_icon():
    # Create professional icon
    image = create_professional_icon()
    
    # Create the system tray icon with improved menu
    icon = pystray.Icon(
        "keylogger",
        image,
        "Keylogger Control Panel",
        menu=pystray.Menu(
            pystray.MenuItem(
                "Show Control Panel", 
                lambda: show_gui(),
                default=True  # Makes it bold/primary action
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                "Exit", 
                lambda icon: exit_app(icon)
            )
        )
    )
    
    # Start the icon in a separate thread
    threading.Thread(target=icon.run, daemon=True).start()
    return icon

def show_gui():
    """Show the GUI window with proper window management"""
    root = tk.Tk()
    app = KeyloggerGUI(root)
    
    # Make window appear in the foreground
    root.attributes('-topmost', 1)
    root.after_idle(root.attributes, '-topmost', 0)
    
    root.mainloop()

def exit_app(icon):
    """Clean exit with proper icon cleanup"""
    if icon:
        icon.visible = False  # Hide immediately
        icon.stop()  # Stop the icon
    os._exit(0)

if __name__ == "__main__":
    try:
        tray_icon = create_tray_icon()
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        exit_app(tray_icon)