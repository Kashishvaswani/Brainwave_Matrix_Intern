import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import threading

from feature_extractor import extract_features
from detector import is_phishing

class PhishingScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Scanner Tool")
        self.root.geometry("900x700")
        self.root.configure(bg="#0d1117")  # Dark bg

        # Title
        self.title_label = tk.Label(
            root,
            text="Phishing Scanner Tool",
            font=("Consolas", 28, "bold"),
            fg="#00FFFF",
            bg="#0d1117"
        )
        self.title_label.pack(pady=15)

        # Default image below title
        default_img = Image.open("default.png").resize((300, 150))
        self.default_photo = ImageTk.PhotoImage(default_img)
        self.default_img_label = tk.Label(root, image=self.default_photo, bg="#0d1117")
        self.default_img_label.pack(pady=10)

        # URL entry field
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(root, textvariable=self.url_var, font=("Consolas", 14), width=60)
        self.url_entry.pack(pady=10)
        self.url_entry.focus()

        # Scan button
        self.scan_button = ttk.Button(root, text="SCAN", command=self.start_scan)
        self.scan_button.pack(pady=10)

        # Result frame (hidden initially)
        self.result_frame = tk.Frame(root, bg="#0d1117")

        # Result text box on left
        self.result_text = tk.Text(
            self.result_frame,
            bg="#1e1e1e",
            fg="#00FFFF",
            insertbackground="#00FFFF",
            font=("Consolas", 12),
            width=70,
            height=25
        )
        self.result_text.pack(side="left", padx=15, pady=10, fill="both", expand=True)

        # Result image on right
        self.result_img_label = tk.Label(self.result_frame, bg="#0d1117")
        self.result_img_label.pack(side="right", padx=15, pady=10)

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url:
            self.show_message("Please enter a URL to scan.")
            return

        # Disable button and show scanning text
        self.scan_button.config(text="Scanning...", state="disabled")
        # Hide result area while scanning
        self.result_frame.pack_forget()

        # Run scan in separate thread so GUI stays responsive
        threading.Thread(target=self.perform_scan, args=(url,), daemon=True).start()

    def perform_scan(self, url):
        try:
            features = extract_features(url)
            phishing = is_phishing(features)

            # Prepare result text
            result_lines = ["=== URL Features ===\n"]
            for k, v in features.items():
                result_lines.append(f"{k}: {v}")
            result_lines.append("\n=== Detection Result ===")
            if phishing:
                result_lines.append("⚠️ PHISHING DETECTED!")
                image_path = "stop.png"
            else:
                result_lines.append("✅ SAFE URL.")
                image_path = "allow.png"

            # Update GUI in main thread
            self.root.after(0, self.show_results, "\n".join(result_lines), image_path)
        except Exception as e:
            self.root.after(0, self.show_message, f"Error: {str(e)}")

    def show_results(self, text, image_path):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, text)

        # Load and show image
        img = Image.open(image_path).resize((150, 150))
        photo = ImageTk.PhotoImage(img)
        self.result_img_label.config(image=photo)
        self.result_img_label.image = photo

        # Show result frame
        self.result_frame.pack(pady=10, fill="both", expand=True)

        # Reset scan button
        self.scan_button.config(text="SCAN", state="normal")

    def show_message(self, msg):
        # Show message in result box and make it visible
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, msg)
        self.result_frame.pack(pady=10, fill="both", expand=True)
        self.scan_button.config(text="SCAN", state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingScannerGUI(root)
    root.mainloop()
