import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from threading import Thread
from feature_extractor import extract_features
from detector import is_phishing

class PhishingScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Scanner Tool")
        self.root.configure(bg="#121212")

        self.title_label = tk.Label(
            root,
            text="Phishing Scanner Tool",
            font=("Consolas", 24, "bold"),
            fg="#00FFFF",
            bg="#121212"
        )
        self.title_label.pack(pady=10)

        self.default_img = Image.open("default.png").resize((250, 250))
        self.default_photo = ImageTk.PhotoImage(self.default_img)
        self.image_label = tk.Label(root, image=self.default_photo, bg="#121212")
        self.image_label.pack(pady=10)

        self.url_entry = tk.Entry(
            root,
            font=("Consolas", 14),
            width=50,
            bg="#1e1e1e",
            fg="#00FFFF",
            insertbackground="#00FFFF"
        )
        self.url_entry.pack(pady=5)

        self.scan_button = tk.Button(
            root,
            text="SCAN",
            font=("Consolas", 14, "bold"),
            fg="#00FFFF",
            bg="#1e1e1e",
            activebackground="#333",
            command=self.start_scan
        )
        self.scan_button.pack(pady=10)

        self.result_frame = tk.Frame(root, bg="#121212")

        # Result Text box only (no external title label)
        self.result_text = tk.Text(
            self.result_frame,
            bg="#1e1e1e",
            fg="#00FFFF",
            insertbackground="#00FFFF",
            font=("Consolas", 12),
            width=45,
            height=24  # slightly taller for status line
        )
        self.result_text.pack(side="left", padx=15, pady=10, fill="both", expand=True)

        self.result_img_label = tk.Label(self.result_frame, bg="#121212")
        self.result_img_label.pack(side="right", padx=20, pady=10)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL to scan.")
            return

        self.scan_button.config(text="Scanning...", state="disabled")
        self.result_frame.pack_forget()
        self.image_label.config(image=self.default_photo)
        self.image_label.image = self.default_photo
        Thread(target=self.perform_scan, args=(url,), daemon=True).start()

    def perform_scan(self, url):
        try:
            features = extract_features(url)
            phishing = is_phishing(features)

            # Prepare feature lines without zero/false/empty and no header line
            feature_lines = []
            for k, v in features.items():
                if v in [0, False, None, ""]:
                    continue
                feature_lines.append(f"{k}: {v}")

            # Status line (SAFE or PHISHING)
            status_text = "SAFE" if not phishing else "PHISHING"

            # Show results on main thread
            self.root.after(0, self.show_results, status_text, phishing, "\n".join(feature_lines), "allow.png" if not phishing else "stop.png")
        except Exception as e:
            self.root.after(0, self.show_message, f"Error: {str(e)}")

    def show_results(self, status_text, phishing, feature_text, image_path):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)

        # Insert status line with tag for color
        self.result_text.insert(tk.END, status_text + "\n\n")
        self.result_text.tag_add("status", "1.0", "1.end")
        if phishing:
            self.result_text.tag_config("status", foreground="#FF4444", font=("Consolas", 14, "bold"))
        else:
            self.result_text.tag_config("status", foreground="#44FF44", font=("Consolas", 14, "bold"))

        # Insert feature lines below
        self.result_text.insert(tk.END, feature_text)
        self.result_text.config(state=tk.DISABLED)

        img = Image.open(image_path).resize((250, 250))
        photo = ImageTk.PhotoImage(img)
        self.result_img_label.config(image=photo)
        self.result_img_label.image = photo

        self.result_frame.pack(pady=10, fill="both", expand=True)
        self.scan_button.config(text="SCAN", state="normal")

    def show_message(self, msg):
        messagebox.showerror("Error", msg)
        self.scan_button.config(text="SCAN", state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    gui = PhishingScannerGUI(root)
    root.mainloop()
