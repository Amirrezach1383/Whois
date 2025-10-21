import tkinter as tk
import socket


class WhoisApp:

    PORT = 43
    BUFFER_SIZE = 4096

    TLD = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "biz": "whois.neulevel.biz",
        "io": "whois.nic.io",
        "ir": "whois.nic.ir",
        "uk": "whois.nic.uk",
        # add more TLDs if needed
    }

    domain_data = ""

    def __init__(self, root):
        self.root = root
        self.root.title("WHOIS Lookup")
        self.root.geometry("500x300")
        self.root.resizable(False, False)

        # Set color scheme
        bg_color = "#F0F0F0"
        button_color = "#0078D7"
        text_color = "#000000"
        self.root.configure(bg=bg_color)

        # Main frame with padding
        main_frame = tk.Frame(root, bg=bg_color)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Top label
        label_top = tk.Label(
            main_frame,
            text="Please enter your domain:",
            font=("Segoe UI", 11),
            bg=bg_color,
            fg=text_color
        )
        label_top.pack(anchor='w', pady=(0, 10))

        # Entry and button frame
        entry_frame = tk.Frame(main_frame, bg=bg_color)
        entry_frame.pack(fill='x', pady=(0, 20))

        # Entry field
        self.entry_website = tk.Entry(
            entry_frame,
            font=("Segoe UI", 10),
            width=35,
            relief='solid',
            borderwidth=1
        )
        self.entry_website.pack(side='left', ipady=5)
        self.entry_website.insert(0, "Domain Name")
        self.entry_website.config(fg='gray')

        # Bind focus events for placeholder behavior
        self.entry_website.bind('<FocusIn>', self.on_entry_focus_in)
        self.entry_website.bind('<FocusOut>', self.on_entry_focus_out)

        # Confirm button
        btn_confirm = tk.Button(
            entry_frame,
            text="Confirm",
            font=("Segoe UI", 10),
            bg=button_color,
            fg='white',
            width=10,
            relief='flat',
            cursor='hand2',
            command=self.confirm_action
        )
        btn_confirm.pack(side='left', padx=(10, 0), ipady=3)

        # Important information label (for preview of WHOIS)
        self.label_preview = tk.Label(
            main_frame,
            text="",
            font=("Segoe UI", 10),
            bg=bg_color,
            fg=text_color,
            wraplength=450,
            justify='left'
        )
        self.label_preview.pack(anchor='w', pady=(0, 15))

        # More Info button
        btn_more_info = tk.Button(
            main_frame,
            text="More Info",
            font=("Segoe UI", 10),
            bg=button_color,
            fg='white',
            width=15,
            relief='flat',
            cursor='hand2',
            command=self.show_more_info
        )
        btn_more_info.pack(anchor='w', pady=(0, 10))

    def on_entry_focus_in(self, event):
        """Clear placeholder text when entry gets focus"""
        if self.entry_website.get() == "Domain Name":
            self.entry_website.delete(0, tk.END)
            self.entry_website.config(fg='black')

    def on_entry_focus_out(self, event):
        """Restore placeholder text if entry is empty"""
        if self.entry_website.get().strip() == "":
            self.entry_website.insert(0, "Domain Name")
            self.entry_website.config(fg='gray')

    def confirm_action(self):
        """Handle confirm button click"""
        website = self.entry_website.get().strip()
        # Check if placeholder text is still present or field is empty
        if not website or website.lower() == "domain name":
            self.show_error_message("Error", "Please enter a valid website name.")
            return

        # Make the WHOIS request
        result = self.whois_request(website)
        if not result:
            return

        # Show success message
        self.show_info_message("Success", f"Fetching WHOIS information for:\n{website}")

        # Display first 5 lines in label_preview
        lines = self.domain_data.splitlines()
        preview_text = "\n".join(lines[:5])
        self.label_preview.config(text=preview_text)

    def whois_request(self, domain: str):
        """Make the request to the appropriate WHOIS server"""
        tld = domain.split('.')[-1].lower()  # Extract TLD properly
        whois_server = self.TLD.get(tld)
        if not whois_server:
            self.show_error_message("Error", f"TLD '{tld}' not supported.")
            return False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        domain_data = []
        try:
            s.settimeout(10)
            s.connect((whois_server, self.PORT))
            s.sendall((domain + "\r\n").encode("utf-8"))
            while True:
                try:
                    data = s.recv(self.BUFFER_SIZE)
                    if not data:
                        break
                    domain_data.append(data)
                except socket.timeout:
                    break
        except (socket.timeout, ConnectionRefusedError) as e:
            self.show_error_message("Connection Error", str(e))
            return False
        finally:
            s.close()

        self.fill_the_domain_data(domain_data)
        return True

    def fill_the_domain_data(self, domain_data: list):
        """Convert list of bytes to string and store in self.domain_data"""
        if domain_data:
            self.domain_data = b"".join(domain_data).decode("utf-8", errors="replace")
        else:
            self.domain_data = ""

    def show_more_info(self):
        """Handle More Info button click: display full WHOIS in a scrollable window"""
        info_text = self.domain_data if self.domain_data else (
            "WHOIS Lookup Tool\n\n"
            "This application allows you to query WHOIS information "
            "for domain names. WHOIS is a protocol used to query databases "
            "that store registered users or assignees of internet resources.\n\n"
            "Simply enter a domain name (e.g., example.com) and click Confirm "
            "to retrieve registration details."
        )

        # Create a new top-level window
        info_window = tk.Toplevel(self.root)
        info_window.title("More Information")
        info_window.geometry("600x400")
        info_window.configure(bg="#F0F0F0")
        info_window.transient(self.root)
        info_window.grab_set()

        # Center the window
        info_window.update_idletasks()
        x = (info_window.winfo_screenwidth() // 2) - (info_window.winfo_width() // 2)
        y = (info_window.winfo_screenheight() // 2) - (info_window.winfo_height() // 2)
        info_window.geometry(f"+{x}+{y}")

        # Create a frame for text and scrollbar
        frame = tk.Frame(info_window, bg="#F0F0F0")
        frame.pack(expand=True, fill='both', padx=10, pady=10)

        # Add Text widget
        text_widget = tk.Text(frame, wrap='word', font=("Segoe UI", 10))
        text_widget.insert('1.0', info_text)
        text_widget.config(state='disabled')  # make it read-only
        text_widget.pack(side='left', expand=True, fill='both')

        # Add Scrollbar
        scrollbar = tk.Scrollbar(frame, command=text_widget.yview)
        scrollbar.pack(side='right', fill='y')
        text_widget.config(yscrollcommand=scrollbar.set)

    def show_error_message(self, title, message):
        """Display custom error message with matching color theme"""
        error_window = tk.Toplevel(self.root)
        error_window.title(title)
        error_window.geometry("300x120")
        error_window.resizable(False, False)
        error_window.configure(bg="#F0F0F0")

        # Center the error window
        error_window.transient(self.root)
        error_window.grab_set()

        # Message label
        label = tk.Label(
            error_window,
            text=message,
            font=("Segoe UI", 10),
            bg="#F0F0F0",
            fg="#000000",
            wraplength=260
        )
        label.pack(pady=(20, 15))

        # OK button
        btn_ok = tk.Button(
            error_window,
            text="OK",
            font=("Segoe UI", 10),
            bg="#0078D7",
            fg="white",
            width=10,
            relief='flat',
            cursor='hand2',
            command=error_window.destroy
        )
        btn_ok.pack(pady=(0, 15))

        # Center window on screen
        error_window.update_idletasks()
        x = (error_window.winfo_screenwidth() // 2) - (error_window.winfo_width() // 2)
        y = (error_window.winfo_screenheight() // 2) - (error_window.winfo_height() // 2)
        error_window.geometry(f"+{x}+{y}")

    def show_info_message(self, title, message):
        """Display custom info message with matching color theme"""
        info_window = tk.Toplevel(self.root)
        info_window.title(title)
        info_window.geometry("350x200")
        info_window.resizable(False, False)
        info_window.configure(bg="#F0F0F0")

        # Center the info window
        info_window.transient(self.root)
        info_window.grab_set()

        # Message label
        label = tk.Label(
            info_window,
            text=message,
            font=("Segoe UI", 10),
            bg="#F0F0F0",
            fg="#000000",
            wraplength=310,
            justify='left'
        )
        label.pack(pady=(20, 15), padx=20)

        # OK button
        btn_ok = tk.Button(
            info_window,
            text="OK",
            font=("Segoe UI", 10),
            bg="#0078D7",
            fg='white',
            width=10,
            relief='flat',
            cursor='hand2',
            command=info_window.destroy
        )
        btn_ok.pack(pady=(0, 15))

        # Center window on screen
        info_window.update_idletasks()
        x = (info_window.winfo_screenwidth() // 2) - (info_window.winfo_width() // 2)
        y = (info_window.winfo_screenheight() // 2) - (info_window.winfo_height() // 2)
        info_window.geometry(f"+{x}+{y}")


def main():
    root = tk.Tk()
    app = WhoisApp(root)

    # Center the main window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")

    root.mainloop()

if __name__ == "__main__":
    main()
