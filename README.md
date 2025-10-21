# Python WHOIS Lookup Tool

This project was originally found on LinkedIn as a learning resource and was implemented to gain hands-on experience in Python networking and GUI development. 
It is a simple GUI-based application for querying WHOIS information of domain names.

## Features
- Query WHOIS information for common TLDs like `.com`, `.net`, `.org`, `.ir`, etc.
- Display first few lines of domain information as a preview.
- "More Info" button opens a scrollable window showing full WHOIS data.
- Basic error handling for invalid domains or connection issues.
- GUI built with Tkinter, including placeholder text, buttons, and labels.
- Centered windows for better user experience.

## Learning Outcomes
Through this project, I have:
- Learned the basics of **socket programming** in Python and how to communicate with WHOIS servers over TCP port 43.
- Practiced **data handling and string processing**, including decoding byte streams from servers.
- Explored **Tkinter** for GUI development, including Labels, Buttons, Entry fields, Text widgets, and Scrollbars.
- Implemented **staging of data**, preview display, and detailed view using a separate scrollable window.
- Understood **domain TLDs**, how WHOIS servers respond, and fallback logic for multiple TLDs.
- Practiced error handling, input validation, and creating a more user-friendly interface.

## How to Run
1. Make sure you have Python 3 installed.
2. Run the script:
   ```bash
   python main.py
