import socket
import threading
import subprocess
import logging
from email_validator import validate_email, EmailNotValidError

HOST = "0.0.0.0"
PORT = 7777

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

PROMPT = r"""
 _____ ___________ _____ 
| _ |_ _| ___ \\ / ___| 
| | | | | | | |_/ / \ `--. ___ _ ____ _____ _ __ 
| | | | | | | __/ `--. \\/ _ \\ '__\\ \ / / _ \\ '__|
\\ \_/ / | | | | /\\__/ / __/ | \ V / __/ | 
 \___/ \\_/ \\_| \\____/ \\___|_| \\_/ \\___|_| 
hack4gov

"""


def handle_client(conn, addr):
    logging.info("Connected by %s", addr)
    try:
        conn.sendall(PROMPT.encode())
        conn.sendall(b"Enter Email > ")

        data = conn.recv(4096)
        if not data:
            logging.info("No data received from %s", addr)
            return

        email = data.decode(errors="replace").strip()
        logging.info("Received input from %s: %s", addr, email)

        # Special testing command retained from original code
        if email == "REVEAL_FLAG":
            try:
                with open("flag.txt", "r") as f:
                    reply = f.read().strip()
            except Exception as e:
                reply = f"Error reading flag: {e}"
            conn.sendall(reply.encode())
            return

        # Validate email address
        try:
            validated = validate_email(email)
            safe_email = validated.email
        except EmailNotValidError as e:
            conn.sendall(f"Invalid email: {e}".encode())
            return

        # Run the CGI script (run explicitly via bash to match original behavior)
        try:
            result = subprocess.run(
                ["/bin/bash", "./generateOTP.cgi", safe_email],
                capture_output=True,
                text=True,
                timeout=10,
            )
            reply = (result.stdout or "") + (result.stderr or "")
        except subprocess.TimeoutExpired:
            reply = "Command timed out"
        except Exception as e:
            reply = f"Error running command: {e}"

        conn.sendall(reply.encode())

    except Exception as e:
        logging.exception("Error handling client %s: %s", addr, e)
    finally:
        try:
            conn.close()
        except Exception:
            pass
        logging.info("Connection closed for %s", addr)


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        logging.info("Server listening on port %s", PORT)

        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()


if __name__ == "__main__":
    run_server()
