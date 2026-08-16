#!/usr/bin/env python3

import csv
import imaplib
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk

EMAIL_RE = re.compile(r"(?i)(?:[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9-]+\.)+[a-z]{2,})")

IMAP_PROVIDER_HOSTS = {
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "live.com": "outlook.office365.com",
    "msn.com": "outlook.office365.com",
    "yahoo.com": "imap.mail.yahoo.com",
    "yahoo.de": "imap.mail.yahoo.com",
    "aol.com": "imap.aol.com",
    "gmx.de": "imap.gmx.net",
    "gmx.net": "imap.gmx.net",
    "gmx.com": "imap.gmx.net",
    "icloud.com": "imap.mail.me.com",
    "me.com": "imap.mail.me.com",
    "protonmail.com": "127.0.0.1",
    "proton.me": "127.0.0.1",
}


DEFAULT_DB = Path(__file__).with_name("target_matches.db")
DEFAULT_EXPORT = Path(__file__).with_name("target_hits.csv")
DEFAULT_TEXT_EXPORT = Path(__file__).with_name("target_hits.txt")


def normalize_email(value):
    if value is None:
        return ""
    candidate = str(value).strip().lower()
    candidate = candidate.replace(" ", "")
    return candidate


def cleanup_address(address):
    candidate = normalize_email(address)
    if not candidate or candidate.count("@") != 1:
        return ""
    local, domain = candidate.rsplit("@", 1)
    if not local or not domain or "." not in domain:
        return ""
    return candidate


def resolve_imap_host(host=None, username=None):
    if host and host.strip():
        return host.strip()

    user = (username or "").strip()
    if not user:
        return ""
    match = EMAIL_RE.search(user)
    if not match:
        return ""
    domain = match.group(0).split("@", 1)[1].lower()
    return IMAP_PROVIDER_HOSTS.get(domain, f"imap.{domain}")


def parse_email_addresses(raw_value):
    if raw_value is None:
        return []

    text = str(raw_value).strip()
    if not text:
        return []

    seen = set()
    result = []

    for name, address in getaddresses([text]):
        candidate = cleanup_address(address or name)
        if candidate and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)

    if result:
        return result

    for match in EMAIL_RE.findall(text):
        candidate = cleanup_address(match)
        if candidate and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)

    return result


def load_targets_from_csv(path):
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Target list not found: {path}")

    targets = {}
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            for key in ("email", "target_email", "mail", "address"):
                value = row.get(key)
                if value:
                    email_value = normalize_email(value)
                    if email_value:
                        targets[email_value] = {
                            "source": row.get("source") or os.path.basename(path),
                            "row": row,
                        }
                        break
    if not targets:
        raise ValueError(f"No valid email addresses found in {path}")
    return targets


def load_mailbox_export(path):
    if not path or not os.path.exists(path):
        raise FileNotFoundError(f"Mailbox export not found: {path}")

    hits = {}
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            email_value = normalize_email(row.get("email") or row.get("address") or row.get("target_email"))
            if not email_value:
                continue
            hit_date = row.get("mail_date") or row.get("date") or row.get("matched_at")
            hits[email_value] = hit_date
    return hits


def fetch_imap_addresses(host, username, password, folder="INBOX", since_days=365):
    resolved_host = resolve_imap_host(host, username)
    if not resolved_host or not username or not password:
        raise ValueError("IMAP host, username and password are required.")

    client = imaplib.IMAP4_SSL(resolved_host)
    client.login(username, password)
    client.select(folder)
    status, message_ids = client.search(None, "ALL")
    if status != "OK":
        raise RuntimeError(f"Unable to search folder {folder}: {status}")

    ids = message_ids[0].split()
    results = {}
    for message_id in ids[-500:]:
        status, payload = client.fetch(message_id, "(RFC822)")
        if status != "OK":
            continue
        for response_part in payload:
            if isinstance(response_part, tuple):
                raw_message = response_part[1]
                message = BytesParser(policy=policy.default).parsebytes(raw_message)
                header_date = message.get("Date")
                date_value = None
                if header_date:
                    try:
                        date_value = str(datetime.fromtimestamp(
                            __parse_rfc2822_timestamp(header_date), timezone.utc
                        ).isoformat())
                    except Exception:
                        date_value = header_date
                for key in ("From", "To", "Cc", "Delivered-To"):
                    for address in parse_email_addresses(message.get(key, "")):
                        results.setdefault(address, []).append(date_value or "unknown")
    client.logout()
    return results


def __parse_rfc2822_timestamp(value):
    from email.utils import parsedate_to_datetime
    return parsedate_to_datetime(value).timestamp()


def run_match(targets_path, mailbox_path=None, host=None, username=None, password=None, folder="INBOX", db_path=DEFAULT_DB, export_path=DEFAULT_EXPORT, text_export_path=DEFAULT_TEXT_EXPORT):
    if mailbox_path and os.path.exists(mailbox_path):
        mailbox_data = load_mailbox_export(mailbox_path)
    elif username and password:
        resolved_host = resolve_imap_host(host, username)
        if not resolved_host:
            raise ValueError("Could not infer a valid IMAP host from the email address. Please enter the host manually.")
        mailbox_data = fetch_imap_addresses(resolved_host, username, password, folder=folder)
    else:
        raise ValueError("Provide either a mailbox export CSV or a valid IMAP configuration.")

    targets = load_targets_from_csv(targets_path)
    matches = []
    seen = set()
    for email_value, target_meta in targets.items():
        if email_value in mailbox_data:
            if email_value in seen:
                continue
            seen.add(email_value)
            source_value = mailbox_data.get(email_value, "unknown")
            if isinstance(source_value, list):
                source_value = ", ".join(source_value)
            matches.append({
                "target_email": email_value,
                "source_list": target_meta.get("source") or "targets",
                "mailbox_value": source_value,
                "matched_at": datetime.now(timezone.utc).isoformat(),
            })

    save_matches(matches, db_path, export_path, text_export_path)
    return matches


def save_matches(matches, db_path=DEFAULT_DB, export_path=DEFAULT_EXPORT, text_export_path=DEFAULT_TEXT_EXPORT):
    db_path = Path(db_path)
    export_path = Path(export_path)
    text_export_path = Path(text_export_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    export_path.parent.mkdir(parents=True, exist_ok=True)
    text_export_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hits (
            target_email TEXT,
            source_list TEXT,
            mailbox_value TEXT,
            matched_at TEXT
        )
        """
    )
    conn.execute("DELETE FROM hits")
    conn.executemany(
        "INSERT INTO hits (target_email, source_list, mailbox_value, matched_at) VALUES (?, ?, ?, ?)",
        [
            (row["target_email"], row["source_list"], row["mailbox_value"], row["matched_at"])
            for row in matches
        ],
    )
    conn.commit()
    conn.close()

    with open(export_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["target_email", "source_list", "mailbox_value", "matched_at"])
        writer.writeheader()
        writer.writerows(matches)

    with open(text_export_path, "w", encoding="utf-8") as handle:
        if matches:
            for row in matches:
                handle.write(
                    f"target_email={row['target_email']} | source_list={row['source_list']} | "
                    f"mailbox_value={row['mailbox_value']} | matched_at={row['matched_at']}\n"
                )
        else:
            handle.write("No hits found.\n")


class TargetMatcherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Madde - Own Data Target Matcher")
        self.geometry("760x520")
        self.minsize(680, 420)

        self.targets_path = tk.StringVar(value="")
        self.mailbox_path = tk.StringVar(value="")
        self.imap_host = tk.StringVar(value="")
        self.imap_user = tk.StringVar(value="")
        self.imap_password = tk.StringVar(value="")
        self.imap_folder = tk.StringVar(value="INBOX")

        self._build_ui()

    def _build_ui(self):
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Own-data target matching: targets are checked only against explicitly authorized data.").pack(anchor="w", pady=(0, 10))

        fields = [
            ("Targets CSV", self.targets_path, "Choose target list"),
            ("Mailbox export CSV (optional)", self.mailbox_path, "Choose mailbox export"),
            ("IMAP host", self.imap_host, "mail.example.com"),
            ("IMAP user", self.imap_user, "user@example.com"),
            ("IMAP password", self.imap_password, "********"),
            ("IMAP folder", self.imap_folder, "INBOX"),
        ]

        for label_text, variable, placeholder in fields:
            frame = ttk.Frame(container)
            frame.pack(fill="x", pady=4)
            ttk.Label(frame, text=label_text, width=18, anchor="w").pack(side="left")
            entry = ttk.Entry(frame, textvariable=variable, width=52)
            entry.pack(side="left", fill="x", expand=True, padx=(8, 6))
            if "Choose" in placeholder:
                ttk.Button(frame, text="Browse", command=lambda v=variable, p=placeholder: self.choose_file(v)).pack(side="left")

        buttons = ttk.Frame(container)
        buttons.pack(fill="x", pady=10)
        ttk.Button(buttons, text="Run match", command=self.run_match).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Save demo data", command=self.save_demo_data).pack(side="left")

        self.output = tk.Text(container, height=18, wrap="word")
        self.output.pack(fill="both", expand=True)

    def choose_file(self, variable):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if path:
            variable.set(path)

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def save_demo_data(self):
        target_path = Path("demo_targets.csv")
        mailbox_path = Path("demo_mailbox.csv")
        with open(target_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["email", "source"])
            writer.writeheader()
            writer.writerows([
                {"email": "alice@example.com", "source": "own-list"},
                {"email": "bob@example.com", "source": "own-list"},
            ])
        with open(mailbox_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["email", "mail_date", "source"])
            writer.writeheader()
            writer.writerows([
                {"email": "alice@example.com", "mail_date": "2024-05-20T10:00:00+00:00", "source": "own-mailbox"},
                {"email": "charlie@example.com", "mail_date": "2024-05-21T11:00:00+00:00", "source": "own-mailbox"},
            ])
        self.log(f"Demo files saved: {target_path} and {mailbox_path}")

    def run_match(self):
        target_path = self.targets_path.get().strip()
        mailbox_path = self.mailbox_path.get().strip()
        host = self.imap_host.get().strip()
        username = self.imap_user.get().strip()
        password = self.imap_password.get().strip()
        folder = self.imap_folder.get().strip() or "INBOX"

        try:
            if not target_path:
                raise ValueError("Select a target CSV file first.")
            if mailbox_path:
                matches = run_match(target_path, mailbox_path=mailbox_path, db_path=DEFAULT_DB, export_path=DEFAULT_EXPORT)
            else:
                matches = run_match(target_path, host=host, username=username, password=password, folder=folder, db_path=DEFAULT_DB, export_path=DEFAULT_EXPORT)

            self.log(f"Matches saved: {len(matches)}")
            for row in matches:
                self.log(f"{row['target_email']} -> {row['mailbox_value']} @ {row['matched_at']}")
            messagebox.showinfo("Done", f"Found {len(matches)} matching entries and saved them to the SQLite database and CSV export.")
        except Exception as exc:  # pragma: no cover - UI feedback only
            self.log(f"ERROR: {exc}")
            messagebox.showerror("Match error", str(exc))


def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "demo":
            TargetMatcherApp().save_demo_data()
            return 0

        if command == "check":
            target_path = sys.argv[2] if len(sys.argv) > 2 else None
            mailbox_path = sys.argv[3] if len(sys.argv) > 3 else None
            if not target_path:
                print("Usage: target_matcher.py check <targets.csv> [mailbox_export.csv]", file=sys.stderr)
                return 2
            try:
                matches = run_match(target_path, mailbox_path=mailbox_path)
                print(json.dumps(matches, indent=2))
                return 0
            except Exception as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1

    app = TargetMatcherApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
