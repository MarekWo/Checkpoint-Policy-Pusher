# -*- coding: utf-8 -*-

"""
Checkpoint Policy Manager GUI

A simple graphical user interface to enable or disable Checkpoint policy
installation jobs by modifying the 'status' flag in a .conf file.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import configparser
import argparse
import os

class PolicyManagerApp:
    """A GUI application to manage policy statuses in a .conf file."""
    def __init__(self, root_window, initial_config_file=None):
        self.root = root_window
        self.root.title("Checkpoint Policy Manager")
        self.root.geometry("500x600")

        self.config = configparser.ConfigParser()
        self.config_file_path = None
        self.policy_vars = {}  # To store {section_name: (var, checkbox_widget)}

        # --- UI Elements ---

        # Top frame for file operations
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X)

        self.load_button = ttk.Button(top_frame, text="Load .conf File", command=self.load_file)
        self.load_button.pack(side=tk.LEFT, padx=(0, 10))

        self.save_button = ttk.Button(top_frame, text="Save Changes", command=self.save_file, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT)

        self.file_label = ttk.Label(top_frame, text="No file loaded.", anchor="w", foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)

        # Main frame for the policy list
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Canvas and Scrollbar for the list
        self.canvas = tk.Canvas(main_frame)
        self.scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor="w", padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        if initial_config_file:
            # Użycie 'after', aby okno główne zdążyło się narysować przed ewentualnym błędem
            self.root.after(10, lambda: self.load_file(filepath=initial_config_file))

    def load_file(self, filepath=None):
        """Opens a file dialog to select a .conf file and loads the policies."""
        if filepath is None:
            filepath = filedialog.askopenfilename(
                title="Select Configuration File",
                filetypes=(("Config files", "*.conf"), ("All files", "*.*"))
            )

        if not filepath:
            return

        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"File not found: {filepath}")

            self.config_file_path = filepath
            self.config = configparser.ConfigParser()
            self.config.read(self.config_file_path, encoding='utf-8')

            self.populate_policy_list()
            self.file_label.config(text=os.path.basename(self.config_file_path))
            self.save_button.config(state=tk.NORMAL)
            self.status_bar.config(text=f"Loaded {len(self.policy_vars)} policies from {os.path.basename(self.config_file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read or parse the file:\n{e}")
            self.config_file_path = None
            self.file_label.config(text="No file loaded.")
            self.save_button.config(state=tk.DISABLED)
            self.status_bar.config(text="Error loading file.")
        except FileNotFoundError as e:
            messagebox.showerror("Error", str(e))
            self.status_bar.config(text=f"Error: {e}")

    def populate_policy_list(self):
        """Clears and repopulates the list of policies in the GUI."""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.policy_vars.clear()

        policy_sections = [s for s in self.config.sections() if s.startswith("Policy:")]

        if not policy_sections:
            ttk.Label(self.scrollable_frame, text="No '[Policy:*]' sections found in this file.").pack(pady=10)
            return

        for section in sorted(policy_sections):
            policy_name = section.split(":", 1)[1]
            try:
                is_enabled = self.config.getboolean(section, "status")
            except (configparser.NoOptionError, ValueError):
                is_enabled = False

            var = tk.BooleanVar(value=is_enabled)

            frame = ttk.Frame(self.scrollable_frame)
            frame.pack(fill=tk.X, pady=2, padx=5)

            cb = ttk.Checkbutton(frame, text=policy_name, variable=var)
            cb.pack(side=tk.LEFT)

            self.policy_vars[section] = (var, cb)

    def save_file(self):
        """Saves the current state of the checkboxes back to the .conf file."""
        if not self.config_file_path:
            messagebox.showwarning("Warning", "No file is loaded to save.")
            return

        try:
            for section, (var, _) in self.policy_vars.items():
                status_str = "true" if var.get() else "false"
                self.config.set(section, "status", status_str)

            with open(self.config_file_path, 'w', encoding='utf-8') as configfile:
                self.config.write(configfile)

            self.status_bar.config(text="Changes saved successfully.")
            messagebox.showinfo("Success", "Changes have been saved successfully.")
        except Exception as e:
            self.status_bar.config(text="Error saving file.")
            messagebox.showerror("Error", f"Failed to save the file:\n{e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Checkpoint Policy Manager GUI.")
    parser.add_argument(
        "--config",
        default=None,
        help="Path to the configuration file to load on startup."
    )
    args = parser.parse_args()

    root = tk.Tk()
    app = PolicyManagerApp(root, initial_config_file=args.config)
    root.mainloop()