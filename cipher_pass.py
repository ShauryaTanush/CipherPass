import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, Toplevel, PhotoImage
from tkinter.constants import END
import re
import os
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import pyperclip
from random import choice, randint, shuffle
from tkinter import W
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Global variables for encryption
ENCRYPTION_KEY_FILE = "encryption_key.txt"

# File paths for storing master password and salt
MASTER_PASSWORD_FILE = "master_password.txt"
SALT_FILE = "salt.txt"

# Global variables
current_selection = None
global detail_window
detail_window = None
process_treeview_click = True 


# Password hashing and verification functions
def create_salt():
    
    salt = os.urandom(16)
    with open(SALT_FILE, 'wb') as f:
        f.write(salt)
    return salt

def load_salt():
    if not os.path.exists(SALT_FILE):
        return create_salt()
    with open(SALT_FILE, 'rb') as f:
        salt = f.read()
    return salt

def hash_password(password, salt):
    # Using PBKDF2HMAC to create a hash of the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def save_master_password(hash):
    with open(MASTER_PASSWORD_FILE, 'w') as f:
        f.write(hash)

def verify_master_password():
    print("Verifying master password...")
    salt = load_salt()
    try:
        with open(MASTER_PASSWORD_FILE, 'r') as f:
            stored_master_password_hash = f.read()
            print(f"Stored master password hash: {stored_master_password_hash}")
    except FileNotFoundError:
        print("Master password file not found. Setting new master password...")
        master_password_input = simpledialog.askstring("Set Master Password", "No master password set. Enter a new master password:", show='*')
        if master_password_input:
            master_password_hash = hash_password(master_password_input, salt)
            save_master_password(master_password_hash)
            return True
        print("No master password was set by the user.")
        return False
    
    master_password_input = simpledialog.askstring("Master Password", "Enter the master password:", show='*')
    if master_password_input:
        input_hash = hash_password(master_password_input, salt)
        print(f"Input master password hash: {input_hash}")
        if input_hash == stored_master_password_hash:
            print("Master password verified successfully.")
            return True
        else:
            print("Incorrect master password.")
    else:
        print("No input was provided for the master password.")
    
    messagebox.showerror("Error", "Incorrect master password.")
    return False


def main_application_window(window):
    style = ttk.Style(window)
    style.theme_use('clam') 
    window.state('zoomed')
    main_frame = ttk.Frame(window, padding="10")
    main_frame.pack(fill='both', expand=True)
    main_frame.rowconfigure(0, weight=1)
    main_frame.columnconfigure(0, weight=1)

    passwords_frame = ttk.Frame(main_frame)
    passwords_frame.grid(row=0, column=0, sticky='nsew')
    passwords_frame.rowconfigure(1, weight=1)
    passwords_frame.columnconfigure(0, weight=1)
    # Customize Treeview
    style.configure("Treeview",
                    background="#333333",
                    foreground="white",
                    rowheight=25,
                    fieldbackground="#333333")
    style.map('Treeview', background=[('selected', '#5F5F5F')])

    # Customize Treeview Heading
    style.configure("Treeview.Heading",
                    background="#5F5F5F",
                    foreground="white",
                    relief="flat")
    style.map('Treeview.Heading', relief=[('active', 'groove'), ('pressed', 'sunken')])

    # Customize Buttons
    style.configure('TButton', background="#5F5F5F", foreground="white", borderwidth=1)
    style.map('TButton',
              background=[('active', '#5F5F5F'), ('pressed', 'black')],
              foreground=[('pressed', 'white'), ('active', 'white')])

    # Customize Entry
    style.configure('TEntry', foreground='white', background="#333333")

    # Configure the main window's background
    window.configure(background='#333333')

    # Search Frame
    search_frame = ttk.Frame(main_frame)
    search_frame.grid(row=1, column=0, sticky='ew') 
    search_frame.columnconfigure(0, weight=1)

    # Search Entry
    search_entry = tk.Entry(search_frame, width=35)
    search_entry.grid(row=0, column=0, padx=(10, 0), pady=10, sticky='ew')

    # Search Button
    search_button = ttk.Button(search_frame, text="Search", command=lambda: search_website(search_entry.get()))
    search_button.grid(row=0, column=1, padx=(10, 0), pady=10)

    def generate_password():
         # Randomly generates a password

        letters = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"  
        numbers = "23456789"  
        symbols = "!#$%&*+@^_"  

        # Ensure at least one character of each  type
        password = [
            choice(letters),
            choice(numbers),
            choice(symbols)
        ]

        
        password += [
            choice(letters + numbers + symbols)
            for _ in range(randint(8, 13))  
        ]

        shuffle(password)  # Shuffle to randomize the order

        sec_password = "".join(password)
        

        password_entry.delete(0, END)
        password_entry.insert(0, sec_password)
        pyperclip.copy(sec_password)


    def create_encryption_key():
        key = AESGCM.generate_key(bit_length=128)
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key
    
    # Function to load the encryption key
    def load_encryption_key():
        if not os.path.exists(ENCRYPTION_KEY_FILE):
            return create_encryption_key()
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            key = f.read()
        return key
    
    def encrypt_data(data):
        key = load_encryption_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_data = aesgcm.encrypt(nonce, data.encode(), None)
        return base64.urlsafe_b64encode(nonce + encrypted_data).decode()
    
    def decrypt_data(encrypted_data):
        key = load_encryption_key()
        aesgcm = AESGCM(key)
        encrypted_data = base64.urlsafe_b64decode(encrypted_data)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()


  # Save password function

    def save():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        new_data = {
            website: {
                "username": encrypt_data(username),
                "password": encrypt_data(password),
            }
        }

        if len(website) == 0 or len(username) == 0 or len(password) == 0:
            messagebox.showinfo(title="Oops", message="Please don't leave any fields empty.")
        else:
            try:
                with open("passwords.json", "r") as file:
                    # Reading old data
                    data = json.load(file)
            except (FileNotFoundError, json.JSONDecodeError):
                data = {}
            
            # Updating old data with new data
            data.update(new_data)

            with open("passwords.json", "w") as file:
                # Saving updated data
                json.dump(data, file, indent=4)
            
            # Clear all the entry fields after saving
            website_entry.delete(0, END)
            username_entry.delete(0, END)
            password_entry.delete(0, END)

            messagebox.showinfo(title="Success", message="Password saved successfully!")
            load_data_to_treeview()
            show_passwords_frame()  # Show the passwords frame with updated data


    def load_data_to_treeview():
        global current_selection
        # Clear the Treeview
        for item in tree.get_children():
            tree.delete(item)
        try:
            # Open the JSON file containing the passwords
            with open("passwords.json", "r") as file:
                data = json.load(file)
                # Iterate over each data item
                for website, details in data.items():
                    # Decrypt the username before inserting it into the Treeview
                    decrypted_username = decrypt_data(details['username'])
                    # Insert the website and the decrypted username into the Treeview
                    iid = tree.insert("", 'end', text=website, values=(website,decrypted_username))
                    # If the website is the currently selected item, highlight it in the Treeview
                    if website == current_selection:
                        tree.selection_set(iid)
        except FileNotFoundError:
            # Handle file not found error
            print("The passwords.json file is not found, creating a new one.")
            with open("passwords.json", "w") as file:
                json.dump({}, file)  # Create an empty JSON object
        except json.JSONDecodeError:
            # Handle JSON decode error
            print("The passwords.json file is empty or contains invalid JSON.")
            with open("passwords.json", "w") as file:
                json.dump({}, file)  # Reset file to an empty JSON object

# Function to show the details of the search term

    def verify_and_show_details(website):
    # Call the master password verification function
        if verify_master_password():
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                
                username_encrypted = data[website]['username']
                password_encrypted = data[website]['password']
                show_email_details_window(website, username_encrypted, password_encrypted)
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Error", "Could not load account details.")
        else:
            messagebox.showerror("Verification Failed", "Incorrect master password.")

# Search functionality


    def search_website(search_input):
        try:
            with open("passwords.json", "r") as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror("Error", "Could not load the password file.")
            return

        # Use regular expression to match the search input
        pattern = re.compile(re.escape(search_input), re.IGNORECASE)
        matches = {website: details for website, details in data.items() if pattern.search(website)}

        if matches:
            # Create a pop-up window to display the search results
            results_popup = Toplevel(window)
            results_popup.title("Search Results")

            # Listbox to display the matches
            results_listbox = tk.Listbox(results_popup)
            results_listbox.pack(padx=10, pady=10)

            for website in matches.keys():
                results_listbox.insert(tk.END, website)

            # Function to handle the selection of an item
            def on_result_select(event):
                selected_website = results_listbox.get(results_listbox.curselection())
                results_popup.destroy()  # Close the search results window
                verify_and_show_details(selected_website)

            results_listbox.bind("<<ListboxSelect>>", on_result_select)
        else:
            messagebox.showinfo("Search", "No matching websites found.")


# Add Password Frame
    add_password_frame = tk.Frame(window)
    add_password_frame.pack_propagate(False)
    add_password_frame.config(width=300, height=200)

# Show different frames in the UI

    def show_add_password_frame():
        nonlocal add_password_frame
        # passwords_frame.pack_forget()
        passwords_frame.grid_remove()
        window_width = window.winfo_width()
        window_height = window.winfo_height()
        frame_width = add_password_frame.winfo_reqwidth()
        frame_height = add_password_frame.winfo_reqheight()

    # Place the add_password_frame in the center
        # add_password_frame.place(in_=main_frame, anchor='c', relx=0.5, rely=0.5)
        add_password_frame.place(in_=main_frame, anchor='c', relx=0.5, rely=0.5)
        # add_password_frame.pack(fill='both', expand=True)
        # Clear all the entry fields when showing the frame
        website_entry.delete(0, END)
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        # Set focus to the website entry field
        website_entry.focus_set()
        
        

    def center_add_password_frame(event):
        nonlocal add_password_frame
        if add_password_frame.winfo_ismapped():
            show_add_password_frame()

    window.bind('<Configure>', center_add_password_frame)

    def show_passwords_frame():
        nonlocal add_password_frame
        add_password_frame.place_forget()
        passwords_frame.grid()
        load_data_to_treeview()
       

   
    global username_content
    global password_content
    
    def show_email_details_window(website, username_encrypted, password_encrypted):
        username = decrypt_data(username_encrypted)
        password = decrypt_data(password_encrypted)
        global username_content
        global password_content
        global detail_window
        if detail_window is not None:
            detail_window.destroy()
        detail_window = Toplevel(window)
        detail_window.title(website)
        # detail_window.transient(window)
        # detail_window.grab_set()

        # Labels for the user information
        website_label = tk.Label(detail_window, text="Website:")
        website_content = tk.Label(detail_window, text=website)

        username_label = tk.Label(detail_window, text="Username/Email:")
        username_content = tk.Label(detail_window, text=username)

        password_label = tk.Label(detail_window, text="Password:")
        password_content = tk.Label(detail_window, text=password)

        # Function to copy content to clipboard
        def copy_to_clipboard(text):
            window.clipboard_clear()
            window.clipboard_append(text)
            messagebox.showinfo("Copied", "Copied to clipboard")
            detail_window.lift()

        # Copy buttons
        copy_username_button = tk.Button(detail_window, text="Copy", command=lambda: copy_to_clipboard(username))
        copy_password_button = tk.Button(detail_window, text="Copy", command=lambda: copy_to_clipboard(password))
        
        # Edit and Delete buttons
        edit_button = tk.Button(detail_window, text="Edit", command=lambda: edit_email_details(website))
        delete_button = tk.Button(detail_window, text="Delete", command=lambda: delete_email_details(website))

        # Place widgets on the detail window
        website_label.grid(row=0, column=0)
        website_content.grid(row=0, column=1)

        username_label.grid(row=1, column=0)
        username_content.grid(row=1, column=1)
        copy_username_button.grid(row=1, column=2)

        password_label.grid(row=2, column=0)
        password_content.grid(row=2, column=1)
        copy_password_button.grid(row=2, column=2)

        edit_button.grid(row=3, column=0)
        delete_button.grid(row=3, column=1)
        # window.wait_window(detail_window)

    # Function to handle when a treeview item is clicked
    def on_treeview_click(event):
        # First, check if there is any selected item
        
        if not tree.selection():
            
            return  # Exit the function if nothing is selected

        # Since there is a selection, proceed to get the selected item
        selected_item = tree.selection()[0]
        website = tree.item(selected_item, 'text')
        # Verify master password before showing details
        if verify_master_password():
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                username = data[website]['username']
                password = data[website]['password']
                show_email_details_window(website, username, password)
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Error", "Could not load account details.")

    def on_edit_window_close():
        # This function is called when the edit window is closed
        global current_selection
        if current_selection:
            # Reselect the item in the Treeview
            for item in tree.get_children():
                if tree.item(item, 'text') == current_selection:
                    tree.selection_set(item)
                    break
        reconnect_treeview(tree)
        # If the detail window is open, bring it to the front
        if detail_window:
            detail_window.lift()


    def edit_email_details(website):
        global current_selection, detail_window
        tree.unbind('<<TreeviewSelect>>')
        # Fetch the current details
        try:
            with open("passwords.json", "r") as file:
                data = json.load(file)
            current_username_encrypted = data[website]['username']
            current_password_encrypted = data[website]['password']
            # Decrypt the username and password before displaying them
            current_username = decrypt_data(current_username_encrypted)
            current_password = decrypt_data(current_password_encrypted)
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror("Error", "Could not load account details.")
            return

        # Create a new window for editing
        edit_window = Toplevel(window)
        edit_window.title(f"Edit {website}")

        # Entries for username and password
        username_entry = tk.Entry(edit_window, width=35)
        username_entry.insert(0, current_username)  # Insert decrypted username
        password_entry = tk.Entry(edit_window, width=35)
        password_entry.insert(0, current_password)  # Insert decrypted password



        def update_and_show_details(website):
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                username_encrypted = data[website]['username']
                password_encrypted = data[website]['password']
                show_email_details_window(website, username_encrypted, password_encrypted)
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Error", "Could not load account details.")


        # Save function
        def save_edited_details():
           # Update the data with the new username and password
            new_username = username_entry.get()
            new_password = password_entry.get()
            # Encrypt the new username and password before saving
            data[website]['username'] = encrypt_data(new_username)
            data[website]['password'] = encrypt_data(new_password)

            # Save the updated data to the file
            with open("passwords.json", "w") as file:
                json.dump(data, file, indent=4)
            
            # Inform the user and close the edit window
            messagebox.showinfo("Success", "Details updated successfully.")

            # Close the edit window
            edit_window.destroy()

            # Call the function to update and show details
            update_and_show_details(website)
            if detail_window:
                detail_window.destroy()
            load_data_to_treeview()  # Refresh the Treeview
            reconnect_treeview(tree)  # Reconnect the Treeview click event
           

        # Layout
        tk.Label(edit_window, text="Username/Email:").grid(row=0, column=0)
        username_entry.grid(row=0, column=1)
        tk.Label(edit_window, text="Password:").grid(row=1, column=0)
        password_entry.grid(row=1, column=1)
        save_button = tk.Button(edit_window, text="Save", command=save_edited_details)
        save_button.grid(row=2, column=1)
        #After closing the edit window, reconnect the treeview select event
        edit_window.protocol("WM_DELETE_WINDOW", lambda: reconnect_treeview(tree))

        edit_window.protocol("WM_DELETE_WINDOW", on_edit_window_close)

        # Start the main loop of the edit window
        edit_window.mainloop()
# Function to reconnect the treeview select event
    def reconnect_treeview(tree):
        global current_selection
        print("Reconnecting Treeview...")
        tree.bind('<<TreeviewSelect>>', on_treeview_click)
        load_data_to_treeview()
        if current_selection:
            for item in tree.get_children():
                if tree.item(item, 'text') == current_selection:
                    tree.selection_set(item)
                    tree.event_generate('<<TreeviewSelect>>')
                    break
        print("Treeview reconnected.")

    
    def delete_email_details(website):
        global detail_window, current_selection
        if detail_window:
            detail_window.destroy()
            detail_window = None

        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the details for {website}?")
        if confirm:
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                if website in data:
                    del data[website]
                    with open("passwords.json", "w") as file:
                        json.dump(data, file, indent=4)
                    messagebox.showinfo("Success", "Details deleted successfully.")
                else:
                    messagebox.showinfo("Info", "The item to delete does not exist.")
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Error", "Could not delete account details.")
            finally:
                current_selection = None
                load_data_to_treeview()
                if tree.selection():
                    tree.selection_remove(tree.selection())


   
    window.title("CipherPass")
    window.config(padx=50, pady=50)

      # Treeview
    tree = ttk.Treeview(passwords_frame, columns=("Website", "Email"), show='headings', height=10)
    tree.grid(row=1, column=0, columnspan=3, pady=10, sticky='nsew')
    
    tree.column("Website", width=120, anchor='w')
    tree.heading("Website", text="Website")
    tree.column("Email", width=180, anchor='w')
    tree.heading("Email", text="Email/Username")
    tree.bind('<<TreeviewSelect>>', on_treeview_click)

    # Treeview column configuration for proper scaling
    tree.column("#0", stretch=True, anchor='center')
    tree.column("Email", stretch=True, anchor='center')

    # Add Button centered by placing it in a frame that expands
    add_button_frame = ttk.Frame(passwords_frame)
    add_button_frame.grid(row=0, column=0, sticky='nsew')
    add_button_frame.columnconfigure(0, weight=1)  # Allow the frame to expand

    add_button = ttk.Button(add_button_frame, text="+", command=show_add_password_frame)
    add_button.grid(row=0, column=0)  # Button centered in its frame

    cancel_button = tk.Button(add_password_frame, text="Cancel", command=show_passwords_frame)

    

    # Labels
    website_label = tk.Label(add_password_frame, text="Website")
    username_label = tk.Label(add_password_frame, text="Email/Username")
    password_label = tk.Label(add_password_frame, text="Password")

    # Entries
    website_entry = tk.Entry(add_password_frame, width=35)
    username_entry = tk.Entry(add_password_frame, width=35)
    password_entry = tk.Entry(add_password_frame, width=35)

    # Buttons
    generate_password_button = tk.Button(add_password_frame, text="Generate Password", command=generate_password)
    save_button = tk.Button(add_password_frame, text="Save", command=save)
    cancel_button = tk.Button(add_password_frame, text="Cancel", command=show_passwords_frame)

    # Layout for add_password_frame
    website_label.grid(row=0, column=0)
    website_entry.grid(row=0, column=1)
    username_label.grid(row=1, column=0)
    username_entry.grid(row=1, column=1)
    password_label.grid(row=2, column=0)
    password_entry.grid(row=2, column=1)
    generate_password_button.grid(row=3, column=0)
    save_button.grid(row=3, column=1)
    cancel_button.grid(row=4, column=1)

    # Start with passwords_frame
    show_passwords_frame()

    window.mainloop()
    

if __name__ == "__main__":
    print("Starting the application...")
    root = tk.Tk()
    root.withdraw()  # Hide the main window

    verification_passed = verify_master_password()
    print(f"Verification passed: {verification_passed}")
    
    if verification_passed:
        print("Displaying the main application window...")
        root.deiconify()  # Show the window if the master password is verified
        main_application_window(root)
        root.mainloop()
    else:
        print("Verification failed or cancelled. Exiting the application...")
        root.destroy()





