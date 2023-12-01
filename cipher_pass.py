
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, Toplevel
from tkinter.constants import END
import hashlib
from tkinter import W
import os
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    salt = load_salt()
    try:
        with open(MASTER_PASSWORD_FILE, 'r') as f:
            stored_master_password_hash = f.read()
    except FileNotFoundError:
         # If no master password is set, prompt the user to set one
         
        master_password_input = simpledialog.askstring("Set Master Password", "No master password set. Enter a new master password:", show='*')
        if master_password_input:
            master_password_hash = hash_password(master_password_input, salt)
            save_master_password(master_password_hash)
            return True
        return False
    
    # Prompt for master password and compare with stored hash
    master_password_input = simpledialog.askstring("Master Password", "Enter the master password:", show='*')
    if master_password_input and hash_password(master_password_input, salt) == stored_master_password_hash:
        return True
    else:
        messagebox.showerror("Error", "Incorrect master password.")
        return False



def main_application_window(window):
  


    def generate_password():
         # Randomly generates a password

        letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

        password_letters = [choice(letters) for _ in range(randint(8, 10))]
        password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
        password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

        password_list = password_letters + password_symbols + password_numbers

        shuffle(password_list)

        password = "".join(password_list)

        password_entry.delete(0, END)
        password_entry.insert(0, password)
        pyperclip.copy(password)


  # Save password function

    def save():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        new_data = {
            website: {
                "username": username,
                "password": password,
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

# Load data to Treeview function
    def load_data_to_treeview():
        global current_selection
        for item in tree.get_children():
            tree.delete(item)
        try:
            with open("passwords.json", "r") as file:
                file_content = file.read()
                # Check if the file is not empty
                if file_content:
                    # Convert string back into JSON
                    data = json.loads(file_content)
                    for website, details in data.items():
                        iid = tree.insert("", 'end', text=website, values=(details['username']))
                        if website == current_selection:
                            tree.selection_set(iid)
        except FileNotFoundError:
            print("The passwords.json file is not found, creating a new one.")
            with open("passwords.json", "w") as file:
                json.dump({}, file)  # Create an empty JSON object
        except json.JSONDecodeError:
            print("The passwords.json file is empty or contains invalid JSON.")
            with open("passwords.json", "w") as file:
                json.dump({}, file)  # Reset file to an empty JSON object

 # Handle Treeview item click

    def on_treeview_click(event):
        global current_selection
        selected_items = tree.selection()
        if not selected_items:
        # Only proceed with the message if there's genuinely no selection.
        # This check helps to avoid showing the message during updates.
            if current_selection is not None:
                messagebox.showinfo("Info", "No item selected.")
                current_selection = None
            return
        selected_item = tree.selection()[0]
        website = tree.item(selected_item, 'text')
        current_selection = website

        if verify_master_password():
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                if website in data:
                    username = data[website]['username']
                    password = data[website]['password']
                    show_email_details_window(website, username, password)
                else:
                    messagebox.showinfo("Info", "The selected item no longer exists.")
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showerror("Error", "Could not load account details.")



    # Search function
    # def search():
    #     website = website_entry.get()
    #     if len(website) == 0:
    #         messagebox.showinfo(title="Oops", message="No website was specified.")
    #     else:
    #         try:
    #             with open("passwords.json", "r") as file:
    #                 # Reading old data
    #                 data = json.load(file)
    #         except FileNotFoundError as err:
    #             messagebox.showinfo(title="Error", message="No data file found.")
    #         else:
    #             if website in data:
    #                 username = data[website]['username']
    #                 password = data[website]['password']
    #                 messagebox.showinfo(title=website, message=f"Username: {username}\n Password: {password}.")
    #             else:
    #                 messagebox.showinfo(title="Oops", message=f"No details for {website} exists.")
    #         finally:
    #             website_entry.delete(0, END)


# Show different frames in the UI

    def show_add_password_frame():
        passwords_frame.pack_forget()
        add_password_frame.pack(fill='both', expand=True)
        # Clear all the entry fields when showing the frame
        website_entry.delete(0, END)
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        # Set focus to the website entry field
        website_entry.focus_set()


    def show_passwords_frame():
        add_password_frame.pack_forget()
        passwords_frame.pack(fill='both', expand=True)
        load_data_to_treeview()


 # Email Details functions
    def show_email_details(event):
        # Get the selected item
        selected_item = tree.selection()[0]
        website = tree.item(selected_item, 'text')

        # Verify the master password before showing details
        if verify_master_password():
            # Assuming the details are in the same JSON file
            try:
                with open("passwords.json", "r") as file:
                    data = json.load(file)
                    if website in data:
                        username = data[website]['username']
                        password = data[website]['password']
                        messagebox.showinfo(title=website, message=f"Username: {username}\nPassword: {password}")
                    else:
                        messagebox.showinfo(title="Error", message="Details not found.")
            except (FileNotFoundError, json.JSONDecodeError):
                messagebox.showinfo(title="Error", message="No data file found.")


   
    global username_content
    global password_content
    
    def show_email_details_window(website, username, password):
        global username_content
        global password_content
        global detail_window
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
            messagebox.showinfo("Error", "No item selected.")
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



    def edit_email_details(website):
        global current_selection
        tree.unbind('<<TreeviewSelect>>')
        # Fetch the current details
        try:
            with open("passwords.json", "r") as file:
                data = json.load(file)
            current_username = data[website]['username']
            current_password = data[website]['password']
        except (FileNotFoundError, json.JSONDecodeError):
            messagebox.showerror("Error", "Could not load account details.")
            return

        # Create a new window for editing
        edit_window = Toplevel(window)
        edit_window.title(f"Edit {website}")

        # Entries for username and password
        username_entry = tk.Entry(edit_window, width=35)
        username_entry.insert(0, current_username)
        password_entry = tk.Entry(edit_window, width=35)
        password_entry.insert(0, current_password)

        # Save function
        def save_edited_details():
            # Update the data with the new username and password
            new_username = username_entry.get()
            new_password = password_entry.get()
            data[website]['username'] = new_username
            data[website]['password'] = new_password

            # Save the updated data to the file
            with open("passwords.json", "w") as file:
                json.dump(data, file, indent=4)

            # Update the labels in the detail window to reflect the changes
            username_content.config(text=new_username)
            password_content.config(text=new_password)

            # Inform the user and close the edit window
            messagebox.showinfo("Success", "Details updated successfully.")
            edit_window.destroy()
            # This will bring the details window to the top after the message box is closed
            detail_window.lift()

        # Layout
        tk.Label(edit_window, text="Username/Email:").grid(row=0, column=0)
        username_entry.grid(row=0, column=1)
        tk.Label(edit_window, text="Password:").grid(row=1, column=0)
        password_entry.grid(row=1, column=1)
        save_button = tk.Button(edit_window, text="Save", command=save_edited_details)
        save_button.grid(row=2, column=1)
        #After closing the edit window, reconnect the treeview select event
        edit_window.protocol("WM_DELETE_WINDOW", lambda: reconnect_treeview(tree))

# Function to reconnect the treeview select event
    def reconnect_treeview(tree):
        global current_selection
        tree.bind('<<TreeviewSelect>>', on_treeview_click)
        load_data_to_treeview()
        # Ensure the previous selection is maintained if possible
        if current_selection:
            for item in tree.get_children():
                if tree.item(item, 'text') == current_selection:
                    tree.selection_set(item)
                    break

    
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

    # Passwords Frame
    passwords_frame = tk.Frame(window)
    passwords_frame.pack(fill='both', expand=True)

    # Treeview
    
    tree = ttk.Treeview(passwords_frame, columns=("Email"), show='headings', height=10)
    tree.column("#0", width=120)
    tree.heading("#0", text="Website")
    tree.column("Email", anchor=W, width=180)
    tree.heading("Email", text="Email/Username")
    tree.grid(row=1, column=0, columnspan=3, pady=10, sticky='nsew')
   # tree.bind('<<TreeviewSelect>>', show_email_details)
    tree.bind('<<TreeviewSelect>>', on_treeview_click)
    # Add Button (+)
    add_button = tk.Button(passwords_frame, text="+", command=show_add_password_frame)
    add_button.grid(row=0, column=0, sticky='ne')

    # Add Password Frame
    add_password_frame = tk.Frame(window)

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
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    if verify_master_password():
        root.deiconify()  # Show the window if the master password is verified
        main_application_window(root)
        root.mainloop()
    else:
        root.destroy()  # Close the application if the master password is not verified





