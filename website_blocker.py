import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import hashlib
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import socket
import subprocess

# Database setup
DATABASE_URL = 'sqlite:///website_blocker.db'
Base = declarative_base()
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

class BlockList(Base):
    __tablename__ = 'block_list'
    id = Column(Integer, primary_key=True, autoincrement=True)
    list_name = Column(String, unique=True, nullable=False)

class BlockedSite(Base):
    __tablename__ = 'blocked_sites'
    id = Column(Integer, primary_key=True, autoincrement=True)
    site_name = Column(String, nullable=False)
    list_id = Column(Integer, nullable=False)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

Base.metadata.create_all(engine)

class WebsiteBlockerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Website Blocker")

        # Create the main frame
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Create a tabbed interface
        self.tab_control = ttk.Notebook(self.main_frame)
        
        self.create_tab1()
        self.create_tab2()
        self.create_tab3()

        self.tab_control.pack(fill=tk.BOTH, expand=True)

    def create_tab1(self):
        # Create tab for list operations
        tab1 = ttk.Frame(self.tab_control)
        self.tab_control.add(tab1, text='Manage Lists')

        self.create_list_button = ttk.Button(tab1, text="Create New List", command=self.create_new_list)
        self.create_list_button.pack(pady=10)

        self.select_table_button = ttk.Button(tab1, text="Select from the List", command=self.display_table_list)
        self.select_table_button.pack(pady=10)

    def create_tab2(self):
        # Create tab for user login
        tab2 = ttk.Frame(self.tab_control)
        self.tab_control.add(tab2, text='User Login')

        self.login_button = ttk.Button(tab2, text="Login", command=self.show_login_window)
        self.login_button.pack(pady=20)

    def create_tab3(self):
        # Create tab for additional features or settings
        tab3 = ttk.Frame(self.tab_control)
        self.tab_control.add(tab3, text='Settings')

        # Example settings options
        ttk.Label(tab3, text="Settings or additional features can be added here.").pack(pady=20)

    def show_login_window(self):
        login_window = tk.Toplevel(self.master)
        login_window.title("Login")

        ttk.Label(login_window, text="Username").pack(pady=5)
        self.username_entry = ttk.Entry(login_window)
        self.username_entry.pack(pady=5)

        ttk.Label(login_window, text="Password").pack(pady=5)
        self.password_entry = ttk.Entry(login_window, show='*')
        self.password_entry.pack(pady=5)

        ttk.Button(login_window, text="Login", command=self.authenticate_user).pack(pady=10)

    def authenticate_user(self):
        username = self.username_entry.get()
        password = hashlib.sha256(self.password_entry.get().encode()).hexdigest()
        
        user = session.query(User).filter_by(username=username, password=password).first()
        if user:
            messagebox.showinfo("Login Successful", "Welcome!")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def display_table_list(self):
        table_selection_window = tk.Toplevel(self.master)
        table_selection_window.title("Select Table")

        tables = session.query(BlockList).all()

        checkbox_vars = []

        def block_selected_tables():
            selected_tables = [table.list_name for table, var in zip(tables, checkbox_vars) if var.get()]
            if selected_tables:
                ip_addresses = self.get_ip_addresses_from_tables(selected_tables)
                self.block_ip_addresses(ip_addresses)
                messagebox.showinfo("Block from the Lists", f"Websites blocked from tables: {selected_tables}")
                table_selection_window.destroy()
            else:
                messagebox.showwarning("Select Table", "Please select at least one table.")

        for table in tables:
            var = tk.BooleanVar()
            checkbox = tk.Checkbutton(table_selection_window, text=table.list_name, variable=var)
            checkbox.pack(anchor=tk.W)
            checkbox_vars.append(var)

        block_button = ttk.Button(table_selection_window, text="BLOCK", command=block_selected_tables)
        block_button.pack(pady=10)

    def get_ip_addresses_from_tables(self, tables):
        ip_addresses = []
        for table_name in tables:
            sites = session.query(BlockedSite).join(BlockList).filter(BlockList.list_name == table_name).all()
            ip_addresses.extend([site.site_name for site in sites])
        return ip_addresses

    def block_ip_addresses(self, ip_addresses):
        # Example placeholder for Windows
        # Replace with appropriate command or method for Windows
        try:
            for ip in ip_addresses:
                # Using netsh on Windows (replace with actual implementation)
                command = ['netsh', 'advfirewall', 'add', 'rule', 'name="Block IP"', 'dir=in', 'action=block', 'remoteip=' + ip]
                subprocess.check_call(command)
            print(f"Blocked incoming traffic from IP addresses: {ip_addresses}")
        except subprocess.CalledProcessError as e:
            print(f"Error executing command: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def create_new_list(self):
        list_name = simpledialog.askstring("Create New List", "Enter the name of the new list:")
        if list_name:
            block_list = BlockList(list_name=list_name)
            session.add(block_list)
            session.commit()
            self.add_websites_to_list(list_name)

    def add_websites_to_list(self, list_name):
        input_window = tk.Toplevel(self.master)
        input_window.title("Enter Websites")

        input_text = tk.Text(input_window, height=10, width=40)
        input_text.pack(pady=10)

        submit_button = ttk.Button(input_window, text="Submit", command=lambda: self.insert_websites_into_table(list_name, input_text.get("1.0", "end-1c")))
        submit_button.pack(pady=10)

    def insert_websites_into_table(self, list_name, websites_input):
        websites_list = [site.strip() for site in websites_input.split('\n') if site.strip()]
        block_list = session.query(BlockList).filter_by(list_name=list_name).first()
        if not block_list:
            messagebox.showerror("Error", f"List '{list_name}' does not exist.")
            return

        for site in websites_list:
            try:
                ip_address = socket.gethostbyname(site)
                blocked_site = BlockedSite(site_name=ip_address, list_id=block_list.id)
                session.add(blocked_site)
            except socket.error as e:
                print(f"Error converting {site} to IP address: {e}")

        session.commit()
        messagebox.showinfo("Website Blocker", f"Websites added to the {list_name} list.")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteBlockerApp(root)
    root.mainloop()

