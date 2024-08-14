import unittest
from unittest.mock import patch, MagicMock
from tkinter import Tk
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from website_blocker import WebsiteBlockerApp, Base, BlockList, BlockedSite, User

class TestWebsiteBlockerApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)
        cls.session = cls.Session()

    def setUp(self):
        self.root = Tk()
        self.app = WebsiteBlockerApp(self.root)

    def tearDown(self):
        self.root.destroy()

    def test_create_new_list(self):
        with patch('your_code.simpledialog.askstring', return_value='TestList'):
            self.app.create_new_list()
        block_list = self.session.query(BlockList).filter_by(list_name='TestList').first()
        self.assertIsNotNone(block_list)
        self.assertEqual(block_list.list_name, 'TestList')

    def test_add_websites_to_list(self):
        # First, create a list
        block_list = BlockList(list_name='TestList')
        self.session.add(block_list)
        self.session.commit()

        with patch('your_code.socket.gethostbyname', return_value='127.0.0.1'):
            self.app.insert_websites_into_table('TestList', 'example.com\nanotherexample.com')
        
        blocked_sites = self.session.query(BlockedSite).filter_by(list_id=block_list.id).all()
        self.assertEqual(len(blocked_sites), 2)
        self.assertEqual(blocked_sites[0].site_name, '127.0.0.1')
        self.assertEqual(blocked_sites[1].site_name, '127.0.0.1')

    def test_authenticate_user(self):
        # Add a user to the database
        password_hash = hashlib.sha256('password'.encode()).hexdigest()
        user = User(username='testuser', password=password_hash)
        self.session.add(user)
        self.session.commit()

        self.app.username_entry = MagicMock()
        self.app.password_entry = MagicMock()

        self.app.username_entry.get.return_value = 'testuser'
        self.app.password_entry.get.return_value = 'password'

        with patch('your_code.messagebox.showinfo') as mock_info, patch('your_code.messagebox.showerror') as mock_error:
            self.app.authenticate_user()
            mock_info.assert_called_once_with("Login Successful", "Welcome!")
            mock_error.assert_not_called()

    def test_display_table_list(self):
        # Create a list with some sites
        block_list = BlockList(list_name='TestList')
        self.session.add(block_list)
        self.session.commit()
        blocked_site = BlockedSite(site_name='127.0.0.1', list_id=block_list.id)
        self.session.add(blocked_site)
        self.session.commit()

        with patch('your_code.messagebox.showinfo') as mock_info:
            self.app.get_ip_addresses_from_tables = MagicMock(return_value=['127.0.0.1'])
            self.app.block_ip_addresses = MagicMock()
            self.app.display_table_list()
            self.app.block_ip_addresses.assert_called_once_with(['127.0.0.1'])
            mock_info.assert_called_once_with("Block from the Lists", "Websites blocked from tables: ['TestList']")

    @patch('subprocess.check_call')
    def test_block_ip_addresses(self, mock_check_call):
        ip_addresses = ['127.0.0.1', '192.168.1.1']
        self.app.block_ip_addresses(ip_addresses)
        self.assertEqual(mock_check_call.call_count, len(ip_addresses))

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(cls.engine)
        cls.session.close()

if __name__ == "__main__":
    unittest.main()
