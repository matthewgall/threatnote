import os
import sys
import unittest
from werkzeug.security import generate_password_hash
path='../threatnote/'
sys.path.append(path)
from main import app, db, add_db_entry
from models import User, Organization, Requirements
 
 
TEST_DB = 'tn_test.db'
 
 
class Tests(unittest.TestCase):
    admin_username='admin@admin.com'
    admin_password='admin'
    user_username='user@user.com'
    user_password='user'
 
    ############################
    #### setup and teardown ####
    ############################
 
    # executed prior to each test
    def setUp(self):
        
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
            os.path.join(path, TEST_DB)
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

        
        #setting up org and users 
        org=Organization(name='Test', org_key='12345')
        add_db_entry(org)
        admin=User(organization=org.id, email=self.admin_username, password=generate_password_hash(self.admin_password), name='Admin', role='admin')
        add_db_entry(admin)
        user=User(organization=org.id, email=self.user_username, password=generate_password_hash(self.user_password), name='User', role='user')
        add_db_entry(user)
        
        self.assertEqual(app.debug, False)
 
    # executed after each test
    def tearDown(self):
        print('tearing down')
        db.drop_all()

        pass
    
    def login(self, email, password):
        print('logging in {} {}'.format(email, password))
        return self.app.post('/login', data=dict(
            email=email,
            password=password
        ), follow_redirects=True)


    def logout(self):
        return self.app.get('/logout', follow_redirects=True)
 
    '''
    A utility function to compare a database record (ie Indicators, Requirements, etc) to
    the dict you submtted when you posted- tricky part- if the form field you posted is different from the 
    database name, will need to substitute before you test
    '''
    def compare_record_to_submitted_data(self, record_object, data_dict):
        errors=[]
        record_dict=record_object.__dict__
        for key, val in record_dict.items():
            if key != '_sa_instance_state' and key in data_dict and val != data_dict[key]:
                errors.append('{} - record value- {} submitted_value- {}'.format(key, val, data_dict[key]))
        return errors
###############
#### tests ####
###############
 
    def test_main_page(self):
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)

    def test_login_logout(self):

        response = self.login(self.admin_username, self.admin_password)
        #made it to the Dashboard page
        self.assertTrue('Dashboard' in response.data.decode())

        response = self.logout()
        #made it to the Dashboard page
        self.assertTrue('Sign in to Account' in response.data.decode())
        
        response = self.login(self.user_username, self.user_password)
        #made it to the Dashboard page
        self.assertTrue('Dashboard' in response.data.decode())

        response = self.logout()
        #made it to the Dashboard page
        self.assertTrue('Sign in to Account' in response.data.decode())

    def test_req(self):
        self.login(self.admin_username, self.admin_password)
        data=dict(username=self.user_username, 
                  owner='test owner',
                  priority='low',
                  title='Test Title',
                  summary='summary',
                  gaps='gaps',
                  friendly_id='IR-1',
                  collection_reqirements='blah blah',
                  deliverables='deliverables',
                  time_requirement='01/01/2021')
        response= self.app.post('/submit_ir', data=data, follow_redirects=True)

        #I'm just checking that the page has Intel Requirements and the title I just made 
        self.assertTrue('Intel Requirements' in response.data.decode())
        self.assertTrue(data['title'] in response.data.decode())
        
        req=Requirements.query.filter_by(friendly_id=data['friendly_id']).first()
        #okay lets be sure the fields all saved
        #username=creator field
        data['creator']=data.pop('username')
        errors=self.compare_record_to_submitted_data(req, data)
        self.assertTrue(len(errors) ==0, '; '.join(errors))
        
        #now editing and saving 
        data=dict(username=self.user_username,
                  req_id=req.id,
                  is_edit='True', 
                  owner='test owner2',
                  priority='low2',
                  title='Test Title2',
                  summary='summary2',
                  gaps='gaps2',
                  friendly_id='IR-1',
                  collection_reqirements='blah blah',
                  deliverables='deliverables',
                  time_requirement='01/01/2021')
        response= self.app.post('/submit_ir', data=data, follow_redirects=True)

        #I'm just checking that the page has Intel Requirements and the title I just made
        self.assertTrue('Intel Requirements' in response.data.decode())
        self.assertTrue(data['title'] in response.data.decode())

        #checking the actual record
        req=Requirements.query.filter_by(friendly_id=data['friendly_id']).first()
        data['creator']=data.pop('username')
        errors=self.compare_record_to_submitted_data(req, data)
        self.assertTrue(len(errors) ==0, '; '.join(errors))
        
        
if __name__ == "__main__":
    
    unittest.main()