import json,os,pathlib,tempfile,unittest
from profiles import load,save,PreferencesError,new_profile,FIELDS
from settings import MAX_PROFILES

class ProfileTests(unittest.TestCase):
    def test_new_install_starts_with_one_and_no_credentials(self):
        with tempfile.TemporaryDirectory() as d:
            data=load(pathlib.Path(d)/'profiles.json')
            self.assertEqual(len(data),1)
            self.assertEqual(data[0]['path'],'')
            self.assertEqual(len(data[0]['credential_id']),32)
            self.assertNotIn('password',data[0])

    def test_one_to_ten_and_legacy_four_profiles_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'profiles.json'
            for count in (0,1,3,4,10):
                data=[dict(FIELDS,name=f'vpn-{i}',path=f'/private/vpn-{i}.ovpn') for i in range(count)]
                save(path,data);loaded=load(path)
                self.assertEqual(len(loaded),count)
                self.assertEqual([x['path'] for x in loaded],[x['path'] for x in data])
                self.assertEqual(os.stat(path).st_mode&0o777,0o600)
                if loaded:self.assertEqual(set(loaded[0]),set(FIELDS))

    def test_invalid_settings_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'profiles.json'
            for text in ('{broken','[null]',json.dumps([{}]*11)):
                path.write_text(text)
                with self.assertRaises(PreferencesError):load(path)
                self.assertEqual(path.read_text(),text)
            save(path,[])
            self.assertEqual(load(path),[])

    def test_add_name_and_credential_identity_survive_old_preferences(self):
        self.assertEqual(new_profile(['vpn-1','vpn-2'])['name'],'vpn-3')
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'profiles.json'
            old=[dict(name='project',path='/private/profile.ovpn')]
            path.write_text(json.dumps(old));first=load(path)[0]['credential_id']
            # An older app may save only its old fields. The Keychain ID stays stable.
            path.write_text(json.dumps(old));self.assertEqual(load(path)[0]['credential_id'],first)
            data=load(path);data[0]['name']='renamed';save(path,data)
            self.assertEqual(load(path)[0]['credential_id'],first)
