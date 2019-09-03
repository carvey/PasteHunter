import responses
import unittest
import json
import os
import requests
from pastehunter import PasteHunter
from common import parse_config


class APITests(unittest.TestCase):

    def setup_scrape_results(self):
        self.config = parse_config()

        scrape_results = [{
            "scrape_url": "https://scrape.pastebin.com/api_scrape_item.php?i=abcd1234",
            "full_url": "https://pastebin.com/abcd1234",
            "date": "1442911802",
            "key": "abcd1234",
            "size": "890",
            "expire": "1442998159",
            "title": "Once we all know when we goto function",
            "syntax": "java",
            "user": "admin"
        }]

        responses.add(responses.GET, "https://scrape.pastebin.com/api_scraping.php?limit=200",
                      json=scrape_results, status=404
                      )


    def get_log(self):
        json_log = open('logs/json/abcd1234')
        stored_doc = json.loads(json_log.read())
        json_log.close()

        return stored_doc

    @responses.activate
    def test_b64_exe(self):
        self.setup_scrape_results()
        raw_paste = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAP7MnlkAAAAAAAAAAOAAAgELAQgAAJwAAAASAAAAAAAATroAAAAgAAAAAAAAAABAAAAgAAAAAgAABAAAAAAAAAAEAAAAAAAAAAAAAQAAAgAAAAAAAAIAQIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAPS5AABXAAAAAMAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAOAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAACAAAAAAAAAAAAAAACCAAAEgAAAAAAAAAAAAAubun"

        responses.add(responses.GET, "https://scrape.pastebin.com/api_scrape_item.php?i=abcd1234",
                      body=raw_paste, status=404
                      )

        if self.config['general']['viper']['enabled']:
            responses.add_passthru(self.config['general']['viper']['api_host'])
            
            # delete our test file if its already in Viper
            auth_token = self.config["general"]["viper"]["auth_token"]
            header = {"Authorization": "Token " + auth_token}
            r = requests.delete("https://viper.charlesarvey.com/api/v3/project/default/malware/d363de25d4608eb4fca54f920f1e8cb33acb10f74018d0e0baeaac4cee2d0073/", headers=header)
            print("Deleting old file...", r.status_code, r.content)

        pastehunter = PasteHunter(testing=True)
        pastehunter.start_scanner()

        stored_doc = self.get_log()

        self.assertIn('b64_exe', stored_doc['YaraRule'])

    @responses.activate
    def test_bamfdetect(self):
        self.setup_scrape_results()
        raw_paste_file = open('TSUeDyCL')
        raw_paste = raw_paste_file.read()

        responses.add(responses.GET, "https://scrape.pastebin.com/api_scrape_item.php?i=abcd1234",
                      body=raw_paste, status=404
                      )

        if self.config["post_process"]["post_b64"]["bamfdetect"]["enabled"]:
            pass

        raw_paste_file.close()

        pastehunter = PasteHunter(testing=True)
        pastehunter.start_scanner()

        stored_doc = self.get_log()

        self.assertIn('bamfdetect', stored_doc)

    def tearDown(self):
        if os.path.exists('logs/json/abcd1234'):
            os.remove('logs/json/abcd1234')


if __name__ == '__main__':
    unittest.main()
