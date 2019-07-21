import responses
import unittest
import json
import os
from pastehunter import PasteHunter


class APITests(unittest.TestCase):

    def setup_scrape_results(self):
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

        pastehunter = PasteHunter(testing=True)
        pastehunter.start_scanner()

        stored_doc = self.get_log()

        self.assertEqual(stored_doc['YaraRule'], ['b64_exe'])

    def tearDown(self):
        if os.path.exists('logs/json/abcd1234'):
            os.remove('logs/json/abcd1234')


if __name__ == '__main__':
    unittest.main()
