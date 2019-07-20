import responses
from pastehunter import PasteHunter

class APITests:

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

    @responses.activate
    def test_b64_exe(self):
        self.setup_scrape_results()
        scrape_item_results = [{
                "raw_paste": "test@gmail.com:password", 
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

        responses.add(responses.GET, "https://scrape.pastebin.com/api_scrape_item.php?i=abcd1234", 
                json=scrape_item_results, status=404
                )

        pastehunter = PasteHunter()
        pastehunter.cache_pastes = False
        pastehunter.start_scanner()


tests = APITests()
tests.test_b64_exe()
