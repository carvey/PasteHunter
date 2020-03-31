import requests
import json

offset = 0
out_file = "games.txt"

games = open(out_file, "w+")

body = """
fields alternative_names, aggregated_rating, rating_count, popularity, name, involved_companies;
limit 50;
where rating_count > 15;
sort popularity desc;
offset %s;
"""

def make_request(endpoint, data):
    r = requests.get(endpoint, 
                    headers = {'user-key': '4425115abadcbdab65da53fdbff67055', 'accept': 'application/json'}, 
                    data=data
                    )

    content = json.loads(r.content.decode())
    return content


for offset in range(0, 150, 50):
    r_body = body % offset
    content = make_request('https://api-v3.igdb.com/games', r_body)

games.close()
