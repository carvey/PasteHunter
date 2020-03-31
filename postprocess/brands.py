import re


def run(results, raw_paste_data, paste_object):
    """
    This should check the raw_paste_data for any mention of:
    1) domain names listed in the alexa top 1000
    2) games, their alt names, and their developers from https://api-docs.igdb.com/#feed
    """

    paste_object['brands'] = []

    alexa = open('postprocess/alexa_top_1000.txt')
    for top_site in alexa.readlines():
        if top_site in raw_paste_data:
            paste_object['brands'].append(top_site)


    # Send the updated json back
    return paste_object
