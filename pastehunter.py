#!/usr/bin/python3

import errno
import hashlib
import importlib
import json
import logging
import multiprocessing
import os
import signal
import sys
import time
from logging import handlers
from multiprocessing import Queue
from time import sleep
from urllib.parse import unquote_plus

import requests
import yara

from common import parse_config

VERSION = 1.1


class timeout:

    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        print("Process timeout: {0}".format(self.error_message))
        sys.exit(0)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, _type, value, traceback):
        signal.alarm(0)


class PasteHunter:

    def __init__(self, testing=False):
        # hold inputs and outputs registered in settings file
        self.inputs = []
        self.outputs = []

        # this will be our compiled yara Rules instance
        self.rules = None

        # logger for this instance
        self.logger = None

        # this will be our settings.json or testing.json config file
        self.conf = None

        # if set to testing mode, only one paste is processed before exiting
        self.testing = testing

        # if in testing mode, don't cache any paste keys
        self.cache_pastes = not testing

        # Create Queue to hold paste URI's
        self.q = Queue()
        self.processes = []

        # initialize logging, inputs and outputs, and get yara rules compiled
        self.init_logging()
        self.init_inputs_outputs()
        self.init_yara()

    def init_logging(self):
        # Setup Default logging
        self.logger = logging.getLogger('pastehunter')
        self.logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s:%(filename)s: %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # Version info
        self.logger.info("Starting PasteHunter Version: {0}".format(VERSION))

        # Parse the config file
        self.logger.info("Reading Configs")
        self.conf = parse_config(self.testing)

        # If the config failed to parse
        if not self.conf:
            sys.exit()

        # Set up the log file
        if "log" in self.conf and self.conf["log"]["log_to_file"]:
            if self.conf["log"]["log_path"] != "":
                logfile = "{0}/{1}.log".format(self.conf["log"]["log_path"], self.conf["log"]["log_file"])
                # Assure directory exists
                try:
                    os.makedirs(self.conf["log"]["log_path"], exist_ok=True)  # Python>3.2
                except TypeError:
                    try:
                        os.makedirs(self.conf["log"]["log_path"])
                    except OSError as exc:  # Python >2.5
                        if exc.errno == errno.EEXIST and os.path.isdir(self.conf["log"]["log_path"]):
                            pass
                        else:
                            self.logger.error(
                                    "Can not create log file {0}: {1}".format(self.conf["log"]["log_path"], exc))
            else:
                logfile = "{0}.log".format(self.conf["log"]["log_file"])
            file_handler = handlers.RotatingFileHandler(logfile, mode='a+', maxBytes=(1048576 * 5), backupCount=7)
            if self.conf["log"]["format"] != "":
                file_formatter = logging.Formatter("{0}".format(self.conf["log"]["format"]))
                file_handler.setFormatter(file_formatter)
            else:
                file_handler.setFormatter(logFormatter)
            file_handler.setLevel(self.conf["log"]["logging_level"])
            self.logger.addHandler(file_handler)
            self.logger.info("Enabled Log File: {0}".format(logfile))
        else:
            self.logger.info("Logging to file disabled.")

        # Override Log level if needed
        if "logging_level" in self.conf["log"]:
            log_level = self.conf["log"]["logging_level"]
        elif "logging_level" in self.conf["general"]:
            # For old self.configs
            log_level = self.conf["general"]["logging_level"]
        else:
            # For older self.configs
            self.logger.error("Log Level not in self.config file. Update your base self.config file!")
            log_level = 20

        self.logger.info("Setting Log Level to {0}".format(log_level))
        logging.getLogger('requests').setLevel(log_level)
        logging.getLogger('elasticsearch').setLevel(log_level)
        logging.getLogger('pastehunter').setLevel(log_level)

    def init_inputs_outputs(self):
        # Configure Inputs
        self.logger.info("Configuring Inputs")
        self.inputs = []
        for input_type, input_values in self.conf["inputs"].items():
            if input_values["enabled"]:
                self.inputs.append(input_values["module"])
                self.logger.info("Enabled Input: {0}".format(input_type))

        # Configure Outputs
        self.logger.info("Configuring Outputs")
        self.outputs = []
        for output_type, output_values in self.conf["outputs"].items():
            if output_values["enabled"]:
                self.logger.info("Enabled Output: {0}".format(output_type))
                _module = importlib.import_module(output_values["module"])
                _class = getattr(_module, output_values["classname"])
                instance = _class()
                self.outputs.append(instance)

    def init_yara(self):
        self.logger.info("Compiling Yara Rules")
        try:
            # Update the yara rules index
            self.create_yara_index(self.conf['yara']['rule_path'],
                                   self.conf['yara']['blacklist'],
                                   self.conf['yara']['test_rules'])

            # Compile the yara rules we will use to match pastes
            index_file = os.path.join(self.conf['yara']['rule_path'], 'index.yar')
            self.rules = yara.compile(index_file)
        except Exception as e:
            print("Unable to Create Yara index: ", e)
            sys.exit()

    def create_yara_index(self, rule_path, blacklist, test_rules):
        index_file = os.path.join(rule_path, 'index.yar')
        with open(index_file, 'w') as yar:
            for filename in os.listdir(rule_path):
                if filename.endswith('.yar') and filename != 'index.yar':
                    if filename == 'blacklist.yar':
                        if blacklist:
                            self.logger.info("Enable Blacklist Rules")
                        else:
                            continue
                    if filename == 'test_rules.yar':
                        if test_rules:
                            self.logger.info("Enable Test Rules")
                        else:
                            continue
                    include = 'include "{0}"\n'.format(filename)
                    yar.write(include)

    def paste_scanner(self):
        """
        Get a paste URI from the Queue
        Fetch the raw paste
        scan the Paste
        Store the Paste
        """
        try:
            while True:
                if self.q.empty():
                    # Queue was empty, sleep to prevent busy loop
                    sleep(0.5)
                else:
                    paste_data = self.q.get()

                    with timeout(seconds=5):
                        # Start a timer
                        start_time = time.time()
                        self.logger.debug(
                                "Found New {0} paste {1}".format(paste_data['pastesite'], paste_data['pasteid']))

                        # get raw paste and hash them
                        try:

                            # Stack questions dont have a raw endpoint
                            if ('stackexchange' in self.conf['inputs']) and (
                                    paste_data['pastesite'] in self.conf['inputs']['stackexchange']['site_list']):
                                # The body is already included in the first request so we do not need a second call to the API. 

                                # Unescape the code block strings in the json body. 
                                raw_body = paste_data['body']
                                raw_paste_data = unquote_plus(raw_body)

                                # now remove the old body key as we dont need it any more
                                del paste_data['body']

                            else:
                                raw_paste_uri = paste_data['scrape_url']
                                raw_paste_data = requests.get(raw_paste_uri).text

                        # Cover fetch site SSLErrors
                        except requests.exceptions.SSLError as e:
                            self.logger.error("Unable to scan raw paste : {0} - {1}".format(paste_data['pasteid'], e))
                            raw_paste_data = ""

                        # Pastebin Cache
                        if raw_paste_data == "File is not ready for scraping yet. Try again in 1 minute.":
                            self.logger.info("Paste is still cached sleeping to try again")
                            sleep(45)
                            # get raw paste and hash them
                            raw_paste_uri = paste_data['scrape_url']
                            # Cover fetch site SSLErrors
                            try:
                                raw_paste_data = requests.get(raw_paste_uri).text
                            except requests.exceptions.SSLError as e:
                                self.logger.error(
                                        "Unable to scan raw paste : {0} - {1}".format(paste_data['pasteid'], e))
                                raw_paste_data = ""

                        # Process the paste data here
                        try:
                            # Scan with yara
                            matches = self.rules.match(data=raw_paste_data)
                        except Exception as e:
                            self.logger.error("Unable to scan raw paste : {0} - {1}".format(paste_data['pasteid'], e))
                            continue

                        # For keywords get the word from the matched string
                        results = []
                        for match in matches:
                            if match.rule == 'core_keywords' or match.rule == 'custom_keywords':
                                for s in match.strings:
                                    rule_match = s[1].lstrip('$')
                                    if rule_match not in results:
                                        results.append(rule_match)
                                results.append(str(match.rule))

                            # But a break in here for the base64. Will use it later.
                            elif match.rule.startswith('b64'):
                                results.append(match.rule)

                            # Else use the rule name
                            else:
                                results.append(match.rule)

                        # Store all OverRides other options. 
                        paste_site = paste_data['confname']
                        store_all = self.conf['inputs'][paste_site]['store_all']
                        # remove the self.confname key as its not really needed past this point
                        del paste_data['confname']

                        # Blacklist Check
                        # If any of the blacklist rules appear then empty the result set
                        blacklisted = False
                        if self.conf['yara']['blacklist'] and 'blacklist' in results:
                            results = []
                            blacklisted = True
                            self.logger.info(
                                    "Blacklisted {0} paste {1}".format(paste_data['pastesite'], paste_data['pasteid']))

                        # Post Process

                        # If post module is enabled and the paste has a matching rule.
                        post_results = paste_data
                        for post_process, post_values in self.conf["post_process"].items():
                            if post_values["enabled"]:
                                if any(i in results for i in post_values["rule_list"]) or "ALL" in post_values[
                                    "rule_list"]:
                                    if not blacklisted:
                                        self.logger.info("Running Post Module {0} on {1}".format(post_values["module"],
                                                                                                 paste_data["pasteid"]))
                                        post_module = importlib.import_module(post_values["module"])
                                        post_results = post_module.run(results,
                                                                       raw_paste_data,
                                                                       paste_data
                                                                       )

                        # Throw everything back to paste_data for ease.
                        paste_data = post_results

                        # If we have a result add some meta data and send to storage
                        # If results is empty, ie no match, and store_all is True,
                        # then append "no_match" to results. This will then force output.

                        if store_all is True:
                            if len(results) == 0:
                                results.append('no_match')

                        if len(results) > 0:
                            encoded_paste_data = raw_paste_data.encode('utf-8')
                            md5 = hashlib.md5(encoded_paste_data).hexdigest()
                            sha256 = hashlib.sha256(encoded_paste_data).hexdigest()
                            paste_data['MD5'] = md5
                            paste_data['SHA256'] = sha256
                            paste_data['raw_paste'] = raw_paste_data

                            # since some post processing modules might add a yara rule, this scan needs to be able to append
                            if 'YaraRule' not in paste_data:
                                paste_data['YaraRule'] = results
                            else:
                                paste_data['YaraRule'].append(results)

                            # Set the size for all pastes - This will override any size set by the source
                            paste_data['size'] = len(raw_paste_data)
                            for output in self.outputs:
                                try:
                                    output.store_paste(paste_data)
                                except Exception as e:
                                    self.logger.error(
                                            "Unable to store {0} to {1} with error {2}".format(paste_data["pasteid"],
                                                                                               output, e))

                        end_time = time.time()
                        self.logger.debug("Processing Finished for {0} in {1} seconds".format(
                                paste_data["pasteid"],
                                (end_time - start_time)
                        ))

        except KeyboardInterrupt:
            logging.info("Stopping Process")

    def start_scanner(self):
        # Now Fill the Queue
        try:
            while True:
                queue_count = 0
                counter = 0
                if len(self.processes) < 5:
                    for i in range(5 - len(self.processes)):
                        self.logger.warning("Creating New Process")
                        m = multiprocessing.Process(target=self.paste_scanner)
                        # Add new process to list so we can run join on them later. 
                        self.processes.append(m)
                        m.start()
                for process in self.processes:
                    if not process.is_alive():
                        self.logger.warning("Restarting Dead Process")
                        del self.processes[counter]
                        m = multiprocessing.Process(target=self.paste_scanner)
                        # Add new process to list so we can run join on them later. 
                        self.processes.append(m)
                        m.start()
                    counter += 1

                # Check if the processors are active
                # Paste History
                self.logger.info("Populating Queue")

                if self.cache_pastes and os.path.exists('paste_history.tmp'):
                    with open('paste_history.tmp') as json_file:
                        paste_history = json.load(json_file)
                else:
                    paste_history = {}

                for input_name in self.inputs:
                    if input_name in paste_history:
                        input_history = paste_history[input_name]
                    else:
                        input_history = []

                    try:
                        i = importlib.import_module(input_name)
                        # Get list of recent pastes
                        self.logger.info("Fetching paste list from {0}".format(input_name))
                        paste_list, history = i.recent_pastes(self.conf, input_history)

                        for paste in paste_list:
                            self.q.put(paste)
                            queue_count += 1
                        paste_history[input_name] = history
                    except Exception as e:
                        self.logger.error("Unable to fetch list from {0}: {1}".format(input_name, e))

                if self.cache_pastes:
                    self.logger.debug("Writing History")
                    # Write History
                    with open('paste_history.tmp', 'w') as outfile:
                        json.dump(paste_history, outfile)

                self.logger.info("Added {0} Items to the queue".format(queue_count))

                for proc in self.processes:
                    proc.join(2)

                if self.testing:
                    self.stop_scanner()
                    break

                # Slow it down a little
                self.logger.info("Sleeping for " + str(self.conf['general']['run_frequency']) + " Seconds")
                sleep(self.conf['general']['run_frequency'])

        except KeyboardInterrupt:
            self.stop_scanner()

    def stop_scanner(self):
        self.logger.info("Stopping Processes")
        for proc in self.processes:
            proc.terminate()
            proc.join()


if __name__ == "__main__":
    scanner = PasteHunter()
    scanner.start_scanner()
