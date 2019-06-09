from common import parse_config
import logging

class OutputBase():
    """
    This class sets a number of standard options that all outputs can utilize.
    Options can be set at the global or output specific level in the settings file.
    
    To ensure backwards compatability, neither the globals key nor any of these options are required in the 
    settings file
    """

    def __init__(self):
        """
        here we will parse the config file and determine if any global output settings are defined
        """
        self.config = parse_config()
        self.logger = logging.getLogger('pastehunter')
        
        # if globals key is present under "outputs", get each standard output option or set a default
        self.whitelist_result_type = self.config['outputs'].get('globals', {}).get('whitelist_result_type', [])
        self.blacklist_result_type = self.config['outputs'].get('globals', {}).get('blacklist_result_type', [])
        self.exclude_raw = self.config['outputs'].get('globals', {}).get('exclude_row', False)
        self.raw_only = self.config['outputs'].get('globals', {}).get('raw_only', False)

        # this is here in case the exclude_raw flag is set. If so, it will get pulled out of paste_data
        # so that it can be saved to the output without the raw_text. However because python passes dicts by
        # reference, this raw_text field will not be present in future outputs that may require this field.
        # This instance var will keep track of that text, and replace it after it's been deleted
        self.raw_paste = None

    def get_standard_options(self, output_type):
        """
        output classes can call this in __init__ to get any standard settings from a specific output type
        """

        # check to see if any specific ouput has set it's own standard option
        # as this is a more specific setting, it should override any global setting
        self.whitelist_result_type = self.config['outputs'][output_type].get('whitelist_result_type', self.whitelist_result_type)
        self.blacklist_result_type = self.config['outputs'][output_type].get('blacklist_result_type', self.blacklist_result_type)
        self.exclude_raw = self.config['outputs'][output_type].get('exclude_raw', self.exclude_raw)
        self.raw_only = self.config['outputs'][output_type].get('raw_only', self.raw_only)

    def filter_paste(self, paste_data):
        """
        this shoud be called at the beginning of every store_paste
        """

        if self.exclude_raw:
            print("taking out raw paste")
            self.raw_paste = paste_data.pop('raw_paste')

        # if the settings specify a specific yara type
        if self.whitelist_result_type:
            # if a yara rule doesn't match one of the whitelisted types
            if not set(self.whitelist_result_type) & set(paste_data['YaraRule']):
                self.logger.info("Paste skipped: no match between paste rules {0} and whitelisted rules {1}".format(paste_data['YaraRule'], 
                                                                                                                self.whitelist_result_type)
                                                                                                                )
                return None

        # if the settings specify a yara rule to exclude
        if self.blacklist_result_type:
            # if a blacklistedd rule matches the a yara rule for this paste
            if set(self.blacklist_result_type) & set(paste_data['YaraRule']):
                self.logger.info("Paste skipped: match found between paste rules {0} and blacklisted rules {1}".format(paste_data['YaraRule'], 
                                                                                                                self.blacklist_result_type)
                                                                                                                )
                return None

        return paste_data

