import os

from .output_base import OutputBase


class RawOutput(OutputBase):
    """
    This class allows the contents of a paste to be stored independently of its metadata.

    Storage of these pastes serves as a local cache in case pastes get deleted, further prevents ES from not getting
    wrecked by large pastes, and allows us to store the pastes in a web accessable directory.

    To link the metadata output (elasticsearch document, json, etc) to the web-accessible paste file, use the 'url'
    attribute in the settings file. See the 'elastic_output.py' file for an example of an output linking one output
    to the raw paste files this output is producing.
    """

    def __init__(self):
        super().__init__()
        self.get_standard_options('raw_output')

        self.path = self.config['outputs']['raw_output']['output_path']
        if not os.path.exists(self.path):
            try:
                os.makedirs(self.path)
                self.test = True

            except OSError as e:
                self.logger.error("Unable to create raw path: {0}".format(e))
                self.test = False
        else:
            self.test = True

    def store_paste(self, paste_data):
        paste_data = self.filter_paste(paste_data)
        if not paste_data:
            return

        if self.test:
            output_file = os.path.join(self.path, str(paste_data['pasteid']))
            with open(output_file, 'w') as out:
                out.write(paste_data['raw_paste'])
                out.close()
        else:
            self.logger.error("Error writing raw text to disk")
