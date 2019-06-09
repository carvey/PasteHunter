from .output_base import OutputBase
from elasticsearch import Elasticsearch
from common import parse_config
from datetime import datetime

class ElasticOutput(OutputBase):

    def __init__(self):
        super().__init__()
        self.get_standard_options('elastic_output')
         
        # Set up the database connection
        es_host = self.config['outputs']['elastic_output']['elastic_host']
        es_port = self.config['outputs']['elastic_output']['elastic_port']
        es_user = self.config['outputs']['elastic_output']['elastic_user']
        es_pass = self.config['outputs']['elastic_output']['elastic_pass']
        self.es_index = self.config['outputs']['elastic_output']['elastic_index']
        self.weekly = self.config['outputs']['elastic_output']['weekly_index']
        es_ssl = self.config['outputs']['elastic_output']['elastic_ssl']

        self.test = False

        try:
            self.es = Elasticsearch(es_host, port=es_port, http_auth=(es_user, es_pass), use_ssl=es_ssl)
            self.test = True
        except Exception as e:
            self.logger.error(e)
            raise Exception('Unable to Connect') from None

    def store_paste(self, paste_data):
        if self.test:
            paste_data = self.filter_paste(paste_data)
            if not paste_data:
                return

            index_name = self.es_index
            if self.weekly:
                year_number = datetime.date(datetime.now()).isocalendar()[0]
                week_number = datetime.date(datetime.now()).isocalendar()[1]
                index_name = '{0}-{1}-{2}'.format(index_name, year_number, week_number)

            # ToDo: With multiple paste sites a pasteid collision is more likly!
            try:
                pasteid = str(paste_data['pasteid'])
                paste_data['raw_paste_url'] = 'http://files.charlesarvey.com/pastes/%s' % pasteid
                self.es.index(index=index_name, doc_type='paste', id=pasteid, body=paste_data)
                self.logger.debug("Stored {0} Paste {1}, Matched Rule {2}".format(paste_data['pastesite'],
                                                                             paste_data['pasteid'],
                                                                             paste_data['YaraRule']
                                                                             )
                             )

                # abstract this out eventually
                if 'raw_paste' not in paste_data:
                    paste_data['raw_paste'] = self.raw_paste

            except Exception as e:
                self.logger.error(e)
                raise Exception(e)
        else:
            self.logger.error("Elastic Search Enabled, not configured!")

