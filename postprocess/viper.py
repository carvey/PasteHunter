import requests

class ViperJob:

    def __init__(self, conf, pasteid):
        self.conf = conf
        self.pasteid = pasteid

    def send(self):

        viper_host = self.conf["general"]["viper"]["api_host"]
        #viper_port = self.conf["general"]["viper"]["api_port"]
        #viper_host = 'http://{0}:{1}'.format(viper_ip, viper_port)

        tmp_path = self.conf["general"]["viper"]["tmp_path"]
        auth_token = self.conf["general"]["viper"]["auth_token"]

        file_add_url = '{0}/api/v3/project/default/malware/upload/'.format(viper_host)
        header = {"Authorization": "Token " + auth_token}
        tmp_file = open(tmp_path + self.pasteid, 'rb')
        files = {'file': tmp_file}
        submit_file = requests.post(file_add_url, headers=header, files=files)

        tmp_file.close()

        return submit_file.content
