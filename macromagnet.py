
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT, TAG_USAGE, \
    TAG_SCORE, Tag

import vipermonkey.vmonkey as vmonkey
import os
import re
import sys
import logging
import binascii


class MacroMagnet(ServiceBase):
    SERVICE_CATEGORY = 'Static Analysis'
    SERVICE_ACCEPTS = '(document/.*|code/xml)'
    SERIVCE_DESCRIPTION = 'Office File VBA Macro Magnet'
    SERVICE_REVISION = ServiceBase.parse_revision('$Id$')
    SERVICE_VERSION = '1'
    SERVICE_ENABLED = True
    SERVICE_STAGE = 'CORE'
    SERVICE_CPU_CORES = 1
    SERVICE_RAM_MB = 512

    def __init__(self, cfg=None):
        super(MacroMagnet, self).__init__(cfg)

    def start(self):
        self.log.debug('MacroMagnet service started')

    def execute(self, request):
        self.result = Result()
        request.result = self.result
        self.request = request
        self.task = request.task

        self.ip_list = []
        self.url_list = []

        # Will store vipermonkey log/output
        log_path = os.path.join(self.working_directory, 'vipermonkey_output.log')
        logging.basicConfig(filename=log_path, level=logging.DEBUG, format='%(levelname)-8s %(message)s')

        al_file = request.download()
        with open(al_file, 'r') as f:
            data = f.read()

        with open(log_path, 'a') as log_file:
            # Saving stdout as we want stdout going to a vipermonkey log for the vmonkey call
            stdout_saved = sys.stdout
            sys.stdout = log_file
            try:
                vmonkey_values = vmonkey.process_file(None, al_file, data)
                # Checking for tuple in case vmonkey return is only None
                if type(vmonkey_values) == tuple:
                    '''
                    Structure of variable actions is as follows:
                    [action, description, parameter]
                    action: 'Found Entry Point', 'Execute Command', etc...
                    parameter: Parameters for function
                    description: 'Shell Function', etc...
                    
                    external_functions is a list of built-in VBA functions
                    that were called
                    '''
                    actions = vmonkey_values[0]
                    external_functions = vmonkey_values[1]
                else:
                    return

            except TypeError, error:
                print >> sys.stderr, 'Exception: %s' % str(error)
                return
            sys.stdout = stdout_saved

        # Add vmonkey log as a supplemental file 
        self.task.add_supplementary(log_path, 'vmonkey log')

        if len(actions) > 0:
            # Creating action section
            action_section = ResultSection(SCORE.NULL, 'Recorded Actions:', parent=self.result)
            for action in actions:    # Creating action sub-sections for each action
                cur_action = action[0]
                cur_description = action[2]
                if cur_description == 'Shell function':
                    self.result.add_tag(TAG_TYPE.SHELLCODE, cur_action, TAG_WEIGHT.MED)
                # Entry point actions have an empty description field, re-organize result section for this case
                if cur_action == 'Found Entry Point':
                    sub_action_section = ResultSection(SCORE.LOW, 'Found Entry Point', parent=action_section)
                    sub_action_section.add_line(action[1])
                else:
                    # Action's description will be the sub-section name
                    sub_action_section = ResultSection(SCORE.LOW, cur_description, parent=action_section)
                    sub_action_section.add_line('Action: %s' % cur_action)

                    # Parameters are sometimes stored as a list, account for this
                    if isinstance(action[1], list):
                        param = ', '.join(str(a) for a in action[1])
                    else:
                        param = action[1]

                    # If decoded is true, possible base64 string has been found
                    decoded = self.check_for_b64(param, sub_action_section)
                    # check_for_b64() adds to current section when base64 string found
                    # if not, add raw parameter to section
                    if not decoded:
                        sub_action_section.add_line('Parameters: %s' % param)

                    # Add urls/ips found in parameter to respective lists
                    self.find_ip(param)
                        
        # Add url/ip tags
        self.add_ip_tags()

        # Create section for built-in VBA functions called
        if len(external_functions) > 0:
            external_func_section = ResultSection(SCORE.NULL, 'VBA functions called', body_format=TEXT_FORMAT.MEMORY_DUMP, parent=self.result)
            external_func_section.add_line('\n'.join(external_functions))

        request.result = self.result

    def find_ip(self, parameter):
        """
        Parses parameter for urls/ip addresses, adds them to their respective lists
        """

        url_list = re.findall(r'https?://(?:[-\w.]|(?:[\da-zA-Z/?=%&]))+', parameter)
        ip_list = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\:\d{1,4})?', parameter)

        for url in url_list:
            url_strip = url.strip()
            if url_strip:
                self.url_list.append(url_strip)
        for ip in ip_list:
            ip_strip = ip.strip()
            if ip_strip:
                self.ip_list.append(ip_strip)

    def add_ip_tags(self):
        """
        Adds tags for urls and ip addresses from given lists
        """

        # If URL's have been found, add them to the service results
        if self.url_list:
            # Remove duplicates
            self.url_list = list(dict.fromkeys(self.url_list))
            domain_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these domain names:", parent=self.result)
            for url in self.url_list:
                domain_section.add_line(url)
                self.result.add_tag(TAG_TYPE.NET_FULL_URI, url, TAG_WEIGHT.MED)

        # If IP addresses have been found, add them to the service results
        if self.ip_list:
            # Remove duplicates
            self.ip_list = list(dict.fromkeys(self.ip_list))
            ip_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these IP addresses:", parent=self.result)
            for ip in self.ip_list:
                ip_str = str(ip)
                ip_section.add_line(ip_str)
                # checking if IP ports also found and adding the corresponding tags
                if re.findall(":", ip_str):
                    net_ip, net_port = ip_str.split(':')
                    self.result.add_tag(TAG_TYPE.NET_FULL_URI, net_ip+':'+net_port)
                    self.result.add_tag(TAG_TYPE.NET_IP, net_ip, TAG_WEIGHT.MED)
                    self.result.add_tag(TAG_TYPE.NET_PORT, net_port, TAG_WEIGHT.MED)
                else:
                    self.result.add_tag(TAG_TYPE.NET_IP, ip_str, TAG_WEIGHT.MED)
        
    def check_for_b64(self, data, section):
        """Search and decode base64 strings in sample data.

        Args:
            data: Data to be parsed
            section: Sub-section to be modified if base64 found

        Returns:
            decoded: Boolean which is true if base64 found
        """

        b64_matches = []
        # b64_matches_raw will be used for replacing in case b64_matches are modified
        b64_matches_raw = []
        b64_tag = ''
        base64data = None
        decoded_param = data
        decoded = False

        for b64_match in re.findall('([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})',
                                    re.sub('\x3C\x00\x20\x20\x00', '', data)):
            b64 = b64_match.replace('\n', '').replace('\r', '').replace(' ', '').replace('<', '')
            uniq_char = ''.join(set(b64))
            if len(uniq_char) > 6:
                if len(b64) >= 16 and len(b64) % 4 == 0:
                    b64_matches.append(b64)
                    b64_matches_raw.append(b64_match)
        for b64_string, b64_string_raw in zip(b64_matches, b64_matches_raw):
            try:
                base64data = binascii.a2b_base64(b64_string)
                # Tagging base64, some strings are very long, account for this
                if len(b64_string) > 50:
                    b64_tag = b64_string[:50]
                else:
                    b64_tag = b64_string
                self.result.add_tag(TAG_TYPE.BASE64_ALPHABET, b64_tag, TAG_WEIGHT.MED)
                # Decode base64 bytes, add a space to beginning as it may be stripped off while using regex
                base64data_decoded = ' ' + base64data.decode('utf-16').encode('ascii', 'ignore')
                # Replace base64 from param with decoded string
                decoded_param = re.sub(b64_string_raw, base64data_decoded, decoded_param)
                decoded = True
            except:
                pass
        if decoded:
            section.add_line('Possible Base64 Decoded Parameters: %s' % decoded_param)
            section.add_line('\nOriginal Parameters: %s' % data)
            self.find_ip(decoded_param)
        return decoded
