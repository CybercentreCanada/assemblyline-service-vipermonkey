
from assemblyline.al.service.base import ServiceBase
from assemblyline.al.common.result import Result, ResultSection, SCORE, TAG_TYPE, TAG_WEIGHT, TEXT_FORMAT, TAG_USAGE, \
    TAG_SCORE, Tag

import vipermonkey.vmonkey as vmonkey
import os
import re
import sys
import logging
import base64
import binascii
import string

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

        ip_list = []
        url_list = []

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
                if action[2] == 'Shell function':
                    self.result.add_tag(TAG_TYPE.SHELLCODE, action[0], TAG_WEIGHT.MED)
                # Entry point actions have an empty description field, re-organize result section for this case
                if action[0] == 'Found Entry Point':
                    sub_action_section = ResultSection(SCORE.LOW, 'Found Entry Point', parent=action_section)
                    sub_action_section.add_line(action[1])
                else:
                    # Action's description will be the sub-section name
                    sub_action_section = ResultSection(SCORE.LOW, action[2], parent=action_section)
                    sub_action_section.add_line('Action: %s' % action[0])

                    # Parameters are sometimes stored as a list, account for this
                    if isinstance(action[1], list):
                        param = ', '.join(str(a) for a in action[1])
                    else:
                        param = action[1]

                    # Parameters have been seen as base64 encoded, account for this
                    (b64_results, decoded) = self.check_for_b64(param)

                    # If decoded is True, base64 code was found in param
                    # b64_results parameter with decoded base64
                    if decoded:
                        #b64_results = b64_results.decode('utf-16').encode('ascii', 'ignore')
                        sub_action_section.add_line('Possible Base64 Decoded Parameters: %s' % b64_results)
                        sub_action_section.add_line('\nOriginal Parameters: %s' % param)
                        (new_urls, new_ips) = self.find_ip(b64_results)
                        if new_urls:
                            url_list.extend(new_urls)
                        if new_ips:
                            ip_list.extend(new_ips)
                        # Empty lists to reduce duplicates
                        new_urls = []
                        new_ips = []
                        # Some parameters are very long, splice if necessary (max tag size is 1000)
                        if len(param) > 50:
                            tag_name = param[:50]
                        else:
                            tag_name = param
                        self.result.add_tag(TAG_TYPE.BASE64_ALPHABET, tag_name, TAG_WEIGHT.MED)
                    else:
                        sub_action_section.add_line('Parameters: %s' % param)

                    # Add urls/ips found in parameter to respective lists
                    (new_urls, new_ips) = self.find_ip(param)
                    if new_urls:
                        url_list.extend(new_urls)
                    if new_ips:
                        ip_list.extend(new_ips)
                        
        # Add url/ip tags
        self.add_ip_tags(url_list, ip_list)

        # Create section for built-in VBA functions called
        if len(external_functions) > 0:
            external_func_section = ResultSection(SCORE.NULL, 'VBA functions called', body_format=TEXT_FORMAT.MEMORY_DUMP, parent=self.result)
            external_func_section.add_line('\n'.join(external_functions))

        request.result = self.result

    def find_ip(self, parameter):
        """
        Takes in a string and returns any urls/ip addresses found in their own list
        """

        url_list = re.findall(r'https?://(?:[-\w.]|(?:[\da-zA-Z/?=%&]))+', parameter)
        ip_regex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\:\d{1,4})?')
        ip_list = re.findall(ip_regex, parameter)

        return url_list, ip_list


    def add_ip_tags(self, url_list, ip_list):
        """
        Adds tags for urls and ip addresses from given lists
        """

        # If URL's have been found, add them to the service results
        if url_list:
            # Remove duplicates
            url_list = list(dict.fromkeys(url_list))
            domain_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these domain names:", parent=self.result)
            for url in url_list:
                # Check for empty entry
                if url.strip():
                    domain_section.add_line(url)
                    self.result.add_tag(TAG_TYPE.NET_FULL_URI, url, TAG_WEIGHT.MED)

        # If IP addresses have been found, add them to the service results
        if ip_list:
            ip_list = list(dict.fromkeys(ip_list))
            ip_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these IP addresses:", parent=self.result)
            for ip in ip_list:
                ipstr = str(ip)
                # Check for empty entry
                if ip.strip():
                    ip_section.add_line(ipstr)
                    # checking if IP ports also found and adding the corresponding tags
                    if re.findall(":", ipstr):
                        net_ip, net_port = ipstr.split(':')
                        self.result.add_tag(TAG_TYPE.NET_FULL_URI, net_ip+':'+net_port)
                        self.result.add_tag(TAG_TYPE.NET_IP, net_ip, TAG_WEIGHT.MED)
                        self.result.add_tag(TAG_TYPE.NET_PORT, net_port, TAG_WEIGHT.MED)
                    else:
                        self.result.add_tag(TAG_TYPE.NET_IP, ipstr, TAG_WEIGHT.MED)
        
    def check_for_b64(self, data):
        """Search and decode base64 strings in sample data.

        Args:
            data: Data to be searched.

        Returns:
            decoded_param: Decoded base64 string if found
            decoded: Boolean which is true if base64 found
            AL result object and whether entity was extracted (boolean).
        """
        extract = False
        b64results = {}
        b64_extracted = set()
        b64_res = None
        b64_matches = []
        b64_matches_raw = []
        b64_ascii_content = []
        base64data = None
        base64_decoded_list = []
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
                # Decode base64 bytes, add a space to beginning as it may be stripped off while using regex
                base64data_decoded = ' ' + base64data.decode('utf-16').encode('ascii', 'ignore')
                decoded_param = re.sub(b64_string_raw, base64data_decoded, decoded_param)
                decoded = True
            except:
                pass
        return decoded_param, decoded
