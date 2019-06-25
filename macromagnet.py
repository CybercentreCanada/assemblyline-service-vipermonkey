
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
                    there were called
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
                    # Actions have been seen stored as a list, check for this
                    if isinstance(action[1], list):
                        param = ''.join(action[1])
                    else:
                        param = action[1]
                    # Parameters have been seen as base64 encoded, check for this
                    try:
                        decoded = base64.urlsafe_b64decode(param)
                        if base64.b64encode(decoded) == param:
                            # Remove non-printable characters from decoded param
                            decoded = filter(lambda x: x in string.printable, decoded)
                            sub_action_section.add_line('Decoded Parameters: %s' % decoded)
                            sub_action_section.add_line('Original Parameters: %s' % param)
                            self.find_ip(decoded)
                            # Some parameters are very long, splice if necessary (max tag size is 1000)
                            if len(param) > 50:
                                tag_name = param[:50]
                            else:
                                tag_name = param
                            self.result.add_tag(TAG_TYPE.BASE64_ALPHABET, tag_name, TAG_WEIGHT.MED)
                    except binascii.Error:
                        sub_action_section.add_line('Parameters: %s' % param)
                        self.find_ip(param)
                    except TypeError:
                        sub_action_section.add_line('Parameters: %s' % param)
                        self.find_ip(param)
                    # Specific errors are likely unnecessary to deal with
                    except:
                        sub_action_section.add_line('Parameters: %s' % param)
                        self.find_ip(param) 
        # Create section for built-in VBA functions called
        if len(external_functions) > 0:
            external_func_section = ResultSection(SCORE.NULL, 'VBA functions called', body_format=TEXT_FORMAT.MEMORY_DUMP, parent=self.result)
            external_func_section.add_line('\n'.join(external_functions))

        request.result = self.result


    def find_ip(self, parameter):
        '''
        Takes in a string and tags any domains/ip addresses found
        '''

        url_list = re.findall(r'https?://(?:[-\w.]|(?:[\da-zA-Z/?=%&]))+', parameter)
        ip_regex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\:\d{1,4})?')
        ip_list = re.findall(ip_regex, parameter)

        # going through url_list and taking out any IP addresses it found
        for url in url_list:
            if re.findall(ip_regex, url):
                url_list.remove(url)

        # if URL's have been found, add them to the service results
        if url_list:
            domain_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these domain names:", parent=self.result)
            for url in url_list:
                domain_section.add_line(url + "\n")
                self.result.add_tag(TAG_TYPE.NET_FULL_URI, url, TAG_WEIGHT.MED)

        # if IP addresses have been detected, add them to the service results
        if ip_list:
            ip_section = ResultSection(SCORE['LOW'], "MacroMagnet has found these IP addresses:", parent=self.result)
            for ip in ip_list:
                ipstr = ''.join(ip)
                ip_section.add_line(ipstr)

                # checking if IP ports also found and adding the corresponding tags
                if re.findall(":", ipstr):
                    net_ip, net_port = ipstr.split(':')
                    self.result.add_tag(TAG_TYPE.NET_IP, net_ip, TAG_WEIGHT.MED)
                    self.result.add_tag(TAG_TYPE.NET_PORT, net_port, TAG_WEIGHT.MED)
                else:
                    self.result.add_tag(TAG_TYPE.NET_IP, ipstr, TAG_WEIGHT.MED)