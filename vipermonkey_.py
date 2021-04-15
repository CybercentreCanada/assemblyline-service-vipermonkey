import binascii
import hashlib
import json
import os
import re
import subprocess
import tempfile

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from assemblyline.odm import IP_REGEX, DOMAIN_REGEX, IP_ONLY_REGEX, URI_PATH
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic


PYTHON2_INTERPRETER = os.environ.get("PYTHON2_INTERPRETER", "pypy")
R_URI = f"(?:(?:(?:https?|ftp):)?//)(?:\\S+(?::\\S*)?@)?(?:{IP_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?{URI_PATH}?"
R_IP = f'{IP_REGEX}(?::\\d{{1,4}})?'


# noinspection PyBroadException
class ViperMonkey(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)

        self.ip_list: List[str] = []
        self.url_list: List[str] = []
        self.found_powershell = False
        self.file_hashes: List[str] = []

        self.request: Optional[ServiceRequest] = None
        self.result: Optional[Result] = None

    def start(self) -> None:
        self.log.debug('ViperMonkey service started')

    def execute(self, request: ServiceRequest) -> None:
        self.result = Result()
        request.result = self.result
        self.request = request

        self.ip_list = []
        self.url_list = []
        self.found_powershell = False
        self.file_hashes = []

        vmonkey_err = False
        actions: List[str] = []
        external_functions: List[str] = []
        tmp_iocs: List[str] = []
        output_results: Dict[str, Any] = {}

        # Running ViperMonkey
        try:
            cmd = " ".join([PYTHON2_INTERPRETER,
                            os.path.join(os.path.dirname(__file__), 'vipermonkey_compat.py2'),
                            request.file_path])
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            stdout, _ = p.communicate()

            # Read output
            if stdout:
                for l in stdout.splitlines():
                    if l.startswith(b"{") and l.endswith(b"}"):
                        try:
                            output_results = json.loads(l)
                        except UnicodeDecodeError:
                            output_results = json.loads(l.decode("utf-8", "replace"))
                        break

                # Checking for tuple in case vmonkey return is None
                # If no macros found, return is [][], if error, return is None
                if isinstance(output_results.get('vmonkey_values'), dict):
                    '''
                    Structure of variable "actions" is as follows:
                    [action, description, parameter]
                    action: 'Found Entry Point', 'Execute Command', etc...
                    parameter: Parameters for function
                    description: 'Shell Function', etc...

                    external_functions is a list of built-in VBA functions
                    that were called
                    '''
                    actions = output_results['vmonkey_values']['actions']
                    external_functions = output_results['vmonkey_values']['external_funcs']
                    tmp_iocs = output_results['vmonkey_values']['tmp_iocs']
                else:
                    vmonkey_err = True
            else:
                vmonkey_err = True

        except Exception:
            self.log.exception("Vipermonkey failed to analyze file {request.sha256}")

        if len(actions) > 0:
            # Creating action section
            action_section = ResultSection('Recorded Actions:', parent=self.result)
            action_section.add_tag('technique.macro', 'Contains VBA Macro(s)')
            for action in actions:    # Creating action sub-sections for each action
                cur_action = action[0]
                cur_description = action[2] if action[2] else cur_action

                # Entry point actions have an empty description field, re-organize result section for this case
                if cur_action == 'Found Entry Point':
                    sub_action_section = ResultSection('Found Entry Point', parent=action_section)
                    sub_action_section.add_line(action[1])
                else:
                    # Action's description will be the sub-section name
                    sub_action_section = ResultSection(cur_description, parent=action_section)
                    if cur_description == 'Shell function':
                        sub_action_section.set_heuristic(2)

                    # Parameters are sometimes stored as a list, account for this
                    if isinstance(action[1], list):
                        for item in action[1]:
                            # Parameters includes more than strings (booleans for example)
                            if isinstance(item, str):
                                # Check for PowerShell
                                self.extract_powershell(item, sub_action_section)
                        # Join list items into single string
                        param = ', '.join(str(a) for a in action[1])

                    else:
                        param = action[1]
                        # Parameters includes more than strings (booleans for example)
                        if isinstance(param, str):
                            self.extract_powershell(param, sub_action_section)

                    sub_action_section.add_line(f'Action: {cur_action}')
                    sub_action_section.add_line(f'Parameters: {param}')

                    # If decoded is true, possible base64 string has been found
                    self.check_for_b64(param, sub_action_section)

                    # Add urls/ips found in parameter to respective lists
                    self.find_ip(param)

        # Check tmp_iocs
        res_temp_iocs = ResultSection('Runtime temporary IOCs')
        for ioc in tmp_iocs:
            self.extract_powershell(ioc, res_temp_iocs)
            self.check_for_b64(ioc, res_temp_iocs)
            self.find_ip(ioc)

        if len(res_temp_iocs.subsections) != 0 or res_temp_iocs.body:
            self.result.add_section(res_temp_iocs)

        # Add PowerShell score/tag if found
        if self.found_powershell:
            ResultSection('Discovered PowerShell code in file', parent=self.result, heuristic=Heuristic(3))

        # Add url/ip tags
        self.add_ip_tags()

        # Create section for built-in VBA functions called
        if len(external_functions) > 0:
            vba_builtin_dict = {}
            dict_path = os.path.join(os.path.dirname(__file__), 'VBA_built_ins.txt')
            with open(dict_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if re.search(r'^#', line):
                        continue
                    if line:
                        split_line = line.split(';')
                        vba_builtin_dict[split_line[0].strip()] = split_line[1].strip()

            external_func_section = ResultSection('VBA functions called', body_format=BODY_FORMAT.MEMORY_DUMP,
                                                  parent=self.result)
            for func in external_functions:
                if func in vba_builtin_dict:
                    external_func_section.add_line(func + ': ' + vba_builtin_dict[func])
                else:
                    external_func_section.add_line(func)

        # Add vmonkey log as a supplemental file if we have results
        if 'stdout' in output_results and (vmonkey_err or request.result.sections):
            temp_log_copy = os.path.join(tempfile.gettempdir(), f'{request.sid}_vipermonkey_output.log')
            with open(temp_log_copy, "w") as temp_log_file:
                temp_log_file.write(output_results['stdout'])

            self.request.add_supplementary(temp_log_copy, 'vipermonkey_output.log', 'ViperMonkey log output')
            if vmonkey_err is True:
                ResultSection('ViperMonkey has encountered an error, please check "vipermonkey_output.log"',
                              parent=self.result, heuristic=Heuristic(1))


    def extract_powershell(self, parameter: str, section: ResultSection) -> None:
        """Searches parameter for PowerShell, adds as extracted if found

        Args:
            parameter: String to be searched
            section: Section to be modified if PowerShell found
        """

        if re.findall(r'(?:powershell)|(?:pwsh)', parameter, re.IGNORECASE):
            self.found_powershell = True
            if isinstance(parameter, str):
                # Unicode-objects must be encoded before hashing
                sha256hash = hashlib.sha256(parameter.encode()).hexdigest()
            else:
                sha256hash = hashlib.sha256(parameter).hexdigest()
            ResultSection('Discovered PowerShell code in parameter.', parent=section)

            # Add PowerShell code as extracted, account for duplicates
            if sha256hash not in self.file_hashes:
                self.file_hashes.append(sha256hash)
                powershell_filename = f'{sha256hash[0:25]}_extracted_powershell'
                powershell_file_path = os.path.join(self.working_directory, powershell_filename)
                with open(powershell_file_path, 'w') as f:
                    f.write(parameter)
                    self.request.add_extracted(powershell_file_path, powershell_filename,
                                               'Discovered PowerShell code in parameter')

    def find_ip(self, parameter: str) -> None:
        """
        Parses parameter for urls/ip addresses, adds them to their respective lists

        Args:
            parameter: String to be searched
        """

        url_list = re.findall(r'https?://(?:[-\w.]|(?:[\da-zA-Z/?=%&]))+', parameter)
        ip_list = re.findall(R_IP, parameter)

        for url in url_list:
            url_strip = url.strip()
            if url_strip:
                self.url_list.append(url_strip)
        for ip in ip_list:
            ip_strip = ip.strip()
            if ip_strip:
                self.ip_list.append(ip_strip)

    def add_ip_tags(self) -> None:
        """
        Adds tags for urls and ip addresses from given lists
        """

        if self.url_list or self.ip_list:
            sec_iocs = ResultSection("ViperMonkey has found the following IOCs:",
                                     parent=self.result, heuristic=Heuristic(4))

            # Add Urls
            for url in set(self.url_list):
                sec_iocs.add_line(url)
                sec_iocs.add_tag('network.static.uri', url)
                try:
                    parsed = urlparse(url)
                    if parsed.hostname and not re.match(IP_ONLY_REGEX, parsed.hostname):
                        sec_iocs.add_tag('network.static.domain', parsed.hostname)

                except Exception:
                    pass

            # Add IPs
            for ip in set(self.ip_list):
                sec_iocs.add_line(ip)
                # Checking if IP ports also found and adding the corresponding tags
                if re.findall(":", ip):
                    net_ip, net_port = ip.split(':')
                    sec_iocs.add_tag('network.static.ip', net_ip)
                    sec_iocs.add_tag('network.port', net_port)
                else:
                    sec_iocs.add_tag('network.static.ip', ip)

    def check_for_b64(self, data: str, section: ResultSection) -> bool:
        """Search and decode base64 strings in sample data.

        Args:
            data: Data to be parsed
            section: Sub-section to be modified if base64 found

        Returns:
            decoded: Boolean which is true if base64 found
        """

        b64_matches: List[str] = []
        # b64_matches_raw will be used for replacing in case b64_matches are modified
        b64_matches_raw: List[str] = []
        decoded_param = data
        decoded = False

        for b64_match in re.findall('([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}[\r]?[\n]?){2,})',
                                    re.sub('\x3C\x00\x20{2}\x00', '', data)):
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
                base64data_decoded = ' ' + base64data.decode('utf-16', errors='ignore')
                # Replace base64 from param with decoded string
                decoded_param = re.sub(b64_string_raw, base64data_decoded, decoded_param)
                decoded = True
            except Exception:
                pass

        if decoded:
            decoded_section = ResultSection('Possible Base64 found', parent=section, heuristic=Heuristic(5))
            decoded_section.add_line(f'Possible Base64 Decoded Parameters: {decoded_param}')
            self.find_ip(decoded_param)

        return decoded
