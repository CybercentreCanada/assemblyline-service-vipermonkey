"""ViperMonkey Service"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from codecs import BOM_UTF8, BOM_UTF16
from typing import IO, Any
from urllib.parse import urlparse

from assemblyline.common.str_utils import safe_str
from assemblyline.odm import DOMAIN_REGEX, IP_ONLY_REGEX, IPV4_REGEX, URI_PATH
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.extractor.base64 import find_base64
from assemblyline_v4_service.common.extractor.pe_file import find_pe_files
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    BODY_FORMAT,
    Heuristic,
    Result,
    ResultSection,
)
from multidecoder.analyzers.shell import find_powershell_strings, get_powershell_command

from vba_builtins import vba_builtins

PYTHON2_INTERPRETER = os.environ.get("PYTHON2_INTERPRETER", "pypy")
R_URI = f"(?:(?:(?:https?|ftp):)?//)(?:\\S+(?::\\S*)?@)?(?:{IPV4_REGEX}|{DOMAIN_REGEX})(?::\\d{{2,5}})?{URI_PATH}?"
R_IP = f"{IPV4_REGEX}(?::\\d{{1,4}})?"

FILE_PARAMETER_SIZE = 1000


def truncate(data: bytes | str, length: int = 100) -> str:
    """Helper to avoid cluttering output"""
    string = safe_str(data)
    if len(string) > length:
        return string[:length] + "..."
    return string


class ViperMonkey(ServiceBase):
    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)

        self.ip_list: list[str] = []
        self.url_list: list[str] = []
        self.found_powershell = False
        self.file_hashes: list[str] = []

        self.result: Result | None = None

    def execute(self, request: ServiceRequest) -> None:
        self.result = Result()
        request.result = self.result

        self.ip_list = []
        self.url_list = []
        self.found_powershell = False
        self.file_hashes = []

        vmonkey_err = False
        actions: list[tuple[str, str, str]] = []
        external_functions: list[str] = []
        tmp_iocs: list[str] = []
        output_results: dict[str, Any] = {}
        potential_base64: set[str] = set()

        # Running ViperMonkey
        try:
            file_contents = request.file_contents
            input_file: str = request.file_path
            input_file_obj: IO | None = None
            # Typical start to XML files
            if not file_contents.startswith(b"<?") and request.file_type == "code/xml":
                # Default encoding/decoding if BOM not found
                encoding: str | None = None
                decoding: str | None = None
                # Remove potential BOMs from contents
                if file_contents.startswith(BOM_UTF8):
                    encoding = "utf-8"
                    decoding = "utf-8-sig"
                elif file_contents.startswith(BOM_UTF16):
                    encoding = "utf-16"
                    decoding = "utf-16"
                if encoding and decoding:
                    input_file_obj = tempfile.NamedTemporaryFile("w+", encoding=encoding)
                    input_file_obj.write(file_contents.decode(decoding, errors="ignore"))
                    input_file = input_file_obj.name
                else:
                    # If the file_type was detected as XML, it's probably buried within but not actually an XML file
                    # Give no response as ViperMonkey can't process this kind of file
                    return
            cmd = " ".join(
                [
                    PYTHON2_INTERPRETER,
                    os.path.join(os.path.dirname(__file__), "vipermonkey_compat.py2"),
                    input_file,
                    self.working_directory,
                ]
            )
            p = subprocess.run(cmd, capture_output=True, shell=True, check=False)
            stdout = p.stdout

            # Close file
            if input_file_obj and os.path.exists(input_file_obj.name):
                input_file_obj.close()

            # Add artifacts
            artifact_dir = os.path.join(self.working_directory, os.path.basename(input_file) + "_artifacts")
            if os.path.exists(artifact_dir):
                for file in os.listdir(artifact_dir):
                    try:
                        file_path = os.path.join(artifact_dir, file)
                        if os.path.isfile(file_path) and os.path.getsize(file_path):
                            request.add_extracted(file_path, file, "File extracted by ViperMonkey during analysis")
                    except os.error as e:
                        self.log.warning(e)

            # Read output
            if stdout:
                for line in stdout.splitlines():
                    if line.startswith(b"{") and line.endswith(b"}"):
                        try:
                            output_results = json.loads(line)
                        except UnicodeDecodeError:
                            output_results = json.loads(line.decode("utf-8", "replace"))
                        break

                # Checking for tuple in case vmonkey return is None
                # If no macros found, return is [][][], if error, return is None
                # vmonkey_err can still happen if return is [][][], log as warning instead of error
                if isinstance(output_results.get("vmonkey_values"), dict):
                    # Structure of variable "actions" is as follows:
                    # [action, parameters, description]
                    # action: 'Found Entry Point', 'Execute Command', etc...
                    # parameters: Parameters for function
                    # description: 'Shell Function', etc...
                    #
                    # external_functions is a list of built-in VBA functions
                    # that were called
                    actions = output_results["vmonkey_values"]["actions"]
                    external_functions = output_results["vmonkey_values"]["external_funcs"]
                    tmp_iocs = output_results["vmonkey_values"]["tmp_iocs"]
                    if output_results["vmonkey_err"]:
                        vmonkey_err = True
                        self.log.warning(output_results["vmonkey_err"])
                else:
                    vmonkey_err = True
            else:
                vmonkey_err = True

        except Exception:
            self.log.exception("Vipermonkey failed to analyze file {}", request.sha256)

        if actions:
            # Creating action section
            action_section = ResultSection("Recorded Actions:", parent=self.result)
            action_section.add_tag("technique.macro", "Contains VBA Macro(s)")
            sub_action_sections: dict[str, ResultSection] = {}
            for action, parameters, description in actions:  # Creating action sub-sections for each action
                if not description:  # For actions with no description, just use the type of action
                    description = action

                if description not in sub_action_sections:
                    # Action's description will be the sub-section name
                    sub_action_section = ResultSection(description, parent=action_section)
                    sub_action_sections[description] = sub_action_section
                    if description == "Shell function":
                        sub_action_section.set_heuristic(2)
                else:
                    # Reuse existing section
                    sub_action_section = sub_action_sections[description]
                    if sub_action_section.heuristic:
                        sub_action_section.heuristic.increment_frequency()

                # Parameters are sometimes stored as a list, account for this
                if isinstance(parameters, list):
                    for item in parameters:
                        # Parameters includes more than strings (booleans for example)
                        if isinstance(item, str):
                            # Check for PowerShell
                            self.extract_powershell(item, sub_action_section, request)
                    # Join list items into single string
                    param = ", ".join(str(p) for p in parameters)

                else:
                    param = parameters
                    # Parameters includes more than strings (booleans for example)
                    if isinstance(param, str):
                        self.extract_powershell(param, sub_action_section, request)

                # If the description field was empty, re-organize result section for this case
                if description == action:
                    sub_action_section.add_line(param)
                else:
                    sub_action_section.add_line(f"Action: {action}, Parameters: {param}")

                # Check later for base64
                potential_base64.add(param)

                # Add urls/ips found in parameter to respective lists
                self.find_ip(param)
        # Check tmp_iocs
        res_temp_iocs = ResultSection("Runtime temporary IOCs")
        for ioc in tmp_iocs:
            self.extract_powershell(ioc, res_temp_iocs, request)
            potential_base64.add(ioc)
            self.find_ip(ioc)

        if len(res_temp_iocs.subsections) != 0 or res_temp_iocs.body:
            self.result.add_section(res_temp_iocs)

        # Add PowerShell score/tag if found
        if self.found_powershell:
            ResultSection("Discovered PowerShell code in file", parent=self.result, heuristic=Heuristic(3))

        # Check parameters and temp_iocs for base64
        base64_section = ResultSection("Possible Base64 found", heuristic=Heuristic(5))
        for param in potential_base64:
            self.check_for_b64(param, base64_section, request, request.file_contents)
        if base64_section.body:
            self.result.add_section(base64_section)

        # Add url/ip tags
        self.add_ip_tags()

        # Create section for built-in VBA functions called
        if len(external_functions) > 0:
            external_func_section = ResultSection(
                "VBA functions called", body_format=BODY_FORMAT.MEMORY_DUMP, parent=self.result
            )
            for func in external_functions:
                if func in vba_builtins:
                    external_func_section.add_line(func + ": " + vba_builtins[func])
                else:
                    external_func_section.add_line(func)

        # Add vmonkey log as a supplemental file if we have results
        if "stdout" in output_results and (vmonkey_err or request.result.sections):
            temp_log_copy = os.path.join(tempfile.gettempdir(), f"{request.sid}_vipermonkey_output.log")
            with open(temp_log_copy, "w", encoding="utf-8") as temp_log_file:
                temp_log_file.write(output_results["stdout"])

            request.add_supplementary(temp_log_copy, "vipermonkey_output.log", "ViperMonkey log output")
            if vmonkey_err is True:
                ResultSection(
                    'ViperMonkey has encountered an error, please check "vipermonkey_output.log"',
                    parent=self.result,
                    heuristic=Heuristic(1),
                )

    def extract_powershell(self, parameter: str, section: ResultSection, request: ServiceRequest) -> None:
        """Searches parameter for PowerShell, adds as extracted if found

        Args:
            parameter: String to be searched
            section: Section to be modified if PowerShell found
        """

        matches = find_powershell_strings(parameter.encode())

        if not matches:
            return

        self.found_powershell = True

        for match in matches:
            powershell_command = get_powershell_command(match.value)
            sha256hash = hashlib.sha256(powershell_command).hexdigest()
            # Add PowerShell code as extracted, account for duplicates
            if sha256hash not in self.file_hashes:
                powershell_filename = f"{sha256hash[0:10]}.ps1"
                ResultSection(
                    "Discovered PowerShell code in parameter.",
                    parent=section,
                    body=powershell_command[:100].decode() + f"... see [{powershell_filename}]",
                )
                powershell_file_path = os.path.join(self.working_directory, powershell_filename)
                with open(powershell_file_path, "wb") as f:
                    f.write(powershell_command)
                request.add_extracted(
                    powershell_file_path, powershell_filename, "Discovered PowerShell code in parameter"
                )
                self.file_hashes.append(sha256hash)

    def find_ip(self, parameter: str) -> None:
        """
        Parses parameter for urls/ip addresses, adds them to their respective lists

        Args:
            parameter: String to be searched
        """
        for url in re.findall(r"https?://(?:[-\w.]|(?:[\da-zA-Z/?=%&]))+", parameter):
            url_strip = url.strip()
            if url_strip:
                self.url_list.append(url_strip)
        for ip in re.findall(R_IP, parameter):
            ip_strip = ip.strip()
            if ip_strip:
                self.ip_list.append(ip_strip)

    def add_ip_tags(self) -> None:
        """
        Adds tags for urls and ip addresses from given lists
        """

        if self.url_list or self.ip_list:
            sec_iocs = ResultSection(
                "ViperMonkey has found the following IOCs:", parent=self.result, heuristic=Heuristic(4)
            )

            # Add Urls
            for url in set(self.url_list):
                sec_iocs.add_line(url)
                sec_iocs.add_tag("network.static.uri", url)
                try:
                    parsed = urlparse(url)
                    if parsed.hostname and not re.match(IP_ONLY_REGEX, parsed.hostname):
                        sec_iocs.add_tag("network.static.domain", parsed.hostname)

                except Exception:
                    pass

            # Add IPs
            for ip in set(self.ip_list):
                sec_iocs.add_line(ip)
                # Checking if IP ports also found and adding the corresponding tags
                if ":" in ip:
                    net_ip, net_port = ip.rsplit(":", 1)
                    sec_iocs.add_tag("network.static.ip", net_ip)
                    sec_iocs.add_tag("network.port", net_port)
                else:
                    sec_iocs.add_tag("network.static.ip", ip)

    def check_for_b64(self, data: str, section: ResultSection, request: ServiceRequest, file_contents: bytes) -> bool:
        """Search and decode base64 strings in sample data.

        Args:
            data: Data to be parsed
            section: base64 subsection, must have heuristic set

        Returns:
            decoded: Boolean which is true if base64 found
        """
        assert section.heuristic

        decoded_param = data
        decoded = False

        encoded_data = data.encode()
        for content, start, end in find_base64(encoded_data):
            if encoded_data[start:end] in file_contents:
                # Present in original file, not an intermediate IoC
                continue
            try:
                # Powershell base64 will be utf-16
                content = content.decode("utf-16").encode()
            except UnicodeDecodeError:
                pass
            if len(content) < 24:  # too many false positives
                continue
            try:
                if len(content) < FILE_PARAMETER_SIZE:
                    decoded_param = decoded_param[:start] + " " + content.decode(errors="ignore") + decoded_param[end:]
                else:
                    b64hash = ""
                    pe_files = find_pe_files(content)
                    for pe_file in pe_files:
                        b64hash = hashlib.sha256(pe_file).hexdigest()
                        pe_path = os.path.join(self.working_directory, b64hash)
                        with open(pe_path, "wb") as f:
                            f.write(pe_file)
                        request.add_extracted(pe_path, b64hash, "PE file found in base64 encoded parameter")
                        section.heuristic.add_signature_id("pe_file")
                    if not pe_files:
                        b64hash = hashlib.sha256(content).hexdigest()
                        content_path = os.path.join(self.working_directory, b64hash)
                        with open(content_path, "wb") as f:
                            f.write(content)
                        request.add_extracted(content_path, b64hash, "Large base64 encoded parameter")
                        section.heuristic.add_signature_id("possible_file")
                    decoded_param = decoded_param[:start] + f"[See extracted file {b64hash}]" + decoded_param[end:]
                decoded = True
            except Exception:
                pass

        if decoded:
            section.add_line(f"Possible Base64 {truncate(data)} decoded: {decoded_param}")
            self.find_ip(decoded_param)

        return decoded
