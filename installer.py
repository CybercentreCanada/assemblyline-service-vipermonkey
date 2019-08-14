#!/usr/bin/env python

import os

def install(alsi):
    viper_req = os.path.join(alsi.alroot, "pkg", "al_services", "alsvc_vipermonkey", "ViperMonkey", "requirements.txt")
    alsi.milestone("Installing oletools, olefile, prettytable, colorlog, colorama, pyparsing==2.3.0, xlrd, unidecode, regex")
    alsi.runcmd("sudo -H pip install -r " + viper_path

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

