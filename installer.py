#!/usr/bin/env python

import os


def install(alsi):
    local_viper = os.path.join(alsi.alroot, 'pkg/al_services/pkg/al_services/alsvc_macromagnet/ViperMonkey/')
    alsi.runcmd('pip install -e local_viper')

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

