[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_vipermonkey-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-vipermonkey)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-vipermonkey)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-vipermonkey)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-vipermonkey)](./LICENSE)
# ViperMonkey Service

This service analyzes and emulates VBA macros contained in Microsoft Office files.
## Service Details
This service uses Decalage's ViperMonkey (https://github.com/decalage2/ViperMonkey) for analysis/emulation. ViperMonkey will report the following:

1. All discovered actions including entry points. Able to decode base64 encoded commands.

2. Any VBA built-in functions used.

3. Detected URLs, URIs, and IP addresses.

3. Tags:

        network.static.domain
        network.static.ip
        network.static.uri
        network.port
        technique.macro

### Safety

ViperMonkey may use eval() to speed up emulation. This service should be run in a sandboxed environment, which Assemblyline does by default for non-privileged services. This service should not be run in privileged mode.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name ViperMonkey \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-vipermonkey

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service ViperMonkey

Ce service analyse et émule les macros VBA contenues dans les fichiers Microsoft Office.

## Détails du service
Ce service utilise ViperMonkey de Decalage (https://github.com/decalage2/ViperMonkey) pour l'analyse/l'émulation. ViperMonkey fournit les informations suivantes :

1. Toutes les actions découvertes, y compris les points d'entrée. Capable de décoder les commandes encodées en base64.

2. Toutes les fonctions intégrées VBA utilisées.

3. URL, URI et adresses IP détectés.

3. Tags :

        réseau.statique.domaine
        réseau.statique.ip
        réseau.statique.uri
        réseau.port
        technique.macro

### Sécurité

ViperMonkey peut utiliser eval() pour accélérer l'émulation. Ce service doit être exécuté dans un environnement sandboxé, ce que fait Assemblyline par défaut pour les services non privilégiés. Ce service ne doit pas être exécuté en mode privilégié.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name ViperMonkey \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-vipermonkey

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
