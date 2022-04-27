import errno
import json
import os
from pathlib import Path

import pytest
from assemblyline.common.dict_utils import flatten
from assemblyline.common.identify import fileinfo
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from cart import unpack_file

from vipermonkey_ import ViperMonkey

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SELF_LOCATION = os.environ.get("FULL_SELF_LOCATION", ROOT_DIR)
SAMPLES_LOCATION = os.environ.get("FULL_SAMPLES_LOCATION", None)


def find_sample(locations, sample):
    # Assume samples are carted
    sample = f"{sample}.cart"

    for location in locations:
        p = [path for path in Path(location).rglob(sample)]
        if len(p) == 1:
            return p[0]

    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), sample)


def list_results(location):
    return [f.rstrip(".json") for f in os.listdir(os.path.join(location, "tests", "results"))]


@pytest.fixture()
def sample(request):
    sample_path = find_sample(request.cls.locations, request.param)
    unpack_file(sample_path, os.path.join("/tmp", request.param))
    yield request.param
    os.remove(os.path.join("/tmp", request.param))


def create_service_task(sample):
    fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

    return ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {},
            "fileinfo": dict((k, v) for k, v in fileinfo(f"/tmp/{sample}").items() if k in fileinfo_keys),
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


def generalize_result(result):
    # At first we were comparing the full result and removing the random/unpredictable information.
    # Now we are only keeping the strict minimum to compare with.
    # supplementary/extracted sha256 + heuristics heur_id + tags
    trimed_result = {}
    if "response" in result:
        trimed_result["response"] = {}
        if "supplementary" in result["response"]:
            trimed_result["response"]["supplementary"] = sorted(
                [x["sha256"] for x in result["response"]["supplementary"]]
            )
        if "extracted" in result["response"]:
            trimed_result["response"]["extracted"] = sorted([x["sha256"] for x in result["response"]["extracted"]])

    if "result" in result:
        trimed_result["result"] = {}
        if "sections" in result["result"]:
            trimed_result["result"] = {"heuristics": [], "tags": {}}
            for section in result["result"]["sections"]:
                if "heuristic" in section:
                    if section["heuristic"] is not None:
                        if "heur_id" in section["heuristic"]:
                            trimed_result["result"]["heuristics"].append(section["heuristic"]["heur_id"])
                if "tags" in section:
                    if section["tags"]:
                        for k, v in flatten(section["tags"]).items():
                            if k in trimed_result["result"]["tags"]:
                                trimed_result["result"]["tags"][k].extend(v)
                            else:
                                trimed_result["result"]["tags"][k] = v

            # Sort the heur_id and tags lists so they always appear in the same order even if
            # the result sections where moved around.
            trimed_result["result"]["heuristics"] = sorted(trimed_result["result"]["heuristics"])
            for k, v in trimed_result["result"]["tags"].items():
                trimed_result["result"]["tags"][k] = sorted(v)

    return trimed_result


class TestService:
    @classmethod
    def setup_class(cls):
        # Setup where the samples can be found
        cls.locations = [SELF_LOCATION, SAMPLES_LOCATION]

    @staticmethod
    @pytest.mark.parametrize("sample", list_results(SELF_LOCATION), indirect=True)
    @pytest.mark.skip()
    def test_service(sample):
        overwrite_results = True  # Used temporarily to mass-correct tests

        cls = ViperMonkey()
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)

        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_path = os.path.join(SELF_LOCATION, "tests", "results", f"{sample}.json")
        with open(correct_path, "r") as f:
            correct_result = json.loads(f.read())

        test_result = generalize_result(test_result)

        if overwrite_results:
            if test_result != correct_result:
                with open(correct_path, "w") as f:
                    f.write(json.dumps(test_result))
        else:
            assert test_result == correct_result
