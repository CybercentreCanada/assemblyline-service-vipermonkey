import os
import uuid
import shutil
import pytest
from assemblyline.common import forge
from assemblyline_v4_service.common import helper
from assemblyline.common.importing import load_module_by_path
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.task import Task

identify = forge.get_identify(use_cache=False)

@pytest.fixture()
def sample(request):
    sample_path = os.path.join("tests", "samples", request.param)
    sha256_of_file = identify.fileinfo(sample_path, calculate_entropy=False, skip_fuzzy_hashes=True)["sha256"]
    shutil.copy(sample_path, os.path.join("/tmp", sha256_of_file))
    yield sha256_of_file
    os.remove(os.path.join("/tmp", sha256_of_file))

# Force manifest location
os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

# Setup folder locations
RESULTS_FOLDER = os.path.join(os.path.dirname(__file__), "results")
SAMPLES_FOLDER = os.path.join(os.path.dirname(__file__), "samples")

# Initialize test helper
service_class = load_module_by_path("vipermonkey_.vipermonkey_.ViperMonkey", os.path.join(os.path.dirname(__file__), ".."))

def create_service_task(sample):
    fileinfo_keys = ["magic", "md5", "mime", "sha1", "sha256", "size", "type"]

    return ServiceTask(
        {
            "sid": str(uuid.uuid4()),
            "metadata": {},
            "deep_scan": False,
            "service_name": "Not Important",
            "service_config": {
                "extract_body_text": False,
                "save_emlparser_output": False,
            },
            "fileinfo": {
                k: v
                for k, v in identify.fileinfo(f"/tmp/{sample}", skip_fuzzy_hashes=True, calculate_entropy=False).items()
                if k in fileinfo_keys
            },
            "filename": sample,
            "min_classification": "TLP:WHITE",
            "max_files": 501,
            "ttl": 3600,
        }
    )


class TestService:

    # test FileLen call for a missing file
    @staticmethod
    @pytest.mark.parametrize("sample", ["filelen.vbs"], indirect=True)
    def test_invalid_filelen(sample):
        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        task = Task(create_service_task(sample=sample))
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        print(test_result)

    # test FileLen call for an existing file
    @staticmethod
    @pytest.mark.parametrize("sample", ["filelen.vbs"], indirect=True)
    def test_valid_filelen(sample):

        f = open("/tmp/file.txt", "w")
        f.write("aaaa")
        f.close()
        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()

        print(test_result)

        os.remove("/tmp/file.txt")

        try:
            f = open(f"/tmp/{service_task.sid}_vipermonkey_output.log", "r")
            output_log = f.read()

            assert "Debug Print          | 4" in output_log
        except FileNotFoundError:
            assert True == False # failed to read output log
        except IOError:
            assert True == False # failed to read output log


    # test Get# file read from ActiveDocument.FullName
    @staticmethod
    @pytest.mark.parametrize("sample", ["getread.vbs"], indirect=True)
    def test_get_file_read_1(sample):

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()

        print(test_result['result']['sections'][4]['body'])

        assert "['i', 'm', ' ', 'f', 'i', 'l', 'e', 'N', 'u', 'm', 'b', 'e', 'r', ','," in str(test_result['result']['sections'])

    # test get# file read for a test.txt file
    @staticmethod
    @pytest.mark.parametrize("sample", ["getread_test.vbs"], indirect=True)
    def test_get_file_read_2(sample):

        f = open("/tmp/file.txt", "w")
        f.write("aaaa")
        f.close()

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()
        os.remove("/tmp/file.txt")

        assert "aaaa" in str(test_result['result']['sections'])

    # test regex and .FirstIndex
    @staticmethod
    @pytest.mark.parametrize("sample", ["regex_firstindex.vbs"], indirect=True)
    def test_regex_firstindex(sample):

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()

        assert "match: 3" in str(test_result['result']['sections'])
        assert "match: 8" in str(test_result['result']['sections'])

    # test xor with 2 ints
    @staticmethod
    @pytest.mark.parametrize("sample", ["int_xor.vbs"], indirect=True)
    def test_int_xor(sample):

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()

        assert "result: 6" in str(test_result['result']['sections'])


    # test xor with ascii
    @staticmethod
    @pytest.mark.parametrize("sample", ["ascii_xor.vbs"], indirect=True)
    def test_ascii_xor(sample):

        config = helper.get_service_attributes().config

        f = open("/tmp/file.txt", "w")
        f.write("ab31")
        f.close()

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()
        os.remove("/tmp/file.txt")

        assert "ab31" in str(test_result['result']['sections'])
        assert "result1: 3" in str(test_result['result']['sections'])
        assert "result2: 2" in str(test_result['result']['sections'])

    # test byval function calls
    @staticmethod
    @pytest.mark.parametrize("sample", ["byval.vbs"], indirect=True)
    def test_byval(sample):

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()

        # array shouldnt be updated
        assert "[5, 15, 25, 35, 45]" in str(test_result['result']['sections'])


    # test byref function calls
    # should be treated as byref by default in vbscript
    @staticmethod
    @pytest.mark.parametrize("sample", ["byref.vbs"], indirect=True)
    def test_byref(sample):

        config = helper.get_service_attributes().config

        cls = service_class(config=config)
        cls.start()

        service_task = create_service_task(sample=sample)
        task = Task(service_task)
        service_request = ServiceRequest(task)
        cls.execute(service_request)

        test_result = task.get_service_result()


        assert "[15, 25, 35, 45, 55]" in str(test_result['result']['sections'])
