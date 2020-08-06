import json
import requests
import requests_mock
import urllib.parse
import uuid

from kube_hunter.conf import Config
from kube_hunter.core.events import handler
from kube_hunter.core.types import Hunter
from kube_hunter.modules.hunting.kubelet import (
    AnonymousAuthEnabled,
    ExposedExistingPrivilegedContainersViaSecureKubeletPort,
    ProveAnonymousAuth,
    MaliciousIntentViaSecureKubeletPort,
    ExposedLogsOnContainerFileSystem,
    ExposedLogsOnContainerFileSystemHunter,
)

counter = 0
pod_list_with_privileged_container = """{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "kube-hunter-privileged-deployment-86dc79f945-sjjps",
        "namespace": "kube-hunter-privileged"
      },
      "spec": {
        "containers": [
          {
            "name": "ubuntu",
            "securityContext": {
              {security_context_definition_to_test}
            }
          }
        ]
      }
    }
  ]
}
"""
service_account_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlR0YmxoMXh..."
env = """PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=kube-hunter-privileged-deployment-86dc79f945-sjjps
KUBERNETES_SERVICE_PORT=443
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_PORT=tcp://10.96.0.1:443
KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
KUBERNETES_SERVICE_HOST=10.96.0.1
HOME=/root"""
exposed_privileged_containers = [
    {
        "container_name": "ubuntu",
        "environment_variables": env,
        "pod_id": "kube-hunter-privileged-deployment-86dc79f945-sjjps",
        "pod_namespace": "kube-hunter-privileged",
        "service_account_token": service_account_token,
    }
]
cat_proc_cmdline = "BOOT_IMAGE=/boot/bzImage root=LABEL=Mock loglevel=3 console=ttyS0"
number_of_rm_attempts = 1
number_of_umount_attempts = 1
number_of_rmdir_attempts = 1


def create_test_event_type_one():
    anonymous_auth_enabled_event = AnonymousAuthEnabled()

    anonymous_auth_enabled_event.host = "localhost"
    anonymous_auth_enabled_event.session = requests.Session()

    return anonymous_auth_enabled_event


def create_test_event_type_two():
    exposed_existing_privileged_containers_via_secure_kubelet_port_event = ExposedExistingPrivilegedContainersViaSecureKubeletPort(
        exposed_privileged_containers
    )
    exposed_existing_privileged_containers_via_secure_kubelet_port_event.host = "localhost"
    exposed_existing_privileged_containers_via_secure_kubelet_port_event.session = requests.Session()

    return exposed_existing_privileged_containers_via_secure_kubelet_port_event


def test_get_request_valid_url():
    class_being_tested = ProveAnonymousAuth(create_test_event_type_one())

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/mock"

        session_mock.get(url, text="mock")

        return_value = class_being_tested.get_request(url)

        assert return_value == "mock"


def test_get_request_invalid_url():
    class_being_tested = ProveAnonymousAuth(create_test_event_type_one())

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/[mock]"

        session_mock.get(url, exc=requests.exceptions.InvalidURL)

        return_value = class_being_tested.get_request(url)

        assert return_value.startswith("Exception: ")


def post_request(url, params, expected_return_value, exception=None):
    class_being_tested_one = ProveAnonymousAuth(create_test_event_type_one())

    with requests_mock.Mocker(session=class_being_tested_one.event.session) as session_mock:
        mock_params = {"text": "mock"} if not exception else {"exc": exception}
        session_mock.post(url, **mock_params)

        return_value = class_being_tested_one.post_request(url, params)

        assert return_value == expected_return_value

    class_being_tested_two = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two())

    with requests_mock.Mocker(session=class_being_tested_two.event.session) as session_mock:
        mock_params = {"text": "mock"} if not exception else {"exc": exception}
        session_mock.post(url, **mock_params)

        return_value = class_being_tested_two.post_request(url, params)

        assert return_value == expected_return_value


def test_post_request_valid_url_with_parameters():
    url = "https://localhost:10250/mock?cmd=ls"
    params = {"cmd": "ls"}
    post_request(url, params, expected_return_value="mock")


def test_post_request_valid_url_without_parameters():
    url = "https://localhost:10250/mock"
    params = {}
    post_request(url, params, expected_return_value="mock")


def test_post_request_invalid_url_with_parameters():
    url = "https://localhost:10250/mock?cmd=ls"
    params = {"cmd": "ls"}
    post_request(url, params, expected_return_value="Exception: ", exception=requests.exceptions.InvalidURL)


def test_post_request_invalid_url_without_parameters():
    url = "https://localhost:10250/mock"
    params = {}
    post_request(url, params, expected_return_value="Exception: ", exception=requests.exceptions.InvalidURL)


def test_has_no_exception_result_with_exception():
    mock_result = "Exception: Mock."

    return_value = ProveAnonymousAuth.has_no_exception(mock_result)

    assert return_value is False


def test_has_no_exception_result_without_exception():
    mock_result = "Mock."

    return_value = ProveAnonymousAuth.has_no_exception(mock_result)

    assert return_value is True


def test_has_no_error_result_with_error():
    mock_result = "Mock exited with error."

    return_value = ProveAnonymousAuth.has_no_error(mock_result)

    assert return_value is False


def test_has_no_error_result_without_error():
    mock_result = "Mock."

    return_value = ProveAnonymousAuth.has_no_error(mock_result)

    assert return_value is True


def test_has_no_error_nor_exception_result_without_exception_and_without_error():
    mock_result = "Mock."

    return_value = ProveAnonymousAuth.has_no_error_nor_exception(mock_result)

    assert return_value is True


def test_has_no_error_nor_exception_result_with_exception_and_without_error():
    mock_result = "Exception: Mock."

    return_value = ProveAnonymousAuth.has_no_error_nor_exception(mock_result)

    assert return_value is False


def test_has_no_error_nor_exception_result_without_exception_and_with_error():
    mock_result = "Mock exited with error."

    return_value = ProveAnonymousAuth.has_no_error_nor_exception(mock_result)

    assert return_value is False


def test_has_no_error_nor_exception_result_with_exception_and_with_error():
    mock_result = "Exception: Mock. Mock exited with error."

    return_value = ProveAnonymousAuth.has_no_error_nor_exception(mock_result)

    assert return_value is False


def proveanonymousauth_success(anonymous_auth_enabled_event, security_context_definition_to_test):
    global counter
    counter = 0

    with requests_mock.Mocker(session=anonymous_auth_enabled_event.session) as session_mock:
        url = "https://" + anonymous_auth_enabled_event.host + ":10250/"
        listing_pods_url = url + "pods"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="

        session_mock.get(
            listing_pods_url,
            text=pod_list_with_privileged_container.replace(
                "{security_context_definition_to_test}", security_context_definition_to_test
            ),
        )
        session_mock.post(
            run_url + urllib.parse.quote("cat /var/run/secrets/kubernetes.io/serviceaccount/token", safe=""),
            text=service_account_token,
        )
        session_mock.post(run_url + "env", text=env)

        class_being_tested = ProveAnonymousAuth(anonymous_auth_enabled_event)
        class_being_tested.execute()

        assert "The following containers have been successfully breached." in class_being_tested.event.evidence

    assert counter == 1


def test_proveanonymousauth_success_with_privileged_container_via_privileged_setting():
    proveanonymousauth_success(create_test_event_type_one(), '"privileged": true')


def test_proveanonymousauth_success_with_privileged_container_via_capabilities():
    proveanonymousauth_success(create_test_event_type_one(), '"capabilities": { "add": ["SYS_ADMIN"] }')


def test_proveanonymousauth_connectivity_issues():
    class_being_tested = ProveAnonymousAuth(create_test_event_type_one())

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://" + class_being_tested.event.host + ":10250/"
        listing_pods_url = url + "pods"

        session_mock.get(listing_pods_url, exc=requests.exceptions.ConnectionError)

        class_being_tested.execute()

        assert class_being_tested.event.evidence == ""


@handler.subscribe(ExposedExistingPrivilegedContainersViaSecureKubeletPort)
class ExposedPrivilegedContainersViaAnonymousAuthEnabledInSecureKubeletPortEventCounter(object):
    def __init__(self, event):
        global counter
        counter += 1


def test_check_file_exists_existing_file():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("ls mock.txt", safe=""), text="mock.txt")

        return_value = class_being_tested.check_file_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu", "mock.txt"
        )

        assert return_value is True


def test_check_file_exists_non_existent_file():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(
            run_url + urllib.parse.quote("ls nonexistentmock.txt", safe=""),
            text="ls: nonexistentmock.txt: No such file or directory",
        )

        return_value = class_being_tested.check_file_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "nonexistentmock.txt",
        )

        assert return_value is False


rm_command_removed_successfully_callback_counter = 0


def rm_command_removed_successfully_callback(request, context):
    global rm_command_removed_successfully_callback_counter

    if rm_command_removed_successfully_callback_counter == 0:
        rm_command_removed_successfully_callback_counter += 1
        return "mock.txt"
    else:
        return "ls: mock.txt: No such file or directory"


def test_rm_command_removed_successfully():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(
            run_url + urllib.parse.quote("ls mock.txt", safe=""), text=rm_command_removed_successfully_callback
        )
        session_mock.post(run_url + urllib.parse.quote("rm -f mock.txt", safe=""), text="")

        return_value = class_being_tested.rm_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "mock.txt",
            number_of_rm_attempts=1,
            seconds_to_wait_for_os_command=None,
        )

        assert return_value is True


def test_rm_command_removed_failed():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("ls mock.txt", safe=""), text="mock.txt")
        session_mock.post(run_url + urllib.parse.quote("rm -f mock.txt", safe=""), text="Permission denied")

        return_value = class_being_tested.rm_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "mock.txt",
            number_of_rm_attempts=1,
            seconds_to_wait_for_os_command=None,
        )

        assert return_value is False


def test_attack_exposed_existing_privileged_container_success():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "kube-hunter-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(directory_created, file_name)

        session_mock.post(run_url + urllib.parse.quote("touch {}".format(file_name_with_path), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("chmod {} {}".format("755", file_name_with_path), safe=""), text=""
        )

        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            number_of_rm_attempts,
            None,
            file_name,
        )

        assert return_value["result"] is True


def test_attack_exposed_existing_privileged_container_failure_when_touch():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "kube-hunter-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(directory_created, file_name)

        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(
            run_url + urllib.parse.quote("touch {}".format(file_name_with_path), safe=""),
            text="Operation not permitted",
        )

        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            None,
            file_name,
        )

        assert return_value["result"] is False


def test_attack_exposed_existing_privileged_container_failure_when_chmod():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "kube-hunter-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(directory_created, file_name)

        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("touch {}".format(file_name_with_path), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("chmod {} {}".format("755", file_name_with_path), safe=""),
            text="Permission denied",
        )

        return_value = class_being_tested.attack_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            directory_created,
            None,
            file_name,
        )

        assert return_value["result"] is False


def test_check_directory_exists_existing_directory():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("ls Mock", safe=""), text="mock.txt")

        return_value = class_being_tested.check_directory_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu", "Mock"
        )

        assert return_value is True


def test_check_directory_exists_non_existent_directory():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("ls Mock", safe=""), text="ls: Mock: No such file or directory")

        return_value = class_being_tested.check_directory_exists(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu", "Mock"
        )

        assert return_value is False


rmdir_command_removed_successfully_callback_counter = 0


def rmdir_command_removed_successfully_callback(request, context):
    global rmdir_command_removed_successfully_callback_counter

    if rmdir_command_removed_successfully_callback_counter == 0:
        rmdir_command_removed_successfully_callback_counter += 1
        return "mock.txt"
    else:
        return "ls: Mock: No such file or directory"


def test_rmdir_command_removed_successfully():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(
            run_url + urllib.parse.quote("ls Mock", safe=""), text=rmdir_command_removed_successfully_callback
        )
        session_mock.post(run_url + urllib.parse.quote("rmdir Mock", safe=""), text="")

        return_value = class_being_tested.rmdir_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock",
            number_of_rmdir_attempts=1,
            seconds_to_wait_for_os_command=None,
        )

        assert return_value is True


def test_rmdir_command_removed_failed():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        session_mock.post(run_url + urllib.parse.quote("ls Mock", safe=""), text="mock.txt")
        session_mock.post(run_url + urllib.parse.quote("rmdir Mock", safe=""), text="Permission denied")

        return_value = class_being_tested.rmdir_command(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            "Mock",
            number_of_rmdir_attempts=1,
            seconds_to_wait_for_os_command=None,
        )

        assert return_value is False


def test_get_root_values_success():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)
    root_value, root_value_type = class_being_tested.get_root_values(cat_proc_cmdline)

    assert root_value == "Mock" and root_value_type == "LABEL="


def test_get_root_values_failure():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)
    root_value, root_value_type = class_being_tested.get_root_values("")

    assert root_value is None and root_value_type is None


def test_process_exposed_existing_privileged_container_success():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="/dev/mock_fs")
        session_mock.post(run_url + urllib.parse.quote("mkdir {}".format(directory_created), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("mount {} {}".format("/dev/mock_fs", directory_created), safe=""), text=""
        )
        session_mock.post(
            run_url + urllib.parse.quote("cat {}/etc/hostname".format(directory_created), safe=""), text="mockhostname"
        )

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is True


def test_process_exposed_existing_privileged_container_failure_when_cat_cmdline():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text="Permission denied")

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_findfs():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="Permission denied")

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_mkdir():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="/dev/mock_fs")
        session_mock.post(
            run_url + urllib.parse.quote("mkdir {}".format(directory_created), safe=""), text="Permission denied"
        )

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_mount():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="/dev/mock_fs")
        session_mock.post(run_url + urllib.parse.quote("mkdir {}".format(directory_created), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("mount {} {}".format("/dev/mock_fs", directory_created), safe=""),
            text="Permission denied",
        )

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is False


def test_process_exposed_existing_privileged_container_failure_when_cat_hostname():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="/dev/mock_fs")
        session_mock.post(run_url + urllib.parse.quote("mkdir {}".format(directory_created), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("mount {} {}".format("/dev/mock_fs", directory_created), safe=""), text=""
        )
        session_mock.post(
            run_url + urllib.parse.quote("cat {}/etc/hostname".format(directory_created), safe=""),
            text="Permission denied",
        )

        return_value = class_being_tested.process_exposed_existing_privileged_container(
            url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu",
            number_of_umount_attempts,
            number_of_rmdir_attempts,
            None,
            directory_created,
        )

        assert return_value["result"] is False


def test_maliciousintentviasecurekubeletport_success():
    class_being_tested = MaliciousIntentViaSecureKubeletPort(create_test_event_type_two(), None)

    with requests_mock.Mocker(session=class_being_tested.event.session) as session_mock:
        url = "https://localhost:10250/"
        run_url = url + "run/kube-hunter-privileged/kube-hunter-privileged-deployment-86dc79f945-sjjps/ubuntu?cmd="
        directory_created = "/kube-hunter-mock_" + str(uuid.uuid1())
        file_name = "kube-hunter-mock" + str(uuid.uuid1())
        file_name_with_path = "{}/etc/cron.daily/{}".format(directory_created, file_name)

        session_mock.post(run_url + urllib.parse.quote("cat /proc/cmdline", safe=""), text=cat_proc_cmdline)
        session_mock.post(run_url + urllib.parse.quote("findfs LABEL=Mock", safe=""), text="/dev/mock_fs")
        session_mock.post(run_url + urllib.parse.quote("mkdir {}".format(directory_created), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("mount {} {}".format("/dev/mock_fs", directory_created), safe=""), text=""
        )
        session_mock.post(
            run_url + urllib.parse.quote("cat {}/etc/hostname".format(directory_created), safe=""), text="mockhostname"
        )
        session_mock.post(run_url + urllib.parse.quote("touch {}".format(file_name_with_path), safe=""), text="")
        session_mock.post(
            run_url + urllib.parse.quote("chmod {} {}".format("755", file_name_with_path), safe=""), text=""
        )

        class_being_tested.execute(directory_created, file_name)

        message = "The following exposed existing privileged containers have been successfully"
        message += " abused by starting/modifying a process in the host."

        assert message in class_being_tested.event.evidence


HOST = "TESTHOST"
PUBLISHED_EVENTS = []


@handler.subscribe_once(ExposedLogsOnContainerFileSystem)
class OnceHunter(Hunter):
    def __init__(self, event):
        PUBLISHED_EVENTS.append(event)


class TestExposedLogsOnContainerFileSystemHunter:
    POD_NAMESPACE = "my_namespace"
    POD_ID = "my_id"
    CONTAINER_NAME = "my_c_name"

    class DummyEvent:
        def __init__(self):
            self.host = HOST
            self.session = requests.session()

    HUNTER = ExposedLogsOnContainerFileSystemHunter(DummyEvent())
    CONFIG = Config()

    def test__init__(self):
        assert self.HUNTER.base_url == f"https://{HOST}:10250"

    def test_find_all_pods(self):
        scenarios = {
            json.dumps({"should": "ignore"}): None,
            json.dumps({"items": [1, 2]}): [1, 2]
        }

        for scenario, expected_result in scenarios.items():
            with requests_mock.Mocker() as mock:
                mock.get(f"https://{HOST}:10250/pods", text=scenario)

                result = self.HUNTER._find_all_pods(self.CONFIG)
                assert result == expected_result

    def test_send_run_request(self):
        cmd = "my_cmd"

        def return_false(s):
            return False

        def return_true(s):
            return True

        scenarios = {
            ("", None): None,
            ("   ", None): None,
            ("Some String", None): "Some String",
            ("Some String", return_false): None,
            ("Some String", return_true): "Some String",
        }

        for scenario, expected_result in scenarios.items():
            with requests_mock.Mocker() as mock:
                mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                          f"cmd={cmd}", text=scenario[0])

                result = self.HUNTER._send_run_request(
                    config=self.CONFIG,
                    pod_namespace=self.POD_NAMESPACE,
                    pod_id=self.POD_ID,
                    container_name=self.CONTAINER_NAME,
                    cmd=cmd,
                    is_valid_response_func=scenario[1])

                assert result == expected_result

    def test_find_log_files(self):
        cmd = "find /var/log -type f -print"

        scenarios = {
            "": None,
            " No such file or directory ": None,
            " file1.log \n  file2.log \n  ": ["file1.log", "file2.log"]
        }

        for scenario, expected_result in scenarios.items():
            with requests_mock.Mocker() as mock:
                mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                          f"cmd={cmd}", text=scenario)

                result = self.HUNTER._find_log_files(self.CONFIG, self.POD_NAMESPACE, self.POD_ID, self.CONTAINER_NAME)
                assert result == expected_result

    def test_read_contents_of_file(self):
        log = "my.log"
        cmd = f"tail {log}"

        scenarios = {
            "": None,
            f"tail: {log}: Permission denied": None,
            "This text was in the file": "This text was in the file"
        }

        for scenario, expected_result in scenarios.items():
            with requests_mock.Mocker() as mock:
                mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                          f"cmd={cmd}", text=scenario)

                result = self.HUNTER._read_contents_of_file(
                    self.CONFIG, self.POD_NAMESPACE, self.POD_ID, self.CONTAINER_NAME, log_file=log)
                assert result == expected_result

    def test_find_contents_of_any_log_file_with_no_logs(self):
        with requests_mock.Mocker() as mock:
            mock.post(
                f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                f"cmd=find /var/log -type f -print",
                text="exited with 126")

            assert self.HUNTER._find_contents_of_any_log_file(
                self.CONFIG, self.POD_NAMESPACE, self.POD_ID, self.CONTAINER_NAME) == (None, None)

    def test_find_contents_of_any_log_file(self):
        with requests_mock.Mocker() as mock:
            mock.post(
                f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                f"cmd=find /var/log -type f -print",
                text="log1.log\nlog2.log")

            mock.post(
                f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                f"cmd=tail log1.log",
                text="tail: log1.log: Permission denied")

            mock.post(
                f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/{self.CONTAINER_NAME}?"
                f"cmd=tail log2.log",
                text="This is the contents of of the file")

            assert self.HUNTER._find_contents_of_any_log_file(
                self.CONFIG, self.POD_NAMESPACE, self.POD_ID, self.CONTAINER_NAME) == \
                ("log2.log", "This is the contents of of the file")

    def test_execute(self):
        PUBLISHED_EVENTS.clear()
        assert len(PUBLISHED_EVENTS) == 0

        pods_data = [
            # Should Ignore As No Containers
            {"metadata": {"namespace": "namespace_1", "name": "pod_id_1"}, "spec": {"containers": []}},

            # Should find the logs in container_2
            {"metadata": {"namespace": f"{self.POD_NAMESPACE}", "name": f"{self.POD_ID}"}, "spec": {
                "containers": [{"name": "container_1"}, {"name": "container_2"}]}},

            # Should ignore as we've already found a log in the above container
            {"metadata": {"namespace": f"{self.POD_NAMESPACE}_2", "name": f"{self.POD_ID}_2"}, "spec": {
                "containers": [{"name": "container_3"}, {"name": "container_4"}]}},
        ]

        with requests_mock.Mocker() as mock:
            mock.get(f"https://{HOST}:10250/pods", text=json.dumps({"items": pods_data}))

            mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/" +
                      f"container_1?cmd=find%20/var/log%20-type%20f%20-print", text="")
            mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/" +
                      f"container_2?cmd=find%20/var/log%20-type%20f%20-print", text="log1.log \n log2.log")

            mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/container_2?"
                      f"cmd=tail%20log1.log",
                      text="tail: log1.log: Permission denied")
            mock.post(f"https://{HOST}:10250/run/{self.POD_NAMESPACE}/{self.POD_ID}/container_2?"
                      f"cmd=tail%20log2.log",
                      text="file contents")

            self.HUNTER.execute()

            assert len(PUBLISHED_EVENTS) == 1
            assert PUBLISHED_EVENTS[0].vid == "KHV052"
            assert PUBLISHED_EVENTS[0].evidence == f"PodId: {self.POD_ID}, ContainerName: container_2, " \
                f"File: log2.log, Contents: file contents"
