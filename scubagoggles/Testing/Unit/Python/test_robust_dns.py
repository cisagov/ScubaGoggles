"""
Tests for the PolicyAPI class.

"""
from pathlib import Path
from unittest.mock import Mock
import pytest
import requests
from scubagoggles.robust_dns import RobustDNSClient

class TestRobustDNSClient:

    """Mocks the GwsAuth class - the tests in this module do not call any
    Google API.
    """
    # Convienient fixture
    @pytest.fixture
    def mock_resolver(self, mocker):
        return mocker.patch('scubagoggles.robust_dns.dns.resolver.Resolver')

    @pytest.fixture
    def mock_requests_get(self, mocker):
        return mocker.patch('scubagoggles.robust_dns.requests.get')

    @pytest.mark.parametrize("subtest, expected", 
    [
        (1, "cloudflare-dns.com"),
        (2, "[2606:4700:4700::1111]"),
        (3, ""),
    ])
    def test_get_doh_server(self, mock_requests_get, subtest, expected):
        robust_dns_client = RobustDNSClient()
        match subtest:
            # The first server works as intended (cloudflare-dns.com)
            case 1:
                mock_requests_get.return_value.json.return_value = {"status": "ok"} # aribtrary return value, doesn't matter
                assert robust_dns_client.get_doh_server() == expected
            # Only the second server is valid ([2606:4700:4700::1111])
            case 2:
                good_return = Mock(spec=requests.Response)
                good_return.json.return_value = {"status": "ok"}
                mock_requests_get.side_effect = [requests.exceptions.Timeout, good_return] #first server fails, second server returns successfully
                assert robust_dns_client.get_doh_server() == expected
            # none of the servers are availible
            case 3:
                mock_requests_get.side_effect = requests.exceptions.Timeout
                assert robust_dns_client.get_doh_server() is None
    

    @pytest.mark.parametrize("subtest, query, max_tries",
    [
        (1, "example_query", 2),
        (2, "example_query", 2),
        (3, "example_query", 2),
        (4, "example_query", 2),
        (5, "example_query", 2),
    ])
    def test_doh_query(self, mocker, mock_requests_get, subtest, query, max_tries):
        robust_dns_client = RobustDNSClient()
        doh_server_mock = mocker.patch('scubagoggles.robust_dns.RobustDNSClient.get_doh_server')
        
        # setup for doh_query return value
        answers = []
        nxdomain = False
        errors = []
        log_entries = []

        # valid working server example (valid for all the cases except the first test case)
        doh_server_mock.return_value = "cloudflare-dns.com"

        match subtest:
            # Case where no servers are availible:
            case 1:
                # no server availible
                doh_server_mock.return_value = None
                # mock the response of the get_doh_server function
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "NA, DoH servers unreachable",
                    "query_answers": []
                })
                return_value = {
                    "answers": answers,
                    "nxdomain": nxdomain,
                    "log_entries": log_entries,
                    "errors": errors
                }
                assert robust_dns_client.doh_query(query, max_tries) == return_value
            # Case where there is a valid server availible but Response is 0, 'Answer' IS NOT in the Json response
            case 2:
                mock_requests_get.return_value.json.return_value = {"Status" : 0}
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "Query returned 0 txt records",
                    "query_answers": []
                })
                return_value = {
                    "answers": answers,
                    "nxdomain": nxdomain,
                    "log_entries": log_entries,
                    "errors": errors
                }
                assert robust_dns_client.doh_query(query, max_tries) == return_value
            # Case where there is a valid server availible but Response is 0, 'Answer' IS in the Json response
            case 3:
                # Answers exists in json response (3 answers)
                json_answer_array = [{"data": "\"An answer with quotes, to be removed.\""}, 
                 {"data": "A quote-free answer"}, 
                 {"data": ""}]
                mock_requests_get.return_value.json.return_value = {"Status" : 0, "Answer": json_answer_array}
                # expected answers (double-quotes removed)
                answers = ["An answer with quotes, to be removed.", "A quote-free answer", ""]
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": f"Query returned 3 txt records",
                    "query_answers": answers
                })
                return_value = {
                    "answers": answers,
                    "nxdomain": nxdomain,
                    "log_entries": log_entries,
                    "errors": errors
                }
                assert robust_dns_client.doh_query(query, max_tries) == return_value
            # Case where there is a valid server availible but Response is 3
            case 4:
                mock_requests_get.return_value.json.return_value = {"Status" : 3}
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "Query returned NXDomain",
                    "query_answers": []
                })
                return_value = {
                    "answers": answers,
                    "nxdomain": nxdomain,
                    "log_entries": log_entries,
                    "errors": errors
                }
                assert robust_dns_client.doh_query(query, max_tries) == return_value
            # Case where there is a valid server and the Status code is non-Zero and not 3
            case 5:
                mock_requests_get.return_value.json.return_value = {"Status" : 1}  # non-zero Status code and Status code is not 1
                # 2 tries
                for _ in range(max_tries):
                    log_entries.append({
                        "query_name": query,
                        "query_method": "DoH",
                        "query_result": f"Query returned response code 1",
                        "query_answers": []
                    })
                    errors.append(f"Response code 1")
                return_value = {
                    "answers": answers,
                    "nxdomain": nxdomain,
                    "log_entries": log_entries,
                    "errors": errors
                }
                assert robust_dns_client.doh_query(query, max_tries) == return_value
            # Exception occurs on the first iteration 
            case 6:
                assert True
            # Exception occurs on second iteration
            case 7:
                assert True
            