"""
Tests for the PolicyAPI class.

"""
from pathlib import Path
from unittest.mock import Mock
import pytest
import dns
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
    
    """
    Test DOH Server Retrieval 
    """
    @pytest.mark.parametrize("subtest, expected", 
    [
        (1, "cloudflare-dns.com"),
        (2, "[2606:4700:4700::1111]"),
        (3, ""),
    ])
    def test_get_doh_server(self, mock_resolver, mock_requests_get, subtest, expected):
        robust_dns_client = RobustDNSClient()
        mock_resolver.assert_called()
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
    
    """
    Test DOH Query
    """
    @pytest.mark.parametrize("subtest, max_tries",
    [
        (1, 2),
        (2, 2),
        (3, 2),
        (4, 2),
        (5, 2),
        (6, 2),
        (7, 3),
        (8, 3)
    ])
    def test_doh_query(self, mocker, mock_resolver, mock_requests_get, subtest, max_tries):
        robust_dns_client = RobustDNSClient()
        mock_resolver.assert_called()
        doh_server_mock = mocker.patch('scubagoggles.robust_dns.RobustDNSClient.get_doh_server')
        query = "An example query."

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
            
            # Case where there is a valid server availible but Response is 0, 'Answer' IS NOT in the Json response
            case 2:
                mock_requests_get.return_value.json.return_value = {"Status" : 0}
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "Query returned 0 txt records",
                    "query_answers": []
                })
            
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
            
            # Case where there is a valid server availible but Response is 3
            case 4:
                mock_requests_get.return_value.json.return_value = {"Status" : 3}
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "Query returned NXDomain",
                    "query_answers": []
                })
            
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

            # Case where there is a valid server, Status code is 1 the first iteration, and 3 the second iteration.
            case 6:
                # Mock requests.Response() [Status 1]
                status_one_return = Mock(spec=requests.Response)
                status_one_return.json.return_value = {"Status" : 1}
                # Mock requests.Response() [Status 3]
                status_three_return = Mock(spec=requests.Response)
                status_three_return.json.return_value = {"Status" : 3}
                mock_requests_get.side_effect = [status_one_return, status_three_return]  #return values for the next two iterations

                # Expected return values for status code 1
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": f"Query returned response code 1",
                    "query_answers": []
                })
                errors.append(f"Response code 1")   

                # Expected return values for status code 3
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": "Query returned NXDomain",
                    "query_answers": []
                })

            # Exception case (from requests.get)
            case 7:
                mock_requests_get.side_effect = requests.exceptions.Timeout("time out")
                # append log entries from Exception
                for _ in range(max_tries):
                    log_entries.append({
                        "query_name": query,
                        "query_method": "DoH",
                        "query_result": f"Query resulted in exception time out",
                        "query_answers": []
                    })
                    errors.append(f"time out")

            # Exception occurs on First Iteration, but Status Code 3 occurs on next iteration
            case 8:
                status_three_return = Mock(spec=requests.Response)
                status_three_return.json.return_value = {"Status" : 3}
                mock_requests_get.side_effect = [requests.exceptions.Timeout("time out"), status_three_return]  #return values for the next two iterations

                # add log entries from Exception
                log_entries.append({
                    "query_name": query,
                    "query_method": "DoH",
                    "query_result": f"Query resulted in exception time out",
                    "query_answers": []
                })
                errors.append(f"time out")

                # add log entries from Status 3 Code
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
        #assert True == True
        assert robust_dns_client.doh_query(query, max_tries) == return_value




    """
    Test Traditional Query
    DELETE when done : MOCK of DNS Resolver MUST be implemented
    """
    @pytest.mark.parametrize("subtest, max_tries",
    [
        (1, 2),
        (2, 2),
        (3, 2),
        (4, 2),
        (5, 3)
    ])
    # NOTE : No need to have a different constructor for the nameservers attributes with mock-testing (document this in code)
    def test_traditional_query(self, mock_resolver, subtest, max_tries):
        robust_dns_client = RobustDNSClient()
        #mock_resolver.assert_called()
        query = "An example query."
        answers = []
        nxdomain = False
        errors = []
        log_entries = []
        expected = None  # collect expected result here
        resolver_instance = mock_resolver.return_value

        match subtest:
        # TEST CASE 1 : General Result Succeeded  (Loop count = 2)
            case 1:
                # Mock item in Mock DNS resolver return value  
                item_one = Mock()
                item_one.to_text.return_value = "127.0.0.1"
                item_two = Mock()
                item_two.to_text.return_value = "192.68.1.1"
                # Successful DNS resolver query
                resolver_instance.resolve.return_value = [item_one, item_two]
                answers = ["127.0.0.1", "192.68.1.1"]
                log_entries.append({
                    "query_name": query,
                    "query_method": "traditional",
                    "query_result": f"Query returned 2 txt records",
                    "query_answers": answers
                })
                robust_dns_client.traditional_query(query, max_tries)
                resolver_instance.resolve.assert_called()
        # TEST CASE 2 : dns.resolver.NoAnswer  (Loop count = 2)
            case 2:
                #simulate no answer
                resolver_instance.resolve.side_effect = dns.resolver.NoAnswer
                log_entries.append({
                    "query_name": query,
                    "query_method": "traditional",
                    "query_result": "Query returned 0 txt records",
                    "query_answers": []
                })
        # TEST CASE 3 : dns.resolver.NXDOMAIN  (Loop count = 2)
            case 3:
                resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN
                log_entries.append({
                    "query_name": query,
                    "query_method": "traditional",
                    "query_result": "Query returned NXDOMAIN",
                    "query_answers": []
                })
                nxdomain = True
        # TEST CASE 4 : General Exception   (Loop count = 2)
            case 4:
                exception = dns.resolver.Timeout("Timeout")
                resolver_instance.resolve.side_effect = exception
                # The query failed, possibly a transient failure. Retry if we haven't reached
                # max_tries.
                for _ in range(max_tries):
                    log_entries.append({
                        "query_name": query,
                        "query_method": "traditional",
                        "query_result": f"Query resulted in exception Timeout",
                        "query_answers": []
                    })
                    errors.append("Timeout")
        # TEST CASE 5 : General Exception   +   Result Succeeded (Loop count = 3)
            case 5:
                exception = dns.resolver.Timeout("Timeout")
                resolver_instance.resolve.side_effect = [exception, dns.resolver.NoAnswer]
                # The query failed, possibly a transient failure. Retry if we haven't reached
                # max_tries.
                # First Loop
                log_entries.append({
                    "query_name": query,
                    "query_method": "traditional",
                    "query_result": f"Query resulted in exception Timeout",
                    "query_answers": []
                })
                errors.append("Timeout")

                # Second loop
                log_entries.append({
                    "query_name": query,
                    "query_method": "traditional",
                    "query_result": "Query returned 0 txt records",
                    "query_answers": []
                })
                # Then Break
        
        # Expected Result
        expected = {
            "answers": answers,
            "nxdomain": nxdomain,
            "log_entries": log_entries,
            "errors": errors
        }
        assert robust_dns_client.traditional_query(query, max_tries) == expected


    """
    Test  Query
    """
    @pytest.mark.parametrize("subtest, max_tries",
    [
        (1, 2),     # Note : max_tries for these test cases is mostly irrelevant here,
        #(2, 2),     # since in-class methods traditional_query and doh_query are being mocked
        #(3, 2),
    ])
    def test_query(self, mocker, mock_resolver, subtest, max_tries):
        assert True
        query = "An example query."
        robust_dns_client = None
        traditional_query_mock = None

        match subtest:
        # TEST CASE 1 : Traditional Query Succeeded, No need for DOH Query
            case 1:
                robust_dns_client = RobustDNSClient()
                mock_resolver.assert_called()
                # Set up constructor as normal (regular instance)
                traditional_query_mock = mocker.patch('scubagoggles.robust_dns.RobustDNSClient.traditional_query')
                expected = {
                    "answers": ["127.0.0.1", "192.68.1.1"],
                    "nxdomain": False,
                    "log_entries": [],
                    "errors": []
                }
                traditional_query_mock.return_value = expected
        # TEST CASE 2 : Traditional Query Failed, Retry with DOH Query
            case 2:
                robust_dns_client = RobustDNSClient()
                # Set up constructor as normal (regular instance)
                # Mock Traditional Query
                # Mock DOH Query
        # TEST CASE 3 : Traditional Query Failed, Do not with DOH Query as skip_doh_query = True
            case 3:
                robust_dns_client = RobustDNSClient(skip_doh = True)
                # Set up constructor with skip_doh_query = True
                # Traditional Query needs to be mocked
                # Traditional Query Fails
        
        # Test Case Assertion
        #print(robust_dns_client.query(query, max_tries))
        #print("\n")
        #print(expected)
        #print("\n")
        #assert True
        assert robust_dns_client.query(query, max_tries) == expected            
