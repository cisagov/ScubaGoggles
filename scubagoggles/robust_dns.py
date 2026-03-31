'''Code for running robust DNS queries, including logic for retries over both the traditional DNS
as well as DNS over HTTPS (DoH)'''

import dns
from dns import resolver
import requests
import re

class RobustDNSClient:
    '''Class used to run robust DNS queries.'''
    def __init__(self, dns_resolvers: list = None, doh_servers: list = None,
                skip_doh: bool = False):
        """
        Initialize the DNS client.

        :param dns_resolvers: (optional) list of DNS resolvers that should be
            used for DNS queries.
        :param doh_servers: (optional) list of DoH servers that should be used 
            for DoH queries.
        :param skip_doh: (optional) whether or not failed DNS queries should be
            retried over DoH.
        """
        self.resolver = resolver.Resolver()
        if dns_resolvers:
            self.resolver.nameservers = dns_resolvers

        self.preferred_doh_list = doh_servers

        self.skip_doh = skip_doh

        # doh_server is a variable used to indicate the preferred DoH server.
        # Initialize to empty string to indicate that we don't yet know the
        # preferred server. Will be set when the Select-DohServer function is
        # called.
        self.doh_server = ""

    def query(self, qname : str, max_tries : int = 2) -> dict:
        '''
        Requests the TXT record for the given qname. First tries to make
        the query over traditional DNS but retries over DoH in the event of
        failure.

        :param qname: The query name (ie domain name).
        :param max_tries: The number of times to retry each kind of query.
                If all queries are unsuccessful, the traditional queries and
                the DoH queries will each be made $MaxTries times. Default 2.
        '''
        results = {
            "answers": [],
            "nxdomain": False,
            "log_entries": [],
            "errors": []
        }
        # First attempt the query over traditional DNS
        trad_result = self.traditional_query(qname, max_tries)
        results['answers'].extend(trad_result['answers'])
        results['nxdomain'] = trad_result['nxdomain']
        results['log_entries'].extend(trad_result['log_entries'])
        results['errors'].extend(trad_result['errors'])

        if len(results['answers']) == 0 and not self.skip_doh:
            # The traditional DNS query(ies) failed. Retry with DoH
            doh_result = self.doh_query(qname, max_tries)
            results['answers'].extend(doh_result['answers'])
            results['nxdomain'] = doh_result['nxdomain']
            results['log_entries'].extend(doh_result['log_entries'])
            results['errors'].extend(doh_result['errors'])

        return results

    def traditional_query(self, qname : str, max_tries : int) -> dict:
        '''
        Requests the TXT record for the given qname over DoH.

            :param qname: The query name (ie domain name).
            :param max_tries: The number of times to retry the query.
        '''
        answers = []
        nxdomain = False
        errors = []
        log_entries = []

        try_number = 0
        while try_number < max_tries:
            try_number += 1
            try:
                # No exception was thrown, we got our answer, so break out of the retry loop
                response = self.resolver.resolve(qname, "TXT")
                for answer in response:
                    answers.append(answer.to_text().strip('"')) # Strip
                    # the quotes because the actual response comes wrapped in
                    # quotes, resulting in duplicate quotes in the json output
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": f"Query returned {len(response)} txt records",
                    "query_answers": answers
                })
                break
            except resolver.NoAnswer:
                # The answer section was empty. This usually means that while
                # the domain exists, but there are no records of the requested
                # type. No need to retry the traditional query, this was not a
                # transient failure. We do want to retry this query from a
                # public resolver, in case the internal DNS server returns a
                # different answer than what is served to the public (i.e.,
                # split horizon DNS).
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": "Query returned 0 txt records",
                    "query_answers": []
                })
                break
            except resolver.NXDOMAIN:
                # The server returned NXDomain, no need to retry the traditional query or retry
                # with DoH, this was not a transient failure.
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": "Query returned NXDOMAIN",
                    "query_answers": []
                })
                nxdomain = True
                break
            except Exception as exception:
                # The query failed, possibly a transient failure. Retry if we haven't reached
                # max_tries.
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": f"Query resulted in exception {exception}",
                    "query_answers": []
                })
                errors.append(str(exception))

        return {
            "answers": answers,
            "nxdomain": nxdomain,
            "log_entries": log_entries,
            "errors": errors
        }

    def get_doh_server(self) -> str:
        """Iterates through several DoH servers. Returns the first successful server.
        If none are successful, returns None.
        """
        doh_servers = ["cloudflare-dns.com", "2606:4700:4700::1111", "1.1.1.1"]

        if self.preferred_doh_list is not None:
            doh_servers = self.preferred_doh_list

        preferred_server = None
        for server in doh_servers:
            try:

                # Add square brackets if the DoH server is an IPv6
                pattern = r"^[0-9a-fA-F]{4}(:[0-9a-fA-F]{4}){3}$"
                if re.match(pattern, server):
                    server = "[" + server + "]"

                uri = f"https://{server}/dns-query"

                # Attempt to resolve DoH server if no preferred list is specified.
                # The domain chosen is somewhat arbitrary, as we don't care what the answer is,
                # only if the query succeeds/fails.

                query = dns.message.make_query(uri, dns.rdatatype.TXT)
                response = dns.query.https(query, uri, timeout=5)
                rcode = response.rcode()

                # No error was thrown, return this server
                if rcode == dns.rcode.NOERROR:
                    preferred_server = server
                    break

            except Exception: # pylint: disable=broad-except
                # This server didn't work, try the next one
                continue
        return preferred_server

    def doh_query(self, qname : str, max_tries : int, dohpath : str = "dns-query") -> dict:
        '''
        Requests the TXT record for the given qname over DoH.

        :param qname: The query name (ie domain name).
        :param max_tries: The number of times to retry the query.
        '''
        answers = []
        nxdomain = False
        errors = []
        log_entries = []

        if self.doh_server == "":
            self.doh_server = self.get_doh_server()
        if self.doh_server is None:
            # None of the DoH servers are accessible
            log_entries.append({
                "query_name": qname,
                "query_method": "DoH",
                "query_result": "NA, DoH servers unreachable",
                "query_answers": []
            })
            return {
                "answers": answers,
                "nxdomain": nxdomain,
                "log_entries": log_entries,
                "errors": errors
            }

        # Add square brackets if the selected DoH server is an IPv6
        pattern = r"^[0-9a-fA-F]{4}(:[0-9a-fA-F]{4}){3}$"
        if re.match(pattern, self.doh_server):
            self.doh_server = "[" + self.doh_server + "]"

        # DoH is available, query for the domain
        try_number = 0
        while try_number < max_tries:
            try_number += 1

            # form the DoH query
            qname = f"https://{self.doh_server}/{dohpath}"

            #headers = {"accept":"application/dns-json"}
            try:

                #response = requests.get(uri, headers=headers, timeout=5).json()
                # True DoH
                query = dns.message.make_query(qname, dns.rdatatype.TXT)
                response = dns.query.https(query, qname, timeout=5)
                rcode = response.rcode()

                if rcode == dns.rcode.NOERROR:
                    # 0 indicates there was no error

                    # need to iterate across all answer sets
                    # to get the number of answers
                    nanswers = 0
                    for answer_set in response.answer:
                        nanswers += len(answer_set)
                        for rdata in answer_set:
                            answers.append(rdata.to_text().replace('"', ''))
                    # Add all the answers to the log_queries list
                    log_entries.append({
                        "query_name": qname,
                        "query_method": "DoH",
                        "query_result": f"Query returned {nanswers} txt records",
                        "query_answers": answers
                    })
                    break

                if rcode == dns.rcode.NXDOMAIN:
                    # 3 indicates NXDomain. The DNS query succeeded, but the domain did not
                    # exist.
                    log_entries.append({
                        "query_name": qname,
                        "query_method": "DoH",
                        "query_result": "Query returned NXDomain",
                        "query_answers": []
                    })
                    break

                # The remainder of the response codes indicate that the query did not succeed.
                # Retry if we haven't reached max_tries.
                log_entries.append({
                    "query_name": qname,
                    "query_method": "DoH",
                    "query_result": f"Query returned response code {rcode}",
                    "query_answers": []
                })
                errors.append(f"Response code {rcode}")

            # Catch Generic Exception when attempting DoH query
            except Exception as exception:
                # The DoH query failed, likely due to a network issue. Retry if we haven't
                # reached max_trues.
                log_entries.append({
                    "query_name": qname,
                    "query_method": "DoH",
                    "query_result": f"Query resulted in exception {exception}",
                    "query_answers": []
                })
                errors.append(str(exception))
        return {
            "answers": answers,
            "nxdomain": nxdomain,
            "log_entries": log_entries,
            "errors": errors
        }
