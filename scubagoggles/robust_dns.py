'''Code for running robust DNS queries, including logic for retries over both the traditional DNS
as well as DNS over HTTPS (DoH)'''

import json
import dns.resolver
import requests

class RobustDNSClient:
    '''Class used to run robust DNS queries.'''
    def __init__(self):
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
        # First attempt the query over traditional DNS
        result = self.traditional_query(qname, max_tries)
        success = result['success']
        trad_empty = result['trad_empty']
        answers = result['answers']
        log_entries = result['log_entries']

        if not success:
            # The traditional DNS query(ies) failed. Retry with DoH
            result = self.doh_query(qname, max_tries)
            success = result['success']
            answers.extend(result['answers'])
            log_entries.extend(result['log_entries'])

        # There are three possible outcomes of this function:
        # - Full confidence: we know conclusively that the domain exists or not, either via a
        # non-empty answer from traditional DNS or an answer from DoH.
        # - Medium confidence: domain likely doesn't exist, but there is some doubt (empty answer
        # from traditonal DNS and DoH failed).
        # No confidence: all queries failed. Throw an exception in this case.
        if success:
            return {"Answers": answers, "HighConfidence": True, "LogEntries": log_entries}
        if trad_empty:
            return {"Answers": answers, "HighConfidence": False, "LogEntries": log_entries}
        log = '\n'.join([json.dumps(entry) for entry in log_entries])
        raise Exception(f"Failed to resolve {qname}. \n{log}")

    def traditional_query(self, qname : str, max_tries : int) -> dict:
        '''
        Requests the TXT record for the given qname over DoH.

            :param qname: The query name (ie domain name).
            :param max_tries: The number of times to retry the query.
        '''
        try_number = 0
        answers = []
        log_entries = []
        success = False
        trad_empty = False

        while try_number < max_tries:
            try_number += 1
            try:
                # No exception was thrown, we got our answer, so break out of the retry loop and
                # set success to True, no need to retry the traditional query or retry with DoH.
                response = dns.resolver.resolve(qname, "TXT")
                for answer in response:
                    answers.append(answer.to_text().strip('"')) # Strip
                    # the quotes because the actual response comes wrapped in
                    # quotes, resulting in duplicate quotes in the json output
                success = True
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": f"Query returned {len(response)} txt records"})
                break
            except dns.resolver.NoAnswer:
                # The answer section was empty. This usually means that while the domain exists,
                # but there are no records of the requested type. No need to retry the traditional
                # query, this was not a transient failure. Don't set success to True though, as we
                # want to retry this query from a public resolver, in case the internal DNS server
                # returns a different answer than what is served to the public (i.e., split horizon
                # DNS).
                trad_empty = True
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": "Query returned 0 txt records"})
                break
            except dns.resolver.NXDOMAIN:
                # The server returned NXDomain, no need to retry the traditional query or retry
                # with DoH, this was not a transient failure. Break out of loop and set success to
                # True
                success = True
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": "Query returned NXDOMAIN"})
                break
            except Exception as exception:
                # The query failed, possibly a transient failure. Retry if we haven't reached
                # max_tries.
                log_entries.append({
                    "query_name": qname,
                    "query_method": "traditional",
                    "query_result": f"Query resulted in exception {exception}"})

        return {
            "success": success,
            "trad_empty": trad_empty,
            "answers": answers,
            "log_entries": log_entries
        }

    def get_doh_server(self) -> str:
        """Iterates through several DoH servers. Returns the first successful server.
        If none are successful, returns None.
        """
        doh_servers = ["cloudflare-dns.com", "[2606:4700:4700::1111]", "1.1.1.1"]
        preferred_server = None
        for server in doh_servers:
            try:
                # Attempt to resolve a.root-servers.net over DoH. The domain chosen is somewhat
                # arbitrary, as we don't care what the answer is, only if the query succeeds/fails.
                # a.root-servers.net, the address of one of the DNS root servers, was chosen as a
                # benign, highly-available domain.
                uri = f"https://{server}/dns-query?name=a.root-servers.net"
                headers = {"accept":"application/dns-json"}
                requests.get(uri, headers=headers, timeout=2).json()
                # No error was thrown, return this server
                preferred_server = server
                break
            except Exception: # pylint: disable=broad-except
                # This server didn't work, try the next one
                continue
        return preferred_server

    def doh_query(self, qname : str, max_tries : int) -> dict:
        '''
        Requests the TXT record for the given qname over DoH.

        :param qname: The query name (ie domain name).
        :param max_tries: The number of times to retry the query.
        '''
        log_entries = []
        try_number = 0
        answers = []
        success = False

        if self.doh_server == "":
            self.doh_server = self.get_doh_server()
        if self.doh_server is None:
            # None of the DoH servers are accessible
            log_entries.append({
                "query_name": qname,
                "query_method": "DoH",
                "query_result": "NA, DoH servers unreachable"
            })
        else:
            # DoH is available, query for the domain
            while try_number < max_tries:
                try_number += 1
                uri = f"https://{self.doh_server}/dns-query?name={qname}&type=txt"
                headers = {"accept":"application/dns-json"}
                try:
                    response = requests.get(uri, headers=headers, timeout=5).json()
                    if response['Status'] == 0:
                        # 0 indicates there was no error
                        if 'Answer' in response:
                            nanswers = len(response['Answer'])
                            log_entries.append({
                                "query_name": qname,
                                "query_method": "DoH",
                                "query_result": f"Query returned {nanswers} txt records"})
                            for answer in response['Answer']:
                                answers.append(answer['data'].replace('"', ''))
                        else:
                            # Edge case where the domain exists but there are no txt records
                            log_entries.append({
                                "query_name": qname,
                                "query_method": "DoH",
                                "query_result": "Query returned 0 txt records"})
                        success = True
                        break
                    if response['Status'] == 3:
                        # 3 indicates NXDomain. The DNS query succeeded, but the domain did not
                        # exist. Set success to True, because event though the domain does not
                        # exist, the query succeeded, and this came from an external resolver so
                        # split horizon is not an issue here.
                        log_entries.append({
                            "query_name": qname,
                            "query_method": "DoH",
                            "query_result": "Query returned NXDomain"})
                        success = True
                        break
                    # The remainder of the response codes indicate that the query did not succeed.
                    # Retry if we haven't reached max_tries.
                    log_entries.append({
                        "query_name": qname,
                        "query_method": "DoH",
                        "query_result": f"Query returned response code {response['Status']}"})
                except Exception as exception:
                    # The DoH query failed, likely due to a network issue. Retry if we haven't
                    # reached max_trues.
                    log_entries.append({
                        "query_name": qname,
                        "query_method": "DoH",
                        "query_result": f"Query resulted in exception {exception}"})
        return {"success": success, "answers": answers, "log_entries": log_entries}
