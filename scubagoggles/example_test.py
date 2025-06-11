# Invoke with: pytest .\example_test.py

from scubagoggles.reporter.reporter import Reporter
from scubagoggles.robust_dns import RobustDNSClient

import xml.etree.ElementTree as ET
from unittest.mock import patch, MagicMock
import pytest


# Helper functions for processing XML (or HTML)
def load_xml_string(raw_xml: str) -> ET.Element:
    '''
    Helper function, loads the given string and returns a parsed XML element.
    '''
    return ET.ElementTree(ET.fromstring(raw_xml)).getroot()


def elements_equal(e1: ET.Element, e2: ET.Element) -> bool:
    '''
    Helper function, checks to see if the two XML elements are equivalent.
    Note that the order of any child elements matters.
    '''
    if e1 is None and e2 is None:
        return True
    if e1 is None or e2 is None:
        return False
    if e1.tag != e2.tag:
        return False
    if e1.text != e2.text:
        if e1.text is not None and e2.text is not None:
            return False
    if e1.tail != e2.tail:
        if e1.tail is not None and e2.tail is not None:
            return False
    if e1.attrib != e2.attrib:
        return False
    if len(e1) != len(e2):
        return False
    return all(elements_equal(c1, c2) for c1, c2 in zip(e1, e2))


# Basic example test
# Pytest assumes any function that starts with "test_" is a unit case
def test_create_table():
    data = [{"a": 1, "b": 2}, {'a': 3, 'b': 4}]
    expected = load_xml_string(("<table><thead><tr><th>a</th><th>b</th></tr>"
                                "</thead><tbody><tr><td>1</td><td>2</td></tr>"
                                "<tr><td>3</td><td>4</td></tr></tbody></table>"))
    actual = load_xml_string(Reporter.create_html_table(data))
    assert elements_equal(expected, actual)


# Example showing how you could test a lot of different combinations at once
@pytest.mark.parametrize(
    "requirement_met,criticality,no_such_events,expected",
    [
        (True, "Shall", False, "Pass"),
        (False, "Shall", False, "Fail"),
        (False, "Should", False, "Warning"),
        (False, "Should/Not-Implemented", False, "N/A"),
        (False, "Shall/Not-Implemented", False, "N/A"),
        (False, "Should/Not-Implemented", True, "N/A"),
        (False, "Shall/Not-Implemented", True, "N/A"),
        (False, "Shall/3rd Party", False, "N/A"),
        (False, "Should/3rd Party", False, "N/A"),
        (False, "Should", True, "No events found"),
        (True, "Should", True, "No events found"),
    ]
)
def test_get_test_result(requirement_met: bool, criticality: str,
                         no_such_events: bool, expected: str):
    assert Reporter._get_test_result(requirement_met, criticality,
                                          no_such_events) == expected


# Example showing how you would "mock" external dependencies, like DNS queries
# or API calls
@patch('dns.resolver.resolve')
def test_dns(resolve_mock):
    mock_answer1 = MagicMock()
    mock_answer1.to_text.return_value = "answer1"
    mock_answer2 = MagicMock()
    mock_answer2.to_text.return_value = "answer2"
    resolve_mock.return_value = [mock_answer1, mock_answer2]
    client = RobustDNSClient()
    answer = client.traditional_query('example.com', 1)
    assert answer["success"]
    assert answer['answers'] == ["answer1", "answer2"]
    assert not answer['trad_empty']