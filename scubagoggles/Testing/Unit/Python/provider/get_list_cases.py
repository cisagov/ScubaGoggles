"""
Parametrize test case data for get_list the Provider method.
"""

GET_LIST_CASES = [
    # Single page response
    {
        "pages": [
            {"items": ["item1", "item2", "item3"]}
        ],
        "item_key": "items",
        "expected": ["item1", "item2", "item3"],
    },
    # Multiple pages
    {
        "pages": [
            {"items": ["item1", "item2"]},
            {"items": ["item3", "item4"]},
            {"items": ["item5"]}
        ],
        "item_key": "items",
        "expected": ["item1", "item2", "item3", "item4", "item5"],
    },
    # Empty response (no items key)
    {
        "pages": [{}],
        "item_key": "items",
        "expected": [],
    },
    # Missing item key
    {
        "pages": [{"otherKey": ["data1", "data2"]}],
        "item_key": "items",
        "expected": [],
    },
]