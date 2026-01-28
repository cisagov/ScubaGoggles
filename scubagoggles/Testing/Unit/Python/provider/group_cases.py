"""
Parametrized test case data for group settings Provider methods.
"""

GET_GROUP_SETTINGS_CASES = [
    # Multiple groups returned
    (
        {
            "groups_list_return": [
                { "email": "user1.example.com" },
                { "email": "user2.example.com" },
            ],
            "directory_side_effect": None,
            "groups_side_effect": None,
            "groups_expected": [
                {
                    "kind": "groupsSettings#groups",
                    "email": "g1@scubagws.org",
                    "name": "Group 1",
                    "whoCanJoin": "INVITED_CAN_JOIN",
                },
                {
                    "kind": "groupsSettings#groups",
                    "email": "g2@scubagws.org",
                    "name": "Group 2",
                    "whoCanJoin": "INVITED_CAN_JOIN",
                },
            ]
        }
    ),
    # No groups returned
    (
        {
            "groups_list_return": [],
            "directory_side_effect": None,
            "groups_side_effect": None,
            "groups_expected": []
        }
    ),
    # Exception thrown when retrieving groups from Directory API
    (
        {
            "groups_list_return": None,
            "directory_side_effect": Exception("API error"),
            "groups_side_effect": None,
            "groups_expected": []
        }
    ),
    # Exception thrown when retrieving group settings from Groups Settings API
    (
        {
            "groups_list_return": [
                { "email": "user1.example.com" },
            ],
            "directory_side_effect": None,
            "groups_side_effect": Exception("API error"),
            "groups_expected": []
        }
    ),
]