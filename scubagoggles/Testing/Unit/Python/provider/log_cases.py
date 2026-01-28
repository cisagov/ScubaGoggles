"""
Parametrized test case data for GWS logs Provider methods.
"""

GET_GWS_LOGS_CASES = [
    # Non-matching event
    {
        "products": ["gmail", "drive"],
        "event": "SOME_OTHER_EVENT",
        "reports": [
            { "id": "meet", "events": [] },
            { "id": "classroom", "events": [] },
        ],
        "expected": {
            "gmail": [
                { "id": "meet", "events": [] },
                { "id": "classroom", "events": [] },
            ],
            "drive": [
                { "id": "meet", "events": [] },
                { "id": "classroom", "events": [] },
            ],
        },
        "expect_warning": False,
    },
    # CHANGE_APPLICATION_SETTING with matching apps
    {
        "products": ["gmail", "drive"],
        "event": "CHANGE_APPLICATION_SETTING",
        "reports": [
            {
                "id": "gmail",
                "events": [
                    {
                        "parameters": [
                            { "name": "APPLICATION_NAME", "value": "Gmail"},
                        ]
                    }
                ]
            },
            {
                "id": "drive",
                "events": [
                    {
                        "parameters": [
                            { "name": "APPLICATION_NAME", "value": "Drive and Docs"},
                        ]
                    }
                ]
            },
            {
                "id": "no_match",
                "events": [
                    {
                        "parameters": [
                            { "name": "APPLICATION_NAME", "value": "Calendar"},
                        ]
                    }
                ]
            }
        ],
        "expected": {
            "gmail": [
                {
                    "id": "gmail",
                    "events": [
                        {
                            "parameters": [
                                { "name": "APPLICATION_NAME", "value": "Gmail"},
                            ]
                        }
                    ]
                }
            ],
            "drive": [
                {
                    "id": "drive",
                    "events": [
                        {
                            "parameters": [
                                { "name": "APPLICATION_NAME", "value": "Drive and Docs"},
                            ]
                        }
                    ]
                }
            ],
        },
        "expect_warning": False,
    },
    # DELETE_APPLICATION_SETTING with only marketplace app
    {
        "products": ["commoncontrols", "gmail"],
        "event": "DELETE_APPLICATION_SETTING",
        "reports": [
            {
                "id": "marketplace",
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "APPLICATION_NAME",
                                "value": "Google Workspace Marketplace"
                            },
                        ]
                    }
                ]
            }
        ],
        "expected": {
            "gmail": [],
            "commoncontrols": [
                {
                    "id": "marketplace",
                    "events": [
                        {
                            "parameters": [
                                {
                                    "name": "APPLICATION_NAME",
                                    "value": "Google Workspace Marketplace"
                                },
                            ],
                        },
                    ],
                },
            ],
        },
        "expect_warning": False,
    },
    # Exception thrown when trying to retrieve logs
    {
        "products": ["gmail", "drive"],
        "event": "CHANGE_APPLICATION_SETTING",
        "reports": [{}],
        "expected": {
            "gmail": [],
            "drive": [],
        },
        "expect_warning": True,
    },
]