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
    # Gemini Beta features use APPLICATION_NAME "Gemini in Workspace"
    {
        "products": ["si", "gmail"],
        "event": "CHANGE_APPLICATION_SETTING",
        "reports": [
            {
                "id": "gemini-beta",
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "APPLICATION_NAME",
                                "value": "Gemini in Workspace",
                            },
                        ]
                    }
                ]
            },
            {
                "id": "gemini-legacy",
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "APPLICATION_NAME",
                                "value": "Gemini in Workspace apps",
                            },
                        ]
                    }
                ]
            },
            {
                "id": "gmail",
                "events": [
                    {
                        "parameters": [
                            {"name": "APPLICATION_NAME", "value": "Gmail"},
                        ]
                    }
                ]
            },
        ],
        "expected": {
            "gmail": [
                {
                    "id": "gmail",
                    "events": [
                        {
                            "parameters": [
                                {"name": "APPLICATION_NAME", "value": "Gmail"},
                            ],
                        },
                    ],
                },
            ],
            "si": [
                {
                    "id": "gemini-beta",
                    "events": [
                        {
                            "parameters": [
                                {
                                    "name": "APPLICATION_NAME",
                                    "value": "Gemini in Workspace",
                                },
                            ],
                        },
                    ],
                },
                {
                    "id": "gemini-legacy",
                    "events": [
                        {
                            "parameters": [
                                {
                                    "name": "APPLICATION_NAME",
                                    "value": "Gemini in Workspace apps",
                                },
                            ],
                        },
                    ],
                },
            ],
        },
        "expect_warning": False,
    },
    # Google Meet Gemini settings use APPLICATION_NAME "Google Meet GenAI",
    # which belongs to the SI baseline rather than Meet
    {
        "products": ["si", "meet"],
        "event": "CHANGE_APPLICATION_SETTING",
        "reports": [
            {
                "id": "meet-genai",
                "events": [
                    {
                        "parameters": [
                            {
                                "name": "APPLICATION_NAME",
                                "value": "Google Meet GenAI",
                            },
                        ]
                    }
                ]
            },
            {
                "id": "meet",
                "events": [
                    {
                        "parameters": [
                            {"name": "APPLICATION_NAME", "value": "Google Meet"},
                        ]
                    }
                ]
            },
        ],
        "expected": {
            "si": [
                {
                    "id": "meet-genai",
                    "events": [
                        {
                            "parameters": [
                                {
                                    "name": "APPLICATION_NAME",
                                    "value": "Google Meet GenAI",
                                },
                            ],
                        },
                    ],
                },
            ],
            "meet": [
                {
                    "id": "meet",
                    "events": [
                        {
                            "parameters": [
                                {"name": "APPLICATION_NAME", "value": "Google Meet"},
                            ],
                        },
                    ],
                },
            ],
        },
        "expect_warning": False,
    },
    # Data regions settings apply to both Assured Controls and the Gemini
    # settings in the SI baseline, so each product receives the event
    {
        "products": ["assuredcontrols", "si"],
        "event": "CHANGE_APPLICATION_SETTING",
        "reports": [
            {
                "id": "data-regions",
                "events": [
                    {
                        "parameters": [
                            {"name": "APPLICATION_NAME", "value": "Data regions"},
                        ]
                    }
                ]
            },
        ],
        "expected": {
            "assuredcontrols": [
                {
                    "id": "data-regions",
                    "events": [
                        {
                            "parameters": [
                                {"name": "APPLICATION_NAME", "value": "Data regions"},
                            ],
                        },
                    ],
                },
            ],
            "si": [
                {
                    "id": "data-regions",
                    "events": [
                        {
                            "parameters": [
                                {"name": "APPLICATION_NAME", "value": "Data regions"},
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
