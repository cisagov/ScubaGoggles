/**
 * Adds the red, green, yellow, and gray coloring to the individual report pages.
 */
const colorRows = () => {
    let rows = document.querySelectorAll('tr');
    // consts for the generic results rows
    const requirementCol = 1;
    const statusCol = 2;
    const criticalityCol = 3;

    // const for the alerts rows
    const alertStatusCol = 2;

    for (let i = 0; i < rows.length; i++) {
        try {
            if (rows[i].children.length == 3) {
                // This row is in the Alerts table
                if (rows[i].children[alertStatusCol]?.innerHTML === "Enabled") {
                    rows[i].style.background = "var(--test-pass)";
                }
                else if (rows[i].children[alertStatusCol]?.innerHTML === "Disabled") {
                    rows[i].style.background = "var(--test-fail)";
                }
                else if (rows[i].children[alertStatusCol]?.innerHTML === "Unknown") {
                    rows[i].style.background = "var(--test-other)";
                }
            }
            else {
                // This row is in one of the generic results rows
                if (rows[i].children[requirementCol]?.innerHTML.startsWith("[DELETED]")) {
                    rows[i].style.color = "var(--test-deleted-color)";
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol]?.innerHTML === "Fail") {
                    rows[i].style.background = "var(--test-fail)";
                }
                else if (rows[i].children[statusCol]?.innerHTML.includes("No events found")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol]?.innerHTML === "Warning") {
                    rows[i].style.background = "var(--test-warning)";
                }
                else if (rows[i].children[statusCol]?.innerHTML === "Pass") {
                    rows[i].style.background = "var(--test-pass)";
                }
                else if (rows[i].children[statusCol]?.innerHTML === "Omitted") {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol]?.innerHTML === "Incorrect result") {
                    if (rows[i].children[criticalityCol]?.innerHTML === "Shall") {
                        rows[i].style.background = "linear-gradient(to right, var(--test-fail), var(--test-pass))";
                    }
                    else if (rows[i].children[criticalityCol]?.innerHTML === "Should") {
                        rows[i].style.background = "linear-gradient(to right, var(--test-warning), var(--test-pass))";
                    }
                    else {
                        // This should never happen
                        console.log(`Unexpected criticality for incorrect result, ${rows[i].children[criticalityCol]?.innerHTML}.`);
                    }
                }
                else if (rows[i].children[criticalityCol]?.innerHTML.includes("Not-Implemented")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[criticalityCol]?.innerHTML.includes("3rd Party")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol]?.innerHTML.includes("Error")) {
                    rows[i].style.background = "var(--test-fail)";
                    rows[i].querySelectorAll('td')[statusCol].style.borderColor = "var(--border-color)";
                    rows[i].querySelectorAll('td')[statusCol].style.color = "#d10000";
                }
            }
        }
        catch (error) {
            console.error(`Error in colorRows, i = ${i}`);
            console.error(error);
        }
    }
}

/**
 * Toggles light and dark mode.
 */
const toggleDarkMode = () => {
    const inputToggle = document.getElementById("toggle");
    if (inputToggle.checked === true) {
        setDarkMode("true");
        return;
    }
    setDarkMode("false");
}

/**
 * Returns the value for the given setting from session storage. Returns
 * undefined if it does not exist.
 * @param {string} setting sgr_settings option to read
 */
const getSetting = (setting) => {
    if (!setting) {
        return undefined;
    }
    let reportSettings = sessionStorage.getItem("sgr_settings");
    if (reportSettings === null || reportSettings === undefined) {
        return undefined;
    }
    return JSON.parse(reportSettings)[setting];
}

/**
 * Updates the report settings object in session storage.
 * @param {string} option sgr_settings option to update
 * @param {string} value update value for sgr_settings option
 */
const updateSettings = (option, value) => {
    let settings = {};
    if ("sgr_settings" in sessionStorage) {
        settings = JSON.parse(sessionStorage.getItem("sgr_settings"));
    }
    settings[option] = value;
    sessionStorage.setItem("sgr_settings", JSON.stringify(settings));
}

/**
 * Set the report CSS to light mode or dark mode.
 * @param {string} state true for Dark Mode or false for Light Mode
 */
const setDarkMode = (state) => {
    const darkModeToggle = document.getElementById("toggle");

    if (state === "true") {
        document.querySelectorAll("html")[0].dataset.theme = "dark";
        document.querySelector("#toggle-text").innerHTML = "Dark Mode";
        updateSettings("darkMode", "true");
        darkModeToggle.checked = true;
        return;
    }

    document.querySelectorAll("html")[0].dataset.theme = "light";
    document.querySelector("#toggle-text").innerHTML = "Light Mode";
    updateSettings("darkMode", "false");
    darkModeToggle.checked = false;
}

/**
 * Sets the dark mode according to the setting stored in session storage, the
 * --darkmode CLI arg, and the system preference (in that order of precedence)
 */
const mountDarkMode = () => {
    // First, check session storage to see if dark mode has already been
    // enabled or disabled. If it has, this is what should take precedence.
    // "darkMode" setting will either be "true", "false", or undefined
    const darkModeSessionVariable = getSetting("darkMode");
    if (
        darkModeSessionVariable !== null &&
        darkModeSessionVariable !== undefined
    ) {
        setDarkMode(darkModeSessionVariable);
        return;
    }

    // Next, check to see if the user specified the dark mode via the --darkmode
    // CLI argument. The Python code dynamically inserts with the value of that
    // arg as the "data-darkmode" attribute of the #sgr_settings element.
    // The value will be a string, either "true" (dark mode is enabled), "false"
    // (disabled), or "None" (not specified).
    const cliElement = document.getElementById("sgr_settings");
    const cliElementValue = cliElement.getAttribute("data-darkmode");
    if (cliElementValue !== "None") {
        setDarkMode(cliElementValue);
        return;
    }

    // Finally, if the dark mode setting is not found in session storage nor
    // provided the --darkmode CLI argument, set the dark mode according to the
    // system preference
    const mediaQuery = "(prefers-color-scheme: dark)";
    const systemPrefersDark = window.matchMedia(mediaQuery).matches;
    setDarkMode(String(systemPrefersDark));
};

/**
 * Media Query for browser darkMode
 */
const darkModePreference = window.matchMedia("(prefers-color-scheme: dark)");

/**
 * Event listener for broswer darkMode Media Query changes.
 * Sets the report CSS to light mode or dark mode.
 */
darkModePreference.addEventListener("change", () =>  {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        setDarkMode("true");
    } else {
        setDarkMode("false");
    }
});

/**
 * Truncates the specified DNS table to the specified number of rows.
 * @param {number} logIndex The index of the table in the list of DNS tables.
 * @param {number} maxRows The number of rows to truncate the table to.
 */
const truncateDNSTable = (logIndex, maxRows) => {
    try {
        const ROW_INCREMENT = 10;
        let dnsLog = document.querySelectorAll('.dns-logs')[logIndex];
        let rows = dnsLog.querySelector('table').querySelectorAll('tr');
        for (let i = 0; i < rows.length; i++) {
            if (i > maxRows) {
                rows[i].style.display = 'none';
            }
            else {
                rows[i].style.display = 'table-row';
            }
        }
        dnsLog.querySelectorAll('.show-more').forEach(e => e.remove());
        if (rows.length > maxRows) {
            let showMoreMessage = document.createElement('p');
            showMoreMessage.classList.add('show-more');
            showMoreMessage.innerHTML = `${rows.length-maxRows} rows hidden. `;
            showMore = document.createElement('button');
            showMore.innerHTML = "Show more.";
            showMore.setAttribute('type', 'button');
            showMore.classList.add('show-more');
            showMore.onclick = () => {truncateDNSTable(logIndex, maxRows+ROW_INCREMENT);};
            showMoreMessage.appendChild(showMore);
            dnsLog.appendChild(showMoreMessage);
        }
    }
    catch (error) {
        console.error(`Error in truncateDNSTable`, error);
    }
}

/**
 * Truncates any DNS table that has more than maxRows rows.
 * @param {number} maxRows The number of rows to truncate the tables to.
 */
const truncateDNSTables = (maxRows) => {
    try {
        let dnsLogs = document.querySelectorAll('.dns-logs');
        for (let i = 0; i < dnsLogs.length; i++) {
            truncateDNSTable(i, maxRows);
        }
    }
    catch (error) {
        console.error(`Error in truncateDNSTables`, error);
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const MAX_DNS_ENTRIES = 20;
    colorRows();
    mountDarkMode();
    truncateDNSTables(MAX_DNS_ENTRIES);
});

