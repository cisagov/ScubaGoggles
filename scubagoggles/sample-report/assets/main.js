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
        document.querySelector("#toggle-text").classList.add("dark");
        updateSettings("darkMode", "true");
        darkModeToggle.checked = true;
        return;
    }

    document.querySelectorAll("html")[0].dataset.theme = "light";
    document.querySelector("#toggle-text").innerHTML = "Light Mode";
    document.querySelector("#toggle-text").classList.remove("dark");
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
    // CLI argument. The Python code dynamically inserts the value of that arg
    // as the "data-darkmode" attribute of the #sgr_settings element. The value
    // will be a string, either "true" (dark mode is enabled), "false" (disabled),
    // or "None" (not specified).
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

/**
 * Apply scope attributes to columns and rows
 */
const applyScopeAttributes = () => {
    try {

        const tables = document.querySelectorAll("table")

        for (let table of tables) {

            let tbody = table.querySelector("tbody")

            if (!tbody) throw new Error(
                `Invalid HTML structure, <table id='${tables[table]?.getAttribute("id")}'> does not have a <tbody> tag.`
            )

            let cols, rows;

            if (tbody.children && tbody.children.length > 0) {
                for (let child of tbody.children) {
                    if (child.querySelectorAll("tr > th")) {
                        cols = table.querySelectorAll("tr > th")
                        for (let col of cols) {
                            col.setAttribute("scope", "col")
                        }
                    }
                }

                let trIdx = (table.classList.contains("caps_table")) ? 1 : 0

                rows = tbody.children

                for (let row of rows) {
                    if (row.children[trIdx].localName === 'td') {
                       row.children[trIdx].setAttribute("scope", "row")
                    }
                }
            }

            else throw new Error(
                `Unable to apply scope attributes to columns/rows,
                <tbody> of <table id='${tables[table]?.getAttribute("id")}'> does not contain children or has no rows.`
            )
        }

    } catch (error) {
        console.error(`Error applying scope attributes: ${error}`)
    }
}


/**
 * Apply redaction to identification information in reports
 * based on the --cicdtestingmode (-ctm) CLI arg
 */
function redaction() {
    const cliElement = document.getElementById("sgr_settings");
    const cliElementValue = cliElement.getAttribute("data-redaction");

    if (cliElementValue !== "None" && cliElementValue == "true") {
        try {
            const identityTable = document.querySelectorAll("table")[0]

            let tbody = identityTable.querySelector("tbody")

            if (!tbody) throw new Error(
                `Invalid HTML structure, <table id='${identityTable.getAttribute("id")}'> does not have a <tbody> tag.`
            )

            if (tbody.children[1].children) {
                let identityData = tbody.children[1].children

                for (let cell of identityData) {
                    cell.classList.add('redact')
                }

            }

        } catch (error) {
            console.error(`Error redacting identification information`)
        }
        return;
    }

}

window.addEventListener('DOMContentLoaded', () => {
    const MAX_DNS_ENTRIES = 20;
    applyScopeAttributes();
    mountDarkMode();
    truncateDNSTables(MAX_DNS_ENTRIES);
    redaction();
});
