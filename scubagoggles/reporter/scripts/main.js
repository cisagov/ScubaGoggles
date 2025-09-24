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
                if (rows[i].children[alertStatusCol].innerHTML === "Enabled") {
                    rows[i].style.background = "var(--test-pass)";
                }
                else if (rows[i].children[alertStatusCol].innerHTML === "Disabled") {
                    rows[i].style.background = "var(--test-fail)";
                }
                else if (rows[i].children[alertStatusCol].innerHTML === "Unknown") {
                    rows[i].style.background = "var(--test-other)";
                }
            }
            else {
                // This row is in one of the generic results rows
                if (rows[i].children[requirementCol].innerHTML.startsWith("[DELETED]")) {
                    rows[i].style.color = "var(--test-deleted-color)";
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol].innerHTML === "Fail") {
                    rows[i].style.background = "var(--test-fail)";
                }
                else if (rows[i].children[statusCol].innerHTML.includes("No events found")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol].innerHTML === "Warning") {
                    rows[i].style.background = "var(--test-warning)";
                }
                else if (rows[i].children[statusCol].innerHTML === "Pass") {
                    rows[i].style.background = "var(--test-pass)";
                }
                else if (rows[i].children[statusCol].innerHTML === "Omitted") {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol].innerHTML === "Incorrect result") {
                    if (rows[i].children[criticalityCol].innerHTML === "Shall") {
                        rows[i].style.background = "linear-gradient(to right, var(--test-fail), var(--test-pass))";
                    }
                    else if (rows[i].children[criticalityCol].innerHTML === "Should") {
                        rows[i].style.background = "linear-gradient(to right, var(--test-warning), var(--test-pass))";
                    }
                    else {
                        // This should never happen
                        console.log(`Unexpected criticality for incorrect result, ${rows[i].children[criticalityCol].innerHTML}.`);
                    }
                }
                else if (rows[i].children[criticalityCol].innerHTML.includes("Not-Implemented")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[criticalityCol].innerHTML.includes("3rd Party")) {
                    rows[i].style.background = "var(--test-other)";
                }
                else if (rows[i].children[statusCol].innerHTML.includes("Error")) {
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
    truncateDNSTables(MAX_DNS_ENTRIES);
});