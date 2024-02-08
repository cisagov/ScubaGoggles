/**
 * Adds the red, green, yellow, and gray coloring to the individual report pages.
 */
const colorRows = () => {
    let rows = document.querySelectorAll('tr');
    const requirementCol = 1
    const statusCol = 2;
    const criticalityCol = 3;
    for (let i = 0; i < rows.length; i++) {
        try {
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
        catch (error) {
            console.error(`Error in colorRows, i = ${i}`);
            console.error(error);
        }
    }
}

window.addEventListener('DOMContentLoaded', (event) => {
    colorRows();
});