function redaction() {
    console.log('Starting redaction')

    try {
        const identityTable = document.querySelectorAll("table")[0]

        let tbody = identityTable.querySelector("tbody")

        if (!tbody) throw new Error(
            `Invalid HTML structure, <table id='${identityTable.getAttribute("id")}'> does not have a <tbody> tag.`
        )

        if (tbody.children[1].children) {
            console.log('found identification row: ', tbody.children[1].children)
            let identityData = tbody.children[1].children

            for (let cell of identityData) {
                // cell.textContent = '[Redacted]'
                cell.classList.add('redact')
            }

        }

    } catch (error) {
        console.error(`Error redacting `)
    }
}