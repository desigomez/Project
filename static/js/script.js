
function sendQuery() {
    const sqlQuery = document.getElementById("sql-query").value;
    const modelType = "svm";

    if (!sqlQuery.trim()) {
        alert("Please enter a SQL query.");
        return;
    }

    document.getElementById("loading").style.display = "block";
    document.getElementById("result").style.display = "none";

    fetch('/detect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sql_query: sqlQuery, model_type: modelType })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("loading").style.display = "none";
        if (data.error) {
            alert(data.error);
            return;
        }

        const resultDiv = document.getElementById("result");
        const classification = document.getElementById("classification");

        document.getElementById("query-text").innerText = data.query;
        classification.innerText = data.classification;

        resultDiv.classList.remove("safe", "malicious");
        resultDiv.classList.add(data.classification.toLowerCase());
        resultDiv.style.display = "block";
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById("loading").style.display = "none";
    });
}

function sendLogin() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    if (!username.trim() || !password.trim()) {
        alert("Please enter both username and password.");
        return;
    }

    document.getElementById("login-loading").style.display = "block";
    document.getElementById("login-result").style.display = "none";

    fetch('/check_login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, password: password })
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById("login-loading").style.display = "none";
        if (data.error) {
            alert(data.error);
            return;
        }

        const resultSpan = document.getElementById("login-classification");
        const resultDiv = document.getElementById("login-result");
        const simulatedQuery = document.getElementById("simulated-query");

        resultSpan.innerText = data.classification;
        simulatedQuery.innerText = data.simulated_query;

        resultDiv.classList.remove("safe", "malicious");
        resultDiv.classList.add(data.classification.toLowerCase());
        resultDiv.style.display = "block";
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById("login-loading").style.display = "none";
    });

}