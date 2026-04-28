window.demoLibrary = {
    name: "Compromised UI Helper",
    version: "1.0.0",
    run: function () {
        const output = document.getElementById("cdn-output");
        output.innerHTML = `
            <div class="danger-box">
                Compromised CDN script loaded. Credentials would now be exfiltrated.
            </div>
        `;

        const form = document.getElementById("fake-login-form");
        form.addEventListener("submit", function (event) {
            event.preventDefault();

            document.getElementById("cdn-output").innerHTML += `
                <div class="danger-box">
                    Demo: login data intercepted by modified third-party JavaScript.
                </div>
            `;
        });
    }
};