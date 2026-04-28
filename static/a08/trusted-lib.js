window.demoLibrary = {
    name: "Trusted UI Helper",
    version: "1.0.0",
    run: function () {
        const output = document.getElementById("cdn-output");
        output.innerHTML = `
            <div class="success-box">
                Trusted CDN script loaded. Login form behaves normally.
            </div>
        `;
    }
};