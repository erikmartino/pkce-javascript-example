export class PKCE {
    constructor(issuer) {
        this.issuer = issuer
        this.openid_configuration = null;
    }

    async fetch_openid_configuration() {
        if (this.openid_configuration) {
            return this.openid_configuration;
        }
        const response = await fetch(`${this.issuer}/.well-known/openid-configuration`, {
            method: 'GET',
            headers: new Headers({ "Accept": "application/json" })
        });
        this.openid_configuration = response.json();
        return this.openid_configuration;
    }

    async authorize() {
        const codeVerifier = this.generateRandomString(64);
        const codeChallenge = this.generateCodeChallenge(codeVerifier);
        window.sessionStorage.setItem("code_verifier", codeVerifier);

        var redirectUri = window.location.href.split('?')[0];

        var args = new URLSearchParams({
            response_type: "code",
            client_id: clientId,
            code_challenge_method: "S256",
            code_challenge: codeChallenge,
            redirect_uri: redirectUri,
            scope: 'openid profile email',
            state: 'mystate',
            nonce: 'mynonce'
        });
        window.location = authorizationEndpoint + "?" + args;
    }

    async auth_code_tokens(code) {
        const conf = await fetch_openid_configuration()
        return fetch(conf.token_endpoint,
            {
                method: 'POST',
                headers: new Headers(
                    {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json"
                    }
                ),
                body: new URLSearchParams({
                    client_id: clientId,
                    code_verifier: window.sessionStorage.getItem("code_verifier"),
                    grant_type: "authorization_code",
                    redirect_uri: location.href.replace(location.search, ''),
                    code: code
                })
            }
        );
    }


    async generateCodeChallenge(codeVerifier) {
        var digest = await crypto.subtle.digest("SHA-256",
            new TextEncoder().encode(codeVerifier));

        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    }

    async generateRandomString(length) {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (var i = 0; i < length; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }

        return text;
    }
}
