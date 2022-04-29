export class PKCE {
    constructor(issuer, client_id) {
        this.issuer = issuer
        this.client_id = client_id;
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

    async authorize(redirectUri) {
        const codeVerifier = await this.generateRandomString(64);
        const codeChallenge = await this.generateCodeChallenge(codeVerifier);
        window.sessionStorage.setItem("code_verifier", codeVerifier);
        window.sessionStorage.setItem("redirect_uri", redirectUri);

        var args = new URLSearchParams({
            response_type: "code",
            client_id: this.client_id,
            code_challenge_method: "S256",
            code_challenge: codeChallenge,
            redirect_uri: redirectUri,
            scope: 'openid profile email',
            state: 'mystate',
            nonce: 'mynonce',
            response_mode: "fragment",
        });
        const conf = await this.fetch_openid_configuration()
        window.location = conf.authorization_endpoint + "?" + args;
    }

    async auth_code_tokens(code) {
        const conf = await this.fetch_openid_configuration()
        return fetch(conf.token_endpoint, {
            method: 'POST',
            headers: new Headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json"
                }
            ),
            body: new URLSearchParams({
                client_id: this.client_id,
                code_verifier: window.sessionStorage.getItem("code_verifier"),
                grant_type: "authorization_code",
                redirect_uri: window.sessionStorage.getItem('redirect_uri'),
                code: code
            })
        }
        ).then(response => response.json())
            .then(tokens => this.saveTokens(tokens));
    }


    async token_refresh() {
        const conf = this.fetch_openid_configuration()
        const tokens = this.loadTokens()
        const refresh_token = tokens?.refresh_token

        if (!refresh_token) {
            console.warn("tokens",tokens)
            throw "Please authenticate, need a refresh_token"
        }

        const token_endpoint = (await conf).token_endpoint
        return fetch(token_endpoint, {
            method: 'POST',
            headers: new Headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json"
                }
            ),
            body: new URLSearchParams({
                client_id: this.client_id,
                refresh_token: refresh_token,
                grant_type: "refresh_token",
            })
        }).then(response => response.json())
            .then(tokens => this.saveTokens(tokens));
    }

    async saveTokens(tokens) {
        const item = JSON.stringify(tokens)
        window.sessionStorage.setItem('tokens', item);
        return tokens;
    }

    loadTokens() {
        const item = window.sessionStorage.getItem('tokens') || {}
        const tokens = JSON.parse(item)
        return tokens
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
