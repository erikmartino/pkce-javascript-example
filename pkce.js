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
        const state = await this.generateRandomString(16);
        const nonce = await this.generateRandomString(16);

        const auth_verify = {}
        auth_verify[state] = {
            code_verifier: codeVerifier,
            redirect_uri: redirectUri,
            nonce: nonce
        }

        window.sessionStorage.setItem("auth_verify", JSON.stringify(auth_verify));

        window.sessionStorage.setItem("code_verifier", codeVerifier);
        window.sessionStorage.setItem("redirect_uri", redirectUri);

        var args = new URLSearchParams({
            response_type: "code",
            client_id: this.client_id,
            code_challenge_method: "S256",
            code_challenge: codeChallenge,
            redirect_uri: redirectUri,
            scope: 'openid profile email',
            state: state,
            nonce: nonce,
            response_mode: "fragment",
        });
        const conf = await this.fetch_openid_configuration()
        window.location = conf.authorization_endpoint + "?" + args;
    }

    async logout() {
        const conf = this.fetch_openid_configuration()
    }

    async auth_code_tokens(args) {
        const conf = await this.fetch_openid_configuration()
        const code = args.code
        const state = args.state
        console.info("auth_verify", state, JSON.parse(window.sessionStorage.getItem("auth_verify")));
        const auth_verify = JSON.parse(window.sessionStorage.getItem("auth_verify") || '{}')[state];

        if (!auth_verify) {
            throw "No matching authorization"
        }

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
                code_verifier: auth_verify.code_verifier,
                grant_type: "authorization_code",
                redirect_uri: auth_verify.redirect_uri,
                code: code
            })
        }).then(response => response.json())
            .then(tokens => this.saveTokens(tokens));
    }

    /**
     * Handles auth code fragment response and end session state query parameter
     * @returns 
     */
    async handle_auth_fragment() {
        const fragment = window.location.hash.substring(1)
        history.replaceState(null, null, ' ');

        const args = Object.fromEntries(new URLSearchParams(fragment));
        if (args.code) {
            return this.auth_code_tokens(args)
        }

        const search = new URLSearchParams(window.location.search)
        const query = Object.fromEntries(new URLSearchParams(window.location.search));
        if (query.state) {
            const end_session_state = JSON.parse(window.sessionStorage.getItem('end_session_state') || '{}') 
            if (end_session_state[query.state]) {
                search.delete('state')
                window.location.search = `?${search.toString()}`
            } else {
                console.info('no matching session state')
            }
        }

        const tokens = await this.loadTokens();
        return tokens;
    }

    async token_refresh() {
        const conf = this.fetch_openid_configuration()
        const tokens = this.loadTokens()
        const refresh_token = tokens?.refresh_token

        if (!refresh_token) {
            console.warn("tokens", tokens)
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

    async end_session(post_logout_redirect_uri) {
        const conf = await this.fetch_openid_configuration()
        const tokens = await this.loadTokens();

        const end_session_endpoint = conf.end_session_endpoint
        const id_token_hint = tokens.id_token
        const state = await this.generateRandomString(16);

        const end_session_parameters = new URLSearchParams({
            post_logout_redirect_uri: post_logout_redirect_uri,
            id_token_hint: id_token_hint,
            client_id: this.client_id,
            state: state,
        })

        const end_session = end_session_endpoint + "?" + end_session_parameters;

        const end_session_state = {}
        end_session_state[state] = end_session_parameters;

        window.sessionStorage.setItem('end_session_state', JSON.stringify(end_session_state));
        window.location = end_session;
    }

    async userinfo() {
        const conf = await this.fetch_openid_configuration()
        const tokens = await this.loadTokens()

        return fetch(conf.userinfo_endpoint, {
            method: 'GET',
            headers: new Headers(
                {
                    "Accept": "application/json",
                    "Authorization": `Bearer ${tokens.access_token}`
                }
            )
        }).then(response => response.json())
    }

    jwt_payload(jwt_token) {
        return jwt_token ? JSON.parse(atob(jwt_token.split('.')[1])) : '';
    }

    jwt_prettify(jwt_token) {
        return JSON.stringify(this.jwt_payload(jwt_token), null, 4)
    }

    async saveTokens(tokens) {
        const item = JSON.stringify(tokens)
        window.sessionStorage.setItem('tokens', item);
        return tokens;
    }

    loadTokens() {
        const item = window.sessionStorage.getItem('tokens') || '{}'
        const tokens = JSON.parse(item)
        return tokens
    }

    async generateCodeChallenge(codeVerifier) {
        var digest = await crypto.subtle.digest("SHA-256",
            new TextEncoder().encode(codeVerifier));

        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    }

    async at_hash(token) {
        const hash = await crypto.subtle.digest("SHA-256",new TextEncoder().encode(token));
        return btoa(String.fromCharCode(...new Uint8Array(hash.slice(0,16))))
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
