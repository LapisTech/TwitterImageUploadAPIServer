"use strict";
const http = require("http");
const https = require("https");
const crypto = require("crypto");
const conf = require('config.json');
const API = {};
function getBody(res, max = 0) {
    return new Promise((resolve, reject) => {
        const data = [];
        let len = 0;
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
            len += chunk.length;
            if (max && max < len) {
                return;
            }
            data.push(chunk);
        });
        res.on('end', () => {
            if (max && max < len) {
                return reject({ message: 'Data size over.' });
            }
            if (typeof data[0] === 'string') {
                resolve(data.join(''));
            }
            else {
                resolve(Buffer.concat(data));
            }
        });
    });
}
function getBodyJSON(res) {
    return getBody(res).then((data) => {
        try {
            return Promise.resolve(JSON.parse(typeof data === 'string' ? data : data.toString()));
        }
        catch (e) {
            return Promise.reject(e);
        }
    });
}
function fetch(options, data = '') {
    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            var data = [];
            res.setEncoding('utf8');
            getBody(res).then((data) => { resolve(data); }).catch((error) => { reject(error); });
        });
        req.on('error', (e) => { reject(e); });
        if (typeof data === 'string') {
            req.write(data);
        }
        else {
            mediaData(req, data);
        }
        req.end();
    });
}
function mediaData(req, data) {
    const boundary = "---------------" + crypto.createHash('md5').update(new Date().getTime().toString()).digest('hex');
    req.setHeader('Content-Type', 'multipart/related; boundary=' + boundary);
    Object.keys(data).forEach((key) => {
        req.write('--' + boundary + '\r\n');
        req.write('Content-Disposition: form-data; name="' + key + '"\r\n\r\n');
        req.write(data[key]);
        req.write('\r\n');
    });
    req.write('--' + boundary + '--\r\n');
}
function createOauthParams(params) {
    const date = new Date().getTime();
    const data = {
        oauth_consumer_key: conf.consumer_key,
        oauth_signature_method: 'HMAC-SHA1',
        oauth_timestamp: Math.floor(date / 1000),
        oauth_nonce: date.toString(),
        oauth_version: '1.0',
    };
    if (params.callback !== undefined) {
        data.oauth_callback = params.callback;
    }
    if (params.token !== undefined) {
        data.oauth_token = params.token;
    }
    if (params.verifier !== undefined) {
        data.oauth_verifier = params.verifier;
    }
    return data;
}
function getRequestToken() {
    var host = 'api.twitter.com';
    var path = '/oauth/request_token';
    var requestUrl = 'https://' + host + path;
    var callbackUrl = 'http://localhost:8080/callback';
    const params = createOauthParams({ callback: callbackUrl });
    params.oauth_signature = signature(requestUrl, params, '');
    const headers = {
        'Authorization': 'OAuth ' + Object.keys(params).map((key) => { return key + '=' + params[key]; }).join(','),
    };
    return fetch({
        host: host,
        port: 443,
        path: path,
        method: 'POST',
        headers: headers,
    }).then((result) => {
        const data = { oauth_token: '', oauth_token_secret: '' };
        result.split('&').forEach((kval) => {
            const d = kval.split('=', 2);
            data[d[0]] = d[1];
        });
        return data;
    });
}
function getAccessToken(token, secret, verifier) {
    var host = 'api.twitter.com';
    var path = '/oauth/access_token';
    var requestUrl = 'https://' + host + path;
    var callbackUrl = 'http://localhost:8080/callback';
    const params = createOauthParams({ token: token, verifier });
    params.oauth_signature = signature(requestUrl, params, secret);
    const headers = {
        'Authorization': 'OAuth ' + Object.keys(params).map((key) => { return key + '=' + params[key]; }).join(','),
    };
    return fetch({
        host: host,
        port: 443,
        path: path,
        method: 'POST',
        headers: headers,
    }).then((result) => {
        const data = { oauth_token: '', oauth_token_secret: '', user_id: '', screen_name: '' };
        result.split('&').forEach((kval) => {
            const d = kval.split('=', 2);
            data[d[0]] = d[1];
        });
        return data;
    });
}
function getMediaId(token, secret, image) {
    var host = 'upload.twitter.com';
    var path = '/1.1/media/upload.json';
    var requestUrl = 'https://' + host + path;
    const params = createOauthParams({ token: token });
    params.oauth_signature = signature(requestUrl, params, secret);
    const headers = {
        'Authorization': 'OAuth ' + Object.keys(params).map((key) => { return key + '=' + params[key]; }).join(','),
    };
    return fetch({
        host: host,
        port: 443,
        path: path,
        method: 'POST',
        headers: headers,
    }, { media_data: image }).then((result) => {
        try {
            const data = JSON.parse(result);
            if (!data.media_id_string) {
                return Promise.reject(data);
            }
            return Promise.resolve(data);
        }
        catch (e) {
            return Promise.reject(e);
        }
    });
}
function tweetWithMedia(token, secret, status, image) {
    var host = 'api.twitter.com';
    var path = '/1.1/statuses/update.json';
    var requestUrl = 'https://' + host + path;
    const params = createOauthParams({ token: token });
    params.oauth_signature = signature(requestUrl, params, secret);
    const headers = {
        'Authorization': 'OAuth ' + Object.keys(params).map((key) => { return key + '=' + params[key]; }).join(','),
    };
    const data = [
        'status=' + encodeURIComponent(status),
        'media_ids=' + image,
    ].join('&');
    return fetch({
        host: host,
        port: 443,
        path: path,
        method: 'POST',
        headers: headers,
    }, data).then((result) => {
        try {
            return Promise.resolve(JSON.parse(result));
        }
        catch (e) {
            return Promise.reject(e);
        }
    });
}
function signature(requestUrl, params, secret) {
    var keyOfSign = encodeURIComponent(conf.consumer_secret) + '&' + encodeURIComponent(secret);
    Object.keys(params).forEach((key) => { params[key] = encodeURIComponent(params[key]); });
    let requestParams = Object.keys(params).sort((a, b) => { if (a < b)
        return -1; if (a > b)
        return 1; return 0; });
    requestParams = requestParams.map((key) => { return key + '=' + params[key]; });
    const dataOfSign = encodeURIComponent('POST') + '&' + encodeURIComponent(requestUrl) + '&' + encodeURIComponent(requestParams.join('&'));
    return encodeURIComponent(crypto.createHmac('sha1', keyOfSign).update(dataOfSign).digest('base64'));
}
function convertObject(arr) {
    const params = {};
    arr.forEach((kv) => { const [k, v] = kv.split('=', 2); params[k] = decodeURIComponent(v || ''); });
    return params;
}
function parseCookie(cookie) {
    return convertObject(cookie.split('; '));
}
function convertCookie(params) {
    return Object.keys(params).map((key) => { return params[key] ? [key, encodeURIComponent(params[key])].join('=') : key; });
}
function redirect(res, redirectUrl, headers = {}) {
    headers['Location'] = redirectUrl,
        res.writeHead(303, headers);
    res.end();
}
function e404(res) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.write(JSON.stringify({ message: 'API notfound.' }));
    res.end();
}
function returnJson(res, data) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write(JSON.stringify(data));
    res.end();
}
function auth(req, res, params) {
    const redirectUrl = req.headers['referer'] || params['referer'] || '';
    getRequestToken().then((data) => {
        res.setHeader('Set-Cookie', convertCookie({
            referer: redirectUrl,
            osecret: data.oauth_token_secret
        }));
        redirect(res, 'https://api.twitter.com/oauth/authorize?oauth_token=' + data.oauth_token);
    }).catch((error) => {
        redirect(res, redirectUrl);
    });
}
function callback(req, res, params) {
    const cookie = parseCookie(req.headers['cookie'] || '');
    const redirectUrl = cookie['referer'] || '';
    getAccessToken(params['oauth_token'], cookie['osecret'], params['oauth_verifier']).then((data) => {
        if (redirectUrl) {
            const uparams = [
                { k: 'token', v: data.oauth_token },
                { k: 'secret', v: data.oauth_token_secret },
                { k: 'name', v: data.screen_name },
            ].map((kv) => { return kv.k + '=' + encodeURIComponent(kv.v); });
            return redirect(res, redirectUrl + '?' + uparams.join('&'));
        }
        returnJson(res, data);
    }).catch((error) => {
        if (redirectUrl) {
            return redirect(res, redirectUrl);
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write(JSON.stringify(error));
        res.end();
    });
}
function upload(req, res, params) {
    if (req.method !== 'POST') {
        return e404(res);
    }
    getBodyJSON(req).then((data) => {
        return getMediaId(data['token'] || '', data['secret'] || '', data['image'] || '').then((data) => {
            returnJson(res, { media_id_string: data.media_id_string });
        });
    }).catch((error) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write(JSON.stringify(error));
        res.end();
    });
}
function tweet(req, res, params) {
    if (req.method !== 'POST') {
        return e404(res);
    }
    getBodyJSON(req).then((data) => {
        return tweetWithMedia(data['token'] || '', data['secret'] || '', data['status'] || '', data['media_ids'] || '').then((data) => {
            returnJson(res, data);
        });
    }).catch((error) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.write(JSON.stringify(error));
        res.end();
    });
}
API['/auth'] = auth;
API['/callback'] = callback;
API['/upload'] = upload;
API['/tweet'] = tweet;
const server = http.createServer();
server.on('request', (req, res) => {
    const [path, get] = (req.url || '/').split('?');
    if (!API[path]) {
        return e404(res);
    }
    API[path](req, res, get ? convertObject(get.split('&')) : {});
});
server.listen(parseInt(process.env.PORT) || 80, process.env.HOST || '127.0.0.1');
