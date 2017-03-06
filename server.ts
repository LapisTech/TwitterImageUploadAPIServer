import * as http from "http"
import * as https from "https"
import * as crypto from "crypto"
const conf: { consumer_key: string, consumer_secret: string } = require( 'config.json' );

interface OAUTH_PARAMS
{
	oauth_callback?:        string,
	oauth_consumer_key:     string,
	oauth_signature?:       string,
	oauth_signature_method: string,
	oauth_timestamp:        number,
	oauth_nonce:            string,
	oauth_version:          string,
	oauth_token?:           string,
	oauth_verifier?:        string,
}

interface GET_PARAMS { [ key: string ]: string }

const API: { [ key: string ]: ( req: http.ServerRequest, res: http.ServerResponse, get: GET_PARAMS ) => void } = {};

function getBody( res: http.ClientResponse | http.ServerRequest, max: number = 0 ): Promise<string|Buffer>
{
	return new Promise( ( resolve, reject ) =>
	{
		const data: (string|Buffer)[] = [];
		let len = 0;
		res.setEncoding( 'utf8' );
		res.on( 'data', ( chunk ) =>
		{
			len += chunk.length;
			if ( max && max < len ) { return; }
			data.push( chunk );
		} );
		res.on( 'end', () =>
		{
			if ( max && max < len ) { return reject( { message: 'Data size over.' } ); }
			if ( typeof data[ 0 ] === 'string' )
			{
				resolve( data.join('') );
			} else
			{
				resolve( Buffer.concat( <Buffer[]>data ) );
			}
		} );
	} );
}

function getBodyJSON( res: http.ClientResponse | http.ServerRequest ): Promise<{}>
{
	return getBody( res ).then( ( data ) =>
	{
		try
		{
			return Promise.resolve( JSON.parse( typeof data === 'string' ? data : data.toString() ) );
		} catch( e )
		{
			return Promise.reject( e );
		}
	} );
}

function fetch( options: {}, data: string | { [ key: string ]: string } = '' ): Promise<string|Buffer>
{
	return new Promise( ( resolve, reject ) =>
	{
		const req = https.request( options, ( res ) =>
		{
			var data: (string|Buffer)[] = [];
			res.setEncoding( 'utf8' );
			getBody( res ).then( ( data ) => { resolve( data ); } ).catch( ( error ) => { reject( error ); } );
		} );
		req.on( 'error', ( e ) => { reject( e ); } );
		if ( typeof data === 'string' )
		{
			req.write( data );
		} else
		{
			// multipart
			mediaData( req, data );
		}
		req.end();
	} );
}

function mediaData( req: http.ClientRequest, data: { [ key: string ]: string } )
{
	const boundary = "---------------" + crypto.createHash( 'md5' ).update( new Date().getTime().toString() ).digest( 'hex' );
	req.setHeader( 'Content-Type', 'multipart/related; boundary=' + boundary );
	Object.keys( data ).forEach( ( key ) =>
	{
		req.write( '--' + boundary + '\r\n' );
		req.write( 'Content-Disposition: form-data; name="' + key + '"\r\n\r\n' );
		req.write( data[ key ] );
		req.write( '\r\n' );
	} );
	req.write( '--' + boundary + '--\r\n' );
}

// OAuth

function createOauthParams( params: { callback?: string, token?: string, verifier?: string } ): OAUTH_PARAMS
{
	const date = new Date().getTime();
	const data: OAUTH_PARAMS =
	{
		oauth_consumer_key:     conf.consumer_key,
		oauth_signature_method: 'HMAC-SHA1',
		oauth_timestamp:        Math.floor( date / 1000 ),
		oauth_nonce:            date.toString(),
		oauth_version:          '1.0',
	};
	if ( params.callback !== undefined ) { data.oauth_callback = params.callback; }
	if ( params.token !== undefined ) { data.oauth_token = params.token; }
	if ( params.verifier !== undefined ) { data.oauth_verifier = params.verifier; }
	return data;
}

function getRequestToken()
{
	var host = 'api.twitter.com';
	var path = '/oauth/request_token';
	var requestUrl = 'https://' + host + path;
	var callbackUrl = 'http://localhost:8080/callback';

	const params: OAUTH_PARAMS = createOauthParams( { callback: callbackUrl } );

	params.oauth_signature = signature( requestUrl, params, '' );

	const headers =
	{
		'Authorization': 'OAuth ' + Object.keys( params ).map( ( key: keyof OAUTH_PARAMS ) => { return key + '=' + params[ key ]; } ).join( ',' ),
	};

	return fetch(
	{
		host: host,
		port: 443,
		path: path,
		method: 'POST',
		headers: headers,
	} ).then( ( result: string ): { oauth_token: string, oauth_token_secret: string } =>
	{
		const data = { oauth_token: '', oauth_token_secret: '' };
		result.split( '&' ).forEach( ( kval ) =>
		{
			const d = kval.split( '=', 2 );
			(<any>data)[ d[ 0 ] ] = d[ 1 ];
		} );
		return data;
	} );
}

function getAccessToken( token: string, secret: string, verifier: string )
{
	var host = 'api.twitter.com';
	var path = '/oauth/access_token';
	var requestUrl = 'https://' + host + path;
	var callbackUrl = 'http://localhost:8080/callback';

	const params: OAUTH_PARAMS = createOauthParams( { token: token, verifier } );

	params.oauth_signature = signature( requestUrl, params, secret );

	const headers =
	{
		'Authorization': 'OAuth ' + Object.keys( params ).map( ( key: keyof OAUTH_PARAMS ) => { return key + '=' + params[ key ]; } ).join( ',' ),
	};

	return fetch(
	{
		host: host,
		port: 443,
		path: path,
		method: 'POST',
		headers: headers,
	} ).then( ( result: string ): { oauth_token: string, oauth_token_secret: string, user_id: string, screen_name: string } =>
	{
		const data = { oauth_token: '', oauth_token_secret: '', user_id: '', screen_name: '' };
		result.split( '&' ).forEach( ( kval ) =>
		{
			const d = kval.split( '=', 2 );
			(<any>data)[ d[ 0 ] ] = d[ 1 ];
		} );
		return data;
	} );
}

function getMediaId( token: string, secret: string, image: string ): Promise<{ media_id_string: string }>
{
	var host = 'upload.twitter.com';
	var path = '/1.1/media/upload.json';
	var requestUrl = 'https://' + host + path;

	const params: OAUTH_PARAMS = createOauthParams( { token: token } );

	params.oauth_signature = signature( requestUrl, params, secret );

	const headers =
	{
		'Authorization': 'OAuth ' + Object.keys( params ).map( ( key: keyof OAUTH_PARAMS ) => { return key + '=' + params[ key ]; } ).join( ',' ),
	};

	return fetch(
	{
		host: host,
		port: 443,
		path: path,
		method: 'POST',
		headers: headers,
	}, { media_data: image } ).then( ( result: string ): Promise<{ media_id_string: string }> =>
	{
		try
		{
			const data: { media_id_string: string } = <any>JSON.parse( result );
			if ( !data.media_id_string ) { return Promise.reject( data ); }
			return Promise.resolve( data );
		}catch( e )
		{
			return Promise.reject( e );
		}
	} );
}

function tweetWithMedia( token: string, secret: string, status: string, image: string ): Promise<{}>
{
	var host = 'api.twitter.com';
	var path = '/1.1/statuses/update.json';
	var requestUrl = 'https://' + host + path;

	const params: OAUTH_PARAMS = createOauthParams( { token: token } );

	params.oauth_signature = signature( requestUrl, params, secret );

	const headers =
	{
		'Authorization': 'OAuth ' + Object.keys( params ).map( ( key: keyof OAUTH_PARAMS ) => { return key + '=' + params[ key ]; } ).join( ',' ),
	};

	const data =
	[
		'status=' + encodeURIComponent( status ),
		'media_ids=' + image,
	].join( '&' );

	return fetch(
	{
		host: host,
		port: 443,
		path: path,
		method: 'POST',
		headers: headers,
	}, data ).then( ( result: string ): Promise<{}> =>
	{
		try
		{
			return Promise.resolve( JSON.parse( result ) );
		}catch( e )
		{
			return Promise.reject( e );
		}
	} );

}

function signature( requestUrl: string, params: OAUTH_PARAMS, secret: string )
{
	var keyOfSign = encodeURIComponent( conf.consumer_secret ) + '&' + encodeURIComponent( secret );

	Object.keys( params ).forEach( ( key: keyof OAUTH_PARAMS ) => { params[ key ] = encodeURIComponent( <string>params[ key ] ); } );
	let requestParams = Object.keys( params ).sort( ( a, b ) => { if( a < b ) return -1; if( a > b ) return 1; return 0; } );
	requestParams = requestParams.map( ( key: keyof OAUTH_PARAMS ) => { return key + '=' + params[ key ]; } );

	const dataOfSign = encodeURIComponent( 'POST' ) + '&' + encodeURIComponent( requestUrl ) + '&' + encodeURIComponent( requestParams.join( '&' ) );

	return encodeURIComponent( crypto.createHmac( 'sha1', keyOfSign ).update( dataOfSign ).digest( 'base64' ) );
}

// Params

function convertObject( arr: string[] ): GET_PARAMS
{
	const params: GET_PARAMS = {};
	arr.forEach( ( kv ) => { const [ k, v ] = kv.split( '=', 2 ); params[ k ] = decodeURIComponent( v || '' ); } );
	return params;
}

// Cookie

function parseCookie( cookie: string ): GET_PARAMS
{
	return convertObject( cookie.split( '; ' ) )
}

function convertCookie( params: { [ key: string ]: string } )
{
	return Object.keys( params ).map( ( key ) => { return params[ key ] ? [ key, encodeURIComponent( params[ key ] ) ].join( '=' ) : key; } );//.join( '; ' );
}

// Return function

function redirect( res: http.ServerResponse, redirectUrl: string, headers: { [ key: string ]: string } = {} )
{
	headers[ 'Location' ] = redirectUrl,
	res.writeHead( 303, headers );
	res.end();
}

function e404( res: http.ServerResponse )
{
	res.writeHead( 404, { 'Content-Type':'application/json' } );
	res.write( JSON.stringify( { message: 'API notfound.' } ) );
	res.end();
}

function returnJson( res: http.ServerResponse, data: {} )
{
	res.writeHead( 200, { 'Content-Type':'application/json' } );
	res.write( JSON.stringify( data ) );
	res.end();
}

// API

function auth( req: http.ServerRequest, res: http.ServerResponse, params: GET_PARAMS )
{
	const redirectUrl = req.headers[ 'referer' ] || params[ 'referer' ] || '';
	getRequestToken().then( ( data ) =>
	{
		res.setHeader( 'Set-Cookie', convertCookie(
		{
			referer: redirectUrl,
			osecret: data.oauth_token_secret
		} ) );
		redirect( res, 'https://api.twitter.com/oauth/authorize?oauth_token=' + data.oauth_token );
	} ).catch( ( error ) =>
	{
		redirect( res, redirectUrl );
	} );
}

function callback( req: http.ServerRequest, res: http.ServerResponse, params: GET_PARAMS )
{
//denied
	const cookie = parseCookie( req.headers[ 'cookie' ] || '' );
	const redirectUrl = cookie[ 'referer' ] || '';

	getAccessToken( params[ 'oauth_token' ], cookie[ 'osecret' ], params[ 'oauth_verifier' ] ).then( ( data ) =>
	{
		if ( redirectUrl )
		{
			const uparams =
			[
				{ k: 'token', v: data.oauth_token },
				{ k: 'secret', v: data.oauth_token_secret },
				{ k: 'name', v: data.screen_name },
			].map( ( kv ) => { return kv.k + '=' + encodeURIComponent( kv.v ); } );
			return redirect( res, redirectUrl + '?' + uparams.join( '&' ) );
		}
		returnJson( res, data );
	} ).catch( ( error ) =>
	{
		if ( redirectUrl ) { return redirect( res, redirectUrl ); }
		res.writeHead( 200, { 'Content-Type':'application/json' } );
		res.write( JSON.stringify( error ) );
		res.end();
	} );
}

function upload( req: http.ServerRequest, res: http.ServerResponse, params: GET_PARAMS )
{
	if ( req.method !== 'POST') { return e404( res ); }

	getBodyJSON( req ).then( ( data: { [ key: string ]: string } ) =>
	{
		return getMediaId( data[ 'token' ] || '', data[ 'secret' ] || '', data[ 'image' ] || '' ).then( ( data ) =>
		{
			returnJson( res, { media_id_string: data.media_id_string } );
		} );
	} ).catch( ( error ) =>
	{
		res.writeHead( 200, { 'Content-Type':'application/json' } );
		res.write( JSON.stringify( error ) );
		res.end();
	} );
}

function tweet( req: http.ServerRequest, res: http.ServerResponse, params: GET_PARAMS )
{
	if ( req.method !== 'POST') { return e404( res ); }

	getBodyJSON( req ).then( ( data: { [ key: string ]: string } ) =>
	{
		return tweetWithMedia( data[ 'token' ] || '', data[ 'secret' ] || '', data[ 'status' ] || '', data[ 'media_ids' ] || '' ).then( ( data ) =>
		{
			returnJson( res, data );
		} );
	} ).catch( ( error ) =>
	{
		res.writeHead( 200, { 'Content-Type':'application/json' } );
		res.write( JSON.stringify( error ) );
		res.end();
	} );
}

// Server

API[ '/auth' ] = auth;
API[ '/callback' ] = callback;
API[ '/upload' ] = upload;
API[ '/tweet' ] = tweet;

const server = http.createServer();

server.on( 'request', ( req: http.ServerRequest, res: http.ServerResponse ) =>
{
	const [ path, get ]= ( req.url || '/' ).split( '?' );

	if( !API[ path ] ) { return e404( res ); }

	API[ path ]( req, res, get ? convertObject( get.split( '&' ) ) : {} );
} );

server.listen( parseInt( process.env.PORT ) || 80, process.env.HOST || '127.0.0.1' );
