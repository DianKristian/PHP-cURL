<?php


$isCurlHandle = isset($GLOBALS['curlHandle']);
if (version_compare(PHP_VERSION, '8.0.0', '<')) {
	$isCurlHandle = $isCurlHandle 
	&& is_resource($GLOBALS['curlHandle']) 
	&& get_resource_type($GLOBALS['curlHandle']) === 'curl';
} else {
	$isCurlHandle = $isCurlHandle 
	&& $GLOBALS['curlHandle'] instanceof CurlHandle;
}



if ($isCurlHandle) {
	curl_reset($GLOBALS['curlHandle']);
} else {
	if (false === extension_loaded('curl')) {
		if (false === function_exists('dl')) {
			throw new ErrorException('curl extension not installed');
		}
		
		$prefix = (PHP_SHLIB_SUFFIX === 'dll') ? 'php' : '';
		
		if (false === @dl($prefix . 'curl.' . PHP_SHLIB_SUFFIX)) {
			throw new ErrorException('Load curl extension failed');
		}
		
		unset($prefix);
	}
	$GLOBALS['curlHandle'] = curl_init();
	register_shutdown_function('curl_close', $GLOBALS['curlHandle']);
}



$curlOptions = array();
$curlOptions[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
$curlOptions[CURLOPT_RETURNTRANSFER] = true;
//$curlOptions[CURLOPT_BINARYTRANSFER] = true;
$curlOptions[CURLOPT_VERBOSE] = false;
//$curlOptions[CURLOPT_HEADER] = false;

// To track the handle's request string
$curlOptions[CURLINFO_HEADER_OUT] = true;

// A callback accepting two parameters. The first is the cURL resource, the second is a string with the header 
// data to be written. The header data must be written by this callback. Return the number of bytes written.
$curlResponseHeaders = [];
$curlOptions[CURLOPT_HEADERFUNCTION] = function($curl, $header) use (&$curlResponseHeaders) {
	$bytes = strlen($header);
	$parts = explode(':', $header, 2);
	if (count($parts) < 2)
		return $bytes;
	$name = str_replace('-', '_', strtolower(trim($parts[0])));
	$curlResponseHeaders[$name] = trim($parts[1]);
	return $bytes;
};

$sysTempDir = realpath(sys_get_temp_dir()) . DIRECTORY_SEPARATOR;
$curlOptions[CURLOPT_COOKIEFILE] = $sysTempDir . 'cookie.txt';
$curlOptions[CURLOPT_COOKIEJAR] = $sysTempDir . 'cookie.txt';


if (false === isset($curlRequest)):
	throw new ErrorException('Parameter curlRequest is required');
endif;

if (false === is_array($curlRequest)):
	throw new ErrorException(sprintf(
		'Expects parameter curlRequest is an array, %s given', 
		gettype($curlRequest)
	));
endif;

$defaults = array(
	'url' 				=> null,
	'method' 			=> 'GET',
	'data' 				=> array(),
	'headers' 			=> array(),
	'proxy_host' 		=> null,
	'proxy_port' 		=> null,
	'proxy_user' 		=> null,
	'proxy_pass' 		=> null,
	'follow_location' 	=> true,
	'max_redirect' 		=> true,
	
	// The maximum number of seconds to allow cURL functions to execute.
	'timeout' 			=> 60,
	'connect_timeout' 	=> 60,
);

$curlRequest = array_merge($defaults, array_change_key_case($curlRequest, CASE_LOWER));


if (false === is_array($curlRequest['headers'])) {
	throw new ErrorException(sprintf(
		'Array type required, %s given', 
		gettype($curlRequest['headers'])
	));
}

$curlRequestHeaders = array_change_key_case($curlRequest['headers']);


// URL
if (false === isset($curlRequest['url'])):
	throw new ErrorException('Parameter url in curlRequest required');
endif;

if (false === is_string($curlRequest['url'])):
	throw new ErrorException(sprintf(
		'Parameter url in curlRequest must be a string, %s given', 
		gettype($curlRequest['url'])
	));
endif;

$curlRequest['url'] = trim($curlRequest['url']);

if ($curlRequest['url'] === ''):
	throw new ErrorException('url required! The value can not be empty');
endif;

$curlUrl = parse_url($curlRequest['url']);

if (false === isset($curlUrl['host'])):
	throw new ErrorException('Malformed url. hostname required');
endif;

$curlUrl['host'] = strtolower($curlUrl['host']);
$curlUrl['scheme'] = isset($curlUrl['scheme']) ? strtolower($curlUrl['scheme']) : 'http';

$curlUrlQuery = array();
if (isset($curlUrl['query'])) {
	parse_str($curlUrl['query'], $curlUrlQuery);
}


// METHOD
// @see: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
// @see: https://tools.ietf.org/html/rfc7231#section-4
if (false === isset($curlRequest['method'])):
	$curlRequest['method'] = 'GET';
endif;

if (false === is_string($curlRequest['method'])):
	throw new ErrorException(sprintf(
		'Expects parameter method in curlRequest is a string, %s given', 
		gettype($curlRequest['method'])
	));
endif;

$curlRequest['method'] = strtoupper(trim($curlRequest['method']));

if ($curlRequest['method'] === ''):
	$curlRequest['method'] = 'GET';
endif;

switch ($curlRequest['method']):
	// The GET method requests a representation of the specified resource. 
	// Requests using GET should only retrieve data.
	case 'GET':
		$curlOptions[CURLOPT_HTTPGET] = true;
	break;
	
	// The POST method is used to submit an entity to the specified resource, 
	// often causing a change in state or side effects on the server.
	case 'POST':
		$curlOptions[CURLOPT_POST] = true;
	break;
	
	// The PUT method replaces all current representations of the target 
	// resource with the request payload
	case 'PUT':
		$curlOptions[CURLOPT_PUT] = true;
	break;
	
	// The HEAD method asks for a response identical to that of a GET request, 
	// but without the response body.
	case 'HEAD':
	
	// The DELETE method deletes the specified resource
	case 'DELETE':
	
	// The CONNECT method establishes a tunnel to the server identified by the target resource.
	case 'CONNECT':
	
	// The OPTIONS method is used to describe the communication options for the target resource
	case 'OPTIONS':
	
	// The TRACE method performs a message loop-back test along the path to the target resource.
	case 'TRACE':
	
	// The PATCH method is used to apply partial modifications to a resource
	// @see: https://tools.ietf.org/html/rfc5789#section-2
	case 'PATCH':
		$curlOptions[CURLOPT_CUSTOMREQUEST] = $curlRequest['method'];
	break;
	
	default:
		throw new ErrorException(sprintf(
			'Unsupported method: %s', 
			$curlRequest['method']
		));
	break;
endswitch;

// NOBODY
$curlOptions[CURLOPT_NOBODY] = ($curlRequest['method'] === 'HEAD');



// DATA
if (false === (isset($curlRequest['data']) && is_array($curlRequest['data']))) 
{
	switch ($curlRequest['method']):
		case 'GET':
		case 'HEAD':
		case 'DELETE':
			if (false === empty($curlUrlQuery))
				$curlUrlQuery = array_merge($curlUrlQuery, $curlRequest['data']);
			break;
		
		default:
			
			$curlOptions[CURLOPT_POSTFIELDS] = http_build_query($curlRequest['data']);
			if (empty($curlRequest['headers']['Content-Length']))
				$curlRequest['headers']['Content-Length'] = strval(strlen($curlOptions[CURLOPT_POSTFIELDS]));
			if (empty($curlRequest['headers']['Content-Type']))
				$curlRequest['headers']['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';
			break;
	endswitch;
}



// Rebuild URL
$curlOptions[CURLOPT_URL] = sprintf('%s://', $curlUrl['scheme']);
if (isset($curlUrl['user'])) {
	$curlOptions[CURLOPT_URL] .= $curlUrl['user'];
	$curlOptions[CURLOPT_URL] .= isset($curlUrl['pass']) ? sprintf(':%s', $curlUrl['pass']) . '';
	$curlOptions[CURLOPT_URL] .= '@';
}
$curlOptions[CURLOPT_URL] .= $curlUrl['host'];
$curlOptions[CURLOPT_URL] .= isset($curlUrl['port']) ? sprintf(':%d', $curlUrl['port']) : '';
$curlOptions[CURLOPT_URL] .= isset($curlUrl['path']) ? $curlUrl['path'] : '/';
$curlOptions[CURLOPT_URL] .= empty($curlUrlQuery) ? '' : sprintf('?%s', http_build_query($curlUrlQuery));
$curlOptions[CURLOPT_URL] .= isset($curlUrl['fragment']) ? sprintf('#%s', $curlUrl['fragment']) : '';
unset($curlUrl, $curlUrlQuery);



// Handle proxy options
if (isset($curlRequest['proxy_host']))
{
	// Proxy Host
	if (false === is_string($curlRequest['proxy_host'])) {
		throw new ErrorException(sprintf(
			'String type required, %s given', 
			gettype($curlRequest['proxy_host'])
		));
	}
	
	$curlRequest['proxy_host'] = trim($curlRequest['proxy_host']);
	
	if ($curlRequest['proxy_host']) === '') {
		throw new ErrorException('Empty string found');
	}
	
	$curlOptions[CURLOPT_PROXY] = $curlRequest['proxy_host'];
	
	// Proxy Port
	if (isset($curlRequest['proxy_port'])) 
	{
		if (false === is_int($curlRequest['proxy_port'])) {
			throw new ErrorException(sprintf(
				'Integer type required, %s given', 
				gettype($curlRequest['proxy_port'])
			));
		}
		
		$curlOptions[CURLOPT_PROXYPORT] = $curlRequest['proxy_port'];
	}
	
	// Proxy Username and password
	if (isset($curlRequest['proxy_user'])) 
	{
		if (false === is_string($curlRequest['proxy_user'])) {
			throw new ErrorException(sprintf(
				'String type required, %s given', 
				gettype($curlRequest['proxy_user'])
			));
		}
		
		$curlRequest['proxy_user'] = trim($curlRequest['proxy_user']);
		
		if ($curlRequest['proxy_user'] === '') {
			throw new ErrorException('Empty string found');
		}
		
		$curlOptions[CURLOPT_PROXYUSERPWD] = $curlRequest['proxy_user'];
		
		if (isset($curlRequest['proxy_pass'])) 
		{
			if (false === is_string($curlRequest['proxy_pass'])) {
				throw new Exception(sprintf(
					'String type required, %s given', 
					gettype($curlRequest['proxy_pass'])
				));
			}
			
			$curlRequest['proxy_pass'] = trim($curlRequest['proxy_pass']);
			
			if ($curlRequest['proxy_pass'] !== '') {
				$curlOptions[CURLOPT_PROXYUSERPWD] .= sprintf(':%s', $curlRequest['proxy_pass']);
			}
		}
	}
	
	$curlOptions[CURLOPT_HTTPPROXYTUNNEL] = true;
}


// FOLLOW LOCATION
// true to follow any "Location: " header that the server sends as part of the HTTP header 
// (note this is recursive, PHP will follow as many "Location: " headers that it is sent, unless CURLOPT_MAXREDIRS is set).
$curlOptions[CURLOPT_FOLLOWLOCATION] = true;
if (isset($curlRequest['follow_location'])) {
	if (false === is_bool($curlRequest['follow_location'])) {
		throw new ErrorException(sprintf(
			'Boolean type required, %s given', 
			gettype($curlRequest['follow_location'])
		));
	}
	$curlOptions[CURLOPT_FOLLOWLOCATION] = $curlRequest['follow_location'];
}

if ($curlOptions[CURLOPT_FOLLOWLOCATION]) {
	if (version_compare(PHP_VERSION, '5.6', '>=')) {
		$curlVersion = curl_version();
		$curlOptions[CURLOPT_FOLLOWLOCATION] = boolval(!ini_get('open_basedir') 
		|| version_compare($curlVersion['version'], '7.19.4', '>='));
	} elseif (version_compare(PHP_VERSION, '5.4', '>=')) {
		$curlOptions[CURLOPT_FOLLOWLOCATION] = boolval(!ini_get('open_basedir'));
	} else {
		$curlOptions[CURLOPT_FOLLOWLOCATION] = boolval(!ini_get('open_basedir') && !ini_get('safe_mode'));
	}

	if ($curlOptions[CURLOPT_FOLLOWLOCATION] && version_compare(PHP_VERSION, '5.1.0', '>=')) {
		// PHP 5.1.0
		// true to automatically set the Referer: field in requests where it follows a Location: redirect.
		$curlOptions[CURLOPT_AUTOREFERER] = true;
		
		// The maximum amount of HTTP redirections to follow. Use this option alongside CURLOPT_FOLLOWLOCATION.
		if (isset($curlRequest['max_redirect'])) {
			if (false === is_int($curlRequest['max_redirect'])) {
				throw new ErrorException(sprintf(
					'Integer type required, %s given', 
					gettype($curlRequest['max_redirect'])
				));
			}
			
			$curlOptions[CURLOPT_MAXREDIRS] = $curlRequest['max_redirect'];
		}
	}
}


// The maximum number of seconds to allow cURL functions to execute.
if (isset($curlRequest['timeout'])) {
	if (false === is_int($curlRequest['timeout'])) {
		throw new ErrorException(sprintf('
			Integer type required, %s given', 
			gettype($curlRequest['timeout'])
		));
	}
	$curlOptions[CURLOPT_TIMEOUT] = $curlRequest['timeout'];
}


// The number of seconds to wait while trying to connect. Use 0 to wait indefinitely.
if (isset($curlRequest['connect_timeout'])) {
	if (false === is_int($curlRequest['connect_timeout'])) {
		throw new ErrorException(sprintf(
			'Integer type required, %s given', 
			gettype($curlRequest['connect_timeout'])
		));
	}
	$curlOptions[CURLOPT_CONNECTTIMEOUT] = $curlRequest['connect_timeout'];
}


// HEADERS
// An array of HTTP header fields to set, in the format array('Content-type: text/plain', 'Content-length: 100')
if (isset($curlRequest['headers'])) {
	if (false === is_array($curlRequest['headers'])) {
		throw new ErrorException(sprintf(
			'Array type required, %s given', 
			gettype($curlRequest['headers'])
		));
	}
	
	$headers = array();
	foreach ($curlRequest['headers'] as $key => $val) {
		
		if (false === is_string($key)) {
			continue;
		}
		
		if (false === is_string($val)) {
			throw new Exception(sprintf(
				'String type required, %s given', 
				gettype($val)
			));
		}
		
		$key = trim($key);
		$val = trim($val);
		
		if ($val === '') {
			continue;
		}
		
		switch (strtolower($key)):
			// The contents of the "Accept-Encoding: " header. This enables decoding of the response. 
			// Supported encodings are "identity", "deflate", and "gzip". If an empty string, "", is set, 
			// a header containing all supported encoding types is sent.
			// Added in cURL 7.10.
			case 'accept-encoding':
				$val = strtolower($val);
				/*
				switch ($val) {
				case 'identity':
				case 'deflate':
				case 'gzip':
					break;
				default:
				throw new Exception(sprintf('Unsupported encoding: %s', $val));
				}
				*/
				if (defined('CURLOPT_ENCODING')) {
					$curlOptions[CURLOPT_ENCODING] = $val;
				}
				break;
			
			//
			case 'cache-control':
				if (preg_match('/no-cache/i', $val)) {
					$curlOptions[CURLOPT_FRESH_CONNECT] = true;
				}
				break;
			
			// The contents of the "User-Agent: " header to be used in a HTTP request.
			case 'user-agent':
				$curlOptions[CURLOPT_USERAGENT] = $val;
				break;
			
			// The contents of the "Referer: " header to be used in a HTTP request.
			case 'referer':
				$curlOptions[CURLOPT_REFERER] = $val;
				break;
			
			// The contents of the "Cookie: " header to be used in the HTTP request. 
			// Note that multiple cookies are separated with a semicolon followed by a space (e.g., "fruit=apple; colour=red")
			case 'cookie':
				$curlOptions[CURLOPT_COOKIE] = $val;
				break;
		endswitch;
		
		$headers[] = sprintf('%s:%s', $key, $val);
	}
	
	$curlOptions[CURLOPT_HTTPHEADER] = $headers;
	unset($headers);
}


curl_setopt_array($GLOBALS['curlHandle'], $curlOptions);
$curlResponse = array();
$curlResponse['content'] 	= curl_exec($GLOBALS['curlHandle']);
$curlResponse['headers'] 	= $curlResponseHeaders;
$curlResponse['info'] 		= curl_getinfo($GLOBALS['curlHandle']);
$curlResponse['errno'] 		= curl_errno($GLOBALS['curlHandle']);
$curlResponse['error'] 		= curl_error($GLOBALS['curlHandle']);

if ($curlResponse['errno'] > CURLE_OK) {
	if (empty($curlResponse['error'])) {
		// @see: https://curl.se/libcurl/c/libcurl-errors.html
		$errorMessageList = [
			CURLE_UNSUPPORTED_PROTOCOL 			=> 'The URL you passed to libcurl used a protocol that this libcurl does not support. '
												.  'The support might be a compile-time option that you didn\'t use, it can be a misspelled '
												.  'protocol string or just a protocol libcurl has no code for.',
												
			CURLE_FAILED_INIT 					=> 'Very early initialization code failed. This is likely to be an internal error or problem, '
												.  'or a resource problem where something fundamental couldn\'t get done at init time.',
												
			CURLE_URL_MALFORMAT 				=> 'The URL was not properly formatted.',
			
			CURLE_NOT_BUILT_IN  				=> 'A requested feature, protocol or option was not found built-in in this libcurl due to a '
												.  'build-time decision. This means that a feature or option was not enabled or explicitly disabled '
												.  'when libcurl was built and in order to get it to function you have to get a rebuilt libcurl.',
												
			CURLE_COULDNT_RESOLVE_PROXY 		=> 'Couldn\'t resolve proxy. The given proxy host could not be resolved.',
			CURLE_COULDNT_RESOLVE_HOST 			=> 'Couldn\'t resolve host. The given remote host was not resolved.',
			CURLE_COULDNT_CONNECT 				=> 'Failed to connect() to host or proxy.',
			CURLE_FTP_WEIRD_SERVER_REPLY 		=> 'The server sent data libcurl couldn\'t parse.',
			CURLE_FTP_ACCESS_DENIED 			=> '',
			CURLE_FTP_USER_PASSWORD_INCORRECT 	=> '',
			CURLE_FTP_WEIRD_PASS_REPLY 			=> '',
			CURLE_FTP_WEIRD_USER_REPLY 			=> '',
			CURLE_FTP_WEIRD_PASV_REPLY 			=> '',
			CURLE_FTP_WEIRD_227_FORMAT 			=> '',
			CURLE_FTP_CANT_GET_HOST 			=> '',
			CURLE_FTP_CANT_RECONNECT 			=> '',
			CURLE_FTP_COULDNT_SET_BINARY 		=> '',
			CURLE_PARTIAL_FILE 					=> '',
			CURLE_FTP_COULDNT_RETR_FILE 		=> '',
			CURLE_FTP_WRITE_ERROR 				=> '',
			CURLE_FTP_QUOTE_ERROR 				=> '',
			CURLE_HTTP_NOT_FOUND 				=> '',
			CURLE_WRITE_ERROR 					=> '',
			CURLE_MALFORMAT_USER 				=> '',
			CURLE_FTP_COULDNT_STOR_FILE 		=> '',
			CURLE_READ_ERROR 					=> '',
			CURLE_OUT_OF_MEMORY 				=> '',
			CURLE_OPERATION_TIMEOUTED 			=> '',
			CURLE_FTP_COULDNT_SET_ASCII 		=> '',
			CURLE_FTP_PORT_FAILED 				=> '',
			CURLE_FTP_COULDNT_USE_REST 			=> '',
			CURLE_FTP_COULDNT_GET_SIZE 			=> '',
			CURLE_HTTP_RANGE_ERROR 				=> '',
			CURLE_HTTP_POST_ERROR 				=> '',
			CURLE_SSL_CONNECT_ERROR 			=> '',
			CURLE_FTP_BAD_DOWNLOAD_RESUME 		=> '',
			CURLE_FILE_COULDNT_READ_FILE 		=> '',
			CURLE_LDAP_CANNOT_BIND 				=> '',
			CURLE_LDAP_SEARCH_FAILED 			=> '',
			CURLE_LIBRARY_NOT_FOUND 			=> '',
			CURLE_FUNCTION_NOT_FOUND 			=> '',
			CURLE_ABORTED_BY_CALLBACK 			=> '',
			CURLE_BAD_FUNCTION_ARGUMENT 		=> '',
			CURLE_BAD_CALLING_ORDER 			=> '',
			CURLE_HTTP_PORT_FAILED 				=> '',
			CURLE_BAD_PASSWORD_ENTERED 			=> '',
			CURLE_TOO_MANY_REDIRECTS 			=> '',
			CURLE_UNKNOWN_TELNET_OPTION 		=> '',
			CURLE_TELNET_OPTION_SYNTAX 			=> '',
			CURLE_OBSOLETE 						=> '',
			CURLE_SSL_PEER_CERTIFICATE 			=> '',
			CURLE_GOT_NOTHING 					=> '',
			CURLE_SSL_ENGINE_NOTFOUND 			=> '',
			CURLE_SSL_ENGINE_SETFAILED 			=> '',
			CURLE_SEND_ERROR 					=> '',
			CURLE_RECV_ERROR 					=> '',
			CURLE_SHARE_IN_USE 					=> '',
			CURLE_SSL_CERTPROBLEM 				=> '',
			CURLE_SSL_CIPHER 					=> '',
			CURLE_SSL_CACERT 					=> '',
			CURLE_BAD_CONTENT_ENCODING 			=> '',
			CURLE_LDAP_INVALID_URL 				=> '',
			CURLE_FILESIZE_EXCEEDED 			=> '',
			CURLE_FTP_SSL_FAILED 				=> '',
			CURLE_SSH 							=> '',
			//CURLE_WEIRD_SERVER_REPLY 			=> '',
		];
		
		$curlResponse['error'] = 'Unknown error';
		if (isset($errorMessageList[$errorCode]))
			$curlResponse['error'] = $errorMessageList[$errorCode];
	}
	
	throw new ErrorException($curlResponse['error'], $curlResponse['errno']);
}

return $curlResponse;


?>