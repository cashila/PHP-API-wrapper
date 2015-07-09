<?php

namespace Cashila\Api;

/**
 * Reference implementation for Cashila's REST API.
 *
 * See https://www.cashila.com/docs/api for more info.
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 CASHILA OOD S.R.O.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
* Cashila API Client
*/
class Client {
  protected $_clientId;
  protected $_token;
  protected $_secret;
  protected $_sandbox;
  protected $_version;

  protected $_curl;

  protected $_prodUrl = 'https://www.cashila.com/api';
  protected $_sandboxUrl = 'https://sandbox.cashila.com/api';

  protected static $_defaultSandbox = false;
  protected static $_defaultVersion = 1;


  /**
   * Constructor
   *
   * @param string $token User's token
   * @param string $secret Token's secret
   * @param boolean $sandbox Use sandbox environment
   * @param string $version API version
   */
  public function __construct($token=null, $secret=null, $sandbox=null, $version=null) {
    $this->_token = $token;
    $this->_secret = $secret;
    $this->_sandbox = $sandbox;
    $this->_version = $version;
  }

  /**
  * Set client id
  *
  * @param string Client id
  * @return Client Client instance
  */
  public function setClientId($id) {
    $this->_clientId = $id;
    return $this;
  }

  /**
  * Get client id
  *
  * @return string Client id is set, null otherwise
  */
  public function getClientId() {
    return $this->_clientId;
  }

  /**
   *  Get API version
   *  @return string
   */
  public function getVersion() {
    return null!==$this->_version ? $this->_version : static::$_defaultVersion;
  }

  /**
   *  Returns true, if sandbox is enabled
   *  @return boolean
   */
  public function getSandbox() {
    return !!(null!==$this->_sandbox ? $this->_sandbox : static::$_defaultSandbox);
  }

  /**
   *  Enables/disable sandbox by default
   *  @param boolean sandbox enabled
   */
  public static function setDefaultSandbox($sandbox) {
    static::$_defaultSandbox = $sandbox;
  }

  /**
   *  Sets default API version
   *  @param string version number
   */
  public static function setDefaultVersion($version) {
    static::$_defaultVersion = $version;
  }

  /**
  * Set token and secret
  *
  * @param array should contain token and secret key
  * @return Client Client instance
  */
  public function setAuth($params) {
    return $this
      ->setToken($params['token'])
      ->setSecret($params['secret']);
  }

  /**
  * Get user's token
  *
  * @return string User's token
  */
  public function getToken() {
    return $this->_token;
  }

  /**
  * Set token's secret
  *
  * @param string Secret
  * @return Client Client instance
  */
  public function setToken($token) {
    $this->_token = $token;
    return $this;
  }

  /**
  * Get token's secret
  *
  * @return string Secret
  */
  public function getSecret() {
    return $this->_secret;
  }

  /**
  * Set token's secret
  *
  * @param string Secret
  * @return Client Client instance
  */
  public function setSecret($secret) {
    $this->_secret = $secret;
    return $this;
  }

  /**
  * Magic method for invoking api methods
  * in form (private|public)(get|post|put|delete)
  *
  * @param string path, e.g. billpays/create
  * @param array|string params, array which will be sent either as json payload or search string or string
  * @param int nonce, if not provided it defaults to current unix timestamp in miliseconds
  * @throws Exception
  * @throws \InvalidArgumentException
  * @return array response
  */
  public function __call($method, $args) {
    $matches = [];
    $numMatched = preg_match(
      '#^(?<section>private|public)(?<method>get|post|put|delete)$#i',
      $method,
      $matches
    );

    if ($numMatched) {
      $section = strtolower($matches['section']);
      $method = strtoupper($matches['method']);

      if (isset($args[0]) && is_string($args[0])) {
        $path = $args[0];
      } else {
        throw new \InvalidArgumentException("Missing or mismatch path argument.");
      }

      $nonce = null;
      $query = null;
      $payload = '';
      if (isset($args[1])) {
        if ($method=='GET') {
          $query = $args[1];
        } else if (is_array($args[1]) || is_a($args[1])) {
          $payload = json_encode($args[1]);
        } else if (is_string($args[1])) {
          $payload = $args[1];
        } else {
          throw new \InvalidArgumentException("Missing or mismatch payload argument.");
        }
      }

      if ($matches['section']=='private') {
        if (isset($args[2])) {
          $nonce = $args[2];
        } else {
          $nonce = $this->_generateNonce();
        }
      }

      $curl = $this->_prepareRequest($method, $path, $query, $payload, $nonce);
      return $this->_executeRequest($curl);
    }

    throw new \BadMethodCallException("Unknown method $method");
  }

  /**
  * Creates or returns prepared curl handle
  *
  * @return curl handle
  */
  protected function _getCurl() {
    if (null===$this->_curl) {
      $this->_curl = curl_init();
      curl_setopt_array($this->_curl, [
        CURLOPT_RETURNTRANSFER => true,
      ]);
    }

    return $this->_curl;
  }

  /**
  * Construct full request url based on invironment
  * @param string path, eg. v1/billpays/create
  * @return string url
  */
  protected function _envUrl($path) {
    if (!$this->getSandbox()) {
      return "{$this->_prodUrl}{$path}";
    }

    return "{$this->_sandboxUrl}{$path}";
  }

  /**
  * Generates miliseconds nonce.
  * @return integer nonce
  */
  protected function _generateNonce() {
    $nonce = explode(' ', microtime());
    return $nonce[1] . str_pad(substr($nonce[0], 2, 6), 6, '0');
  }

  /**
  * Prepares request: constructs url, headers (incl. payload signing)
  * @param string method, eg. get/post/...
  * @param string path, eg. billpays/create
  * @param array|string query
  * @param string payload, must already be serialized
  * @param string nonce
  * @param array headers, additional headers to send
  * @throws \InvalidArgumentException
  * @return resource curl handle
  */
  protected function _prepareRequest($method, $path, $query=null, $payload=null, $nonce=null, array $headers=[]) {
    $curl = $this->_getCurl();
    $normMethod = strtoupper($method);
    $isPathUri = !!preg_match('#^https?://#i', $path);

    if ($isPathUri && $nonce) {
      throw new \InvalidArgumentException("Cannot sign request if path is uri");
    }

    if ($clientId = $this->getClientId()) {
      $headers['API-Client'] = $clientId;
    }

    if (!$isPathUri) {
      $fullPath = "/v{$this->getVersion()}/$path";
      if (!empty($query)) {
        if (is_array($query)) {
          $fullPath .= '?'.http_build_query($query, '', '&');
        } else {
          $fullPath .= "?$query";
        }
      }
      $url = $this->_envUrl($fullPath);
    } else {
      $url = $path;
    }

    if ($nonce!==null) {
      if (null===$this->_token || null===$this->_secret) {
        throw new \InvalidArgumentException("Can not call private method without valid token and/or secret.");
      }

      $payloadHash = hash('sha256', $nonce.$payload, true);
      $rawSign = hash_hmac(
        'sha512',
        "{$method}{$fullPath}{$payloadHash}",
        base64_decode($this->_secret),
        true
      );
      $headers = array_merge($headers, [
        'API-User' => $this->_token,
        'API-Nonce' => $nonce,
        'API-Sign' => base64_encode($rawSign)
      ]);
    }

    if ($payload!=null) {
      curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
      $headers['Content-Type'] =  'application/json';
    } else {
      curl_setopt($curl, CURLOPT_POSTFIELDS, null);
    }

    curl_setopt_array($curl, [
      CURLOPT_URL => $url,
      CURLOPT_CUSTOMREQUEST => $method,
      CURLOPT_HTTPHEADER => array_map(function($name) use($headers) {
        return "$name: {$headers[$name]}";
      }, array_keys($headers))
    ]);

    return $curl;
  }

  /**
  * Execute request
  * @param resource curl handle
  * @throws Exception
  * @return array processed response
  */
  protected function _executeRequest($curl) {
    $response = curl_exec($curl);

    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    if ($code>=200 && $code<400) {
      $result = json_decode($response, true);
      if(!is_array($result)) {
        throw new Exception('JSON decode error');
      }

      if (!empty($result['error'])) {
        // construct exception
        $ex =new Exception($result['error']['message'], $result['error']['code']);
        if (isset($result['error']['user_message'])) {
          $ex->setUserMessage($result['error']['user_message']);
        }

        throw $ex;
      }

      if (isset($result['result'])) {
        return $result['result'];
      }
      return null;
    }

    throw new Exception("Request at ".curl_getinfo($curl, CURLINFO_EFFECTIVE_URL)." failed");
  }

  /**
   * Create new user account
   * @param array account params
   * @link https://www.cashila.com/docs/api#put/account
   * @return Client
   */
  public static function createAccount(array $params, $sandbox=null, $version=null) {
    $inst = new static(null, null, $sandbox, $version);
    $res = $this->publicPost('request-signup');

    $inst->setAuth($res);

    $res = $inst->privatePut("account", $params);

    return $inst;
  }

  /**
   * Processes BitID flow.
   * @param Client $client
   * @param string $uri bitid uri
   * @param callable $cb
   */
  protected function _processBitId(Client $client, $uri, callable $cb) {
    // sign payload
    $res = $cb($uri);
    if (!is_array($res) || !isset($res['address']) || !isset($res['signature'])) {
      throw new \InvalidArgumentException("Signing function must sign uri and return array with address and signature field set.");
    }

    // build post url
    $query = [];
    parse_str(parse_url($uri, PHP_URL_QUERY)?:'', $query);
    $http = empty($query['u']) ? 'https' : 'http'; // is http/https
    $postUrl = preg_replace('#bitid://#i', "$http://", $uri);

    // authorize
    $curl = $client->_prepareRequest('POST', $postUrl, null, json_encode([
      'address'=>$res['address'],
      'uri'=>$uri,
      'signature'=>$res['signature']
    ]));

    // store token/secret
    $res = $client->_executeRequest($curl);
    if ($res) {
      $client->setAuth($res);
    }
  }

  /**
   * Pair wallet using bitid protocol
   * @param string $uri BitID uri, available at https://www.cashila.com/bitid-qrcode
   * @param callable $cb Function will be called with uri parameter. Function must return array
   * with addresss and signature keys
   * @link https://www.cashila.com/docs/api#post/bitid/request-token
   * @return Client
   */
  public static function bitIdPair($uri, callable $cb) {
    $inst = new static();
    $inst->_processBitId($inst, $uri, $cb);
  }

  /**
   * Authenticate user using bitid protocol
   * @param callable $cb Function will be called with uri parameter. Function must return array
   * with addresss and signature keys
   * @link https://www.cashila.com/docs/api#post/bitid/request-token
   * @return Client
   */
  public static function bitIdAuth(callable $cb) {
    $inst = new static();

    // fetch bitid token
    $res = $inst->publicPost('bitid/request-token');

    // authorize
    $inst->_processBitId($inst, $res['uri'], $cb);

    return $inst;
  }
}
