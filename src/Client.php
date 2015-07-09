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
        } else if (is_array($args[1])) {
          $payload = json_encode($args[1]);
        } else if (is_string($args[1]) || is_object($args[1]) && $args[1] instanceof \SplFileInfo) {
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
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => 'Cashila PHP API Agent',
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
  * @param mixed payload, must already be serialized or instanceof \SplFileInfo
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
    $curlOptions = [];

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

      // if payload is file, we calculate hash using
      // tmp file to avoid excessive memory usage
      if (is_object($payload) && $payload instanceof \SplFileInfo) {
        // prepare files
        $payFp = fopen($payload->getPathname(), 'r');
        $tempName = tempnam(sys_get_temp_dir(), 'cashila_');
        $tmpFp = fopen($tempName, 'w');

        // write content
        fwrite($tmpFp, (string)$nonce);
        stream_copy_to_stream($payFp, $tmpFp);
        // payFp will be closed after it is uploaded
        fclose($tmpFp);

        // calc hash
        $payloadHash = hash_file('sha256', $tempName, true);

        // cleanup
        unlink($tempName);
      } else {
        $payloadHash = hash('sha256', $nonce.$payload, true);
      }

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

    $curlOptions = [
      CURLOPT_INFILE => null,
      CURLOPT_INFILESIZE => null,
      CURLOPT_PUT => false,
      CURLOPT_POSTFIELDS => null,
      CURLOPT_BINARYTRANSFER => false,
      CURLOPT_URL => $url,
      CURLOPT_CUSTOMREQUEST => $method,
    ];

    if ($payload!=null) {
      if ($payload instanceof \SplFileInfo) {
        $headers['Content-Type'] =  'application/octet-stream';

        $uploaded = 0;
        $totalSize = $payload->getSize();
        rewind($payFp);

        $curlOptions = array_replace($curlOptions, [
          CURLOPT_INFILE => $payFp,
          CURLOPT_INFILESIZE => $totalSize,
          CURLOPT_PUT => true,
          CURLOPT_BINARYTRANSFER => true,
          CURLOPT_READFUNCTION => function($curl, $fp, $maxSize) use(&$uploaded, $totalSize) {
            do {
              if (feof($fp)) {
                $res = '';
                break;
              }

              $res = fread($fp, $maxSize);
              if ($res===false) {
                $res = '';
                break;
              }

              $uploaded += strlen($res);
              if ($uploaded==$totalSize) {
                break;
              }

              return $res;
            } while(false);

            fclose($fp);
            return $res;
          }
        ]);
      } else {
        $headers['Content-Type'] =  'application/json';
        $curlOptions[CURLOPT_POSTFIELDS] = $payload;
      }
    }

    // build headers
    $curlOptions = array_replace($curlOptions, [
      CURLOPT_HTTPHEADER => array_map(function($name) use($headers) {
        return "$name: {$headers[$name]}";
      }, array_keys($headers))
    ]);
    curl_setopt_array($curl, $curlOptions);

    return $curl;
  }

  /**
  * Execute request
  * @param resource curl handle
  * @throws Exception
  * @return array processed response
  */
  protected function _executeRequest($curl, $isBitId=false) {
    $response = curl_exec($curl);
    if ($response===false) {
      throw new Exception('CURL error: '.curl_error($curl));
    }

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

      if ($isBitId) {
        return $result;
      }
      return $result['result'];
    }

    if ($isBitId) {
      $json = @json_decode($response, true);
      if (is_array($json) && isset($json['message'])) {
        $ex = new Exception($json['message']);
        if (isset($json['user_message'])) {
          $ex->setUserMessage($json['user_message']);
        }
        throw $ex;
      }
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
  protected function _processBitId(Client $client, $uri, callable $cb, $isBitId) {
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
    return $client->_executeRequest($curl, $isBitId);
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
    $inst->_processBitId($inst, $uri, $cb, true);
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
    $res = $inst->_processBitId($inst, $res['uri'], $cb, false);

    // store token and secret
    $inst->setAuth($res);

    return $inst;
  }

  /**
   *  @link http://localhost:8000/docs/api#get/exchange-rate/currency
   */
  public function getExchangeRate($currency='EUR') {
    $res = $this->publicGet("exchange-rate/$currency");
    return $res['rate'];
  }

  /**
   *  @link http://localhost:8000/docs/api#get/billpays
   */
  public function listBillPays(array $params=[]) {
    return $this->privateGet('billpays', $params);
  }

  /**
   *  @link http://localhost:8000/docs/api#get/billpays/id
   */
  public function getBillPay($id) {
    return $this->privateGet("billpays/$id");
  }

  /**
   *  @link http://localhost:8000/docs/api#post/billpays/id/revive
   */
  public function reviveBillPay($id) {
    return $this->privatePost("billpays/$id/revive");
  }

  /**
   *  @link http://localhost:8000/docs/api#delete/billpays/id
   */
  public function deleteBillPay($id) {
    return $this->privateDelete("billpays/$id");
  }

  /**
   *  @link http://localhost:8000/docs/api#put/billpays/id
   */
  public function createBillPayFor($recipientId, array $payment) {
    $params = array_merge([
      'based_on'=>$recipientId,
    ], $payment);
    return $this->privatePut('billpays/create', $params);
  }

  /**
   *  @link http://localhost:8000/docs/api#put/billpays/id
   */
  public function createBillPay(array $params) {
    return $this->privatePut('billpays/create', $params);
  }

  /**
   *  @link http://localhost:8000/docs/api#get/recipients
   */
  public function listRecipients(array $params=[]) {
    return $this->privateGet('recipients', $params);
  }

  /**
   *  @link http://localhost:8000/docs/api#get/recipients/id
   */
  public function getRecipient($id) {
    return $this->privateGet("recipients/$id");
  }

  /**
   *  @link http://localhost:8000/docs/api#delete/recipients/id
   */
  public function deleteRecipient($id) {
    return $this->privateDelete("recipients/$id");
  }

  /**
   *  @link http://localhost:8000/docs/api#delete/recipients/id
   */
  public function createRecipient(array $params) {
    return $this->privatePut("recipients", $params);
  }

  /**
   * http://localhost:8000/docs/api#get/verification
   */
  public function getVerification() {
    return $this->privateGet('verification');
  }

  /**
   * Updates verification details and uploads verification documents
   *
   * $documents array should be array of document filenames, where keys are:
   *   gov-id-front, gov-id-back and residence
   *
   * http://localhost:8000/docs/api#put/verification
   */
  public function updateVerification(array $personal, array $documents=[]) {
    // check if documents are readable
    array_walk($documents, function($filename) {
      if (!is_readable($filename)) {
        throw new \InvalidArgumentException("Documents array should contain readable paths to documents");
      }
    });

    $this->privatePut('verification', $personal);

    foreach ($documents as $type=>$fileName) {
      $this->privatePut("verification/{$type}", new \SplFileInfo($fileName));
    }

    return $this->privateGet('verification');
  }

  /**
   * @link http://localhost:8000/docs/api#get/account/limits
   */
  public function getAccountLimits() {
    return $this->privateGet('account/limits');
  }

  /**
   * @link http://localhost:8000/docs/api#post/account/deep-link
   */
  public function createDeepLink($resource) {
    return $this->privatePost('account/deep-link', [
      'resource' => $resource
    ]);
  }
}
