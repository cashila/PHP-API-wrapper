# Cashila API client

This package is a wrapper for [Cashila API](https://www.cashila.com/docs/api).

## Usage

You will need api key to use this. You can create one on [API page](https://www.cashila.com/api-keys).

```php
use Cashila\Api\Client;

$token = '[ api token ]';
$secret = '[ api secret ]';
// use sandbox server instead of production
$useSandbox = false;

$client = new Client($token, $secret, $useSandbox);

// fetches recent billpays
$res = $client->privateGet('billpays');
print_r($res);
```

## Examples

Create billpay:
```php
$res = $client->createBillPay([
  'amount' => 12,
  'currency' => 'EUR',
  'name' => 'Bruce Wayne',
  'address' => '1007 Mountain Drive',
  'postal_code' => '123',
  'city' => 'Gotham',
  'country_code' => 'US',
  'iban' => 'SI56020193466787867',
  'bic' => 'LJBASI2X',
]);
print_r($res);
```

Create billpay for saved recipient:
```php
$res = $client->createBillPayFor('[ recipient id ]', [
  'amount' => 42,
  'currency' => 'EUR'
]);
print_r($res);
```

Create recipient:
```php
$res = $client->createRecipient(array (
  'name' => 'Bruce Wayne',
  'address' => '1007 Mountain Drive',
  'postal_code' => '123',
  'city' => 'Gotham',
  'country_code' => 'US',
  'iban' => 'SI56020193466787867',
  'bic' => 'LJBASI2X',
));
print_r($res);
```

Upload verification
```php
$res = $client->updateVerification([
  "first_name" => "Peter",
  "last_name" =>"Griffin",
  "address" =>"Spooner street",
  "postal_code" =>"1234",
  "city" =>"Quahog",
  "country_code" =>"US"
], [
  'gov-id-front' => '[ path to picture of government id, front side ]',
  'residence' => '[ path to picture of proof of residence ]',
]);
print_r($res);
```


## BitID pairing

```php
use Cashila\Api\Client as Cashila;

// You will need to sign message with
// your wallet. Here we are using BitCoinRpc
// https://github.com/aceat64/EasyBitcoin-PHP
require 'BitcoinRpc.php';

// configure bitcoin rpc client
$btc_rpc_host = '127.0.0.1';
$btc_rpc_port = 8332;
$btc_rpc_username = '[ your bitcoin rpc username ]';
$btc_rpc_password = '[ your bitcoin rpc password ]';

// address from your wallet you want to pair with Cashila
$btc_address = '[ address you want to pair ]';

/*
 * Pairing wallet with cashila
 *
 * This needs to be done only once per wallet/user.
 * If address is already paired, you can skip to
 * retrieving token
 */
// bitid url to sign
// https://www.cashila.com/bitid-qrcode
$bitid_uri = '[ bitid url ]';

// bitcoin rpc client
$btc_rpc = new BitcoinRpc(
  $btc_rpc_username,
  $btc_rpc_password,
  $btc_rpc_host,
  $btc_rpc_port
);

// do pairing, this needs to be done only once
Cashila::bitIdPair($bitid_uri, function($uri) use($btc_rpc, $btc_address) {
  // sign uri
  $signature = $btc_rpc->signmessage($btc_address, $uri);
  return [
    'address'=>$btc_address,
    'signature'=>$signature
  ];
});

/*
 * Retrieving access token
 */
$client = Cashila::bitIdAuth(function($uri) use($btc_rpc, $btc_address) {
  // sign uri
  $signature = $btc_rpc->signmessage($btc_address, $uri);

  return [
    'address'=>$btc_address,
    'signature'=>$signature
  ];
});

// client has stored token and secret,
// from now on you can make requests
$res = $client->privateGet('recipients');
print_r($res);

// you can (and should) store token and
// secret for later use
$token = $client->getToken();
$secret = $client->getSecret();

// and use it at later time
$newClient = new Cashila($token, $secret);
$res = $newClient->privateGet('recipients');
print_r($res);
```

## Configuring defaults

You can set default environment (production or sandbox):

```php
Cashila\Api\Client::setDefaultSandbox(true);
```

## Call API methods directly

You can call API methods directly, by calling magic method, which takes name
in the following form:
```
(private|public)(get|post|put|delete)
```

I takes 3 arguments:
- resource path (without version), e.g. account/limits
- payload, can be array, string, or SplFileInfo (for file uploads)
- nonce

For example:
```php
$client->privateGet('accounts/limits');

```
