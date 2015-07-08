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
