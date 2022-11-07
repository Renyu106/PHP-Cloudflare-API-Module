<?php
$account_id = "##CLOUDFLARE_ACCOUNT_ID##"; // Account ID
$zone_id = "##CLOUDFLARE_ZONE_ID##"; // zone ID
$auth_email = "##CLOUDFLARE_EMAIL##"; // Cloudflare Email
$auth_key = "##CLOUDFLARE_GOLBAL_KEY##"; // Cloudflare Global API Key


$cf_request_header = array(); // Request Header
$cf_request_header[] = 'X-Auth-Email: '.$auth_email.'';
$cf_request_header[] = 'X-Auth-Key: '.$auth_key.'';
$cf_request_header[] = 'Content-Type: application/json';

$cf_curl_opt = array();
$cf_curl_opt[CURLOPT_RETURNTRANSFER] = true;
$cf_curl_opt[CURLOPT_MAXREDIRS] = 10;
$cf_curl_opt[CURLOPT_TIMEOUT] = 0;
$cf_curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
$cf_curl_opt[CURLOPT_SSL_VERIFYHOST] = 0;
$cf_curl_opt[CURLOPT_FOLLOWLOCATION] = true;
$cf_curl_opt[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_1_1;
$cf_curl_opt[CURLOPT_HTTPHEADER] = $cf_request_header;
