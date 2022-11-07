# PHP-Cloudflare-API-Module
PHP에서 작동하는 클라우드플레어 API 함수입니다..!!

# 사용방법
PHP 코드 상단에 `require_once 'cloudflare.php';`를 추가합니다

# 지원하는 함수
`cloudflare.php`를 열면 상단에 지원하는 API목록이 있습니다

## 캐시 (Cache)
|함수|한국어이름|영어이름
|:---|:---|:---|
|`cf_set_developer_mode(true of false)`|개발 모드|Development  Mode|
|`cf_get_developer_mode()`|개발 모드 상태|Development Mode Status|
|`cf_set_always_online()`|Always Online™|Always Online™|
|`cf_get_always_online()`|Always Online™ 상태|Always Online™ Status|
|`cf_set_browser_cache_ttl(0~31536000)`|브라우저 캐시 TTL|Browser Cache TTL|
|`cf_get_browser_cache_ttl()`|브라우저 캐시 TTL 상태|Browser Cache TTL Status|
|`cf_set_cache_level(aggressive, basic, simplified)`|캐싱 수준|Caching Level|
|`cf_get_cache_level()`|캐싱 수준 상태|Caching Level Status|
|`cf_purge_all_cache(true)`|모든 캐시 삭제|All Cache Remove|

## SSL
|함수|한국어이름|영어이름
|:---|:---|:---|
|`cf_set_ssl(flexible, full, strict, off)`|SSL/TLS 암호화 모드|SSL/TLS Encryption  Mode|
|`cf_get_ssl()`|SSL/TLS 암호화 모드 상태|SSL/TLS Encryption  Mode Status|
|`cf_get_ssl_verification_info()`|SSL 유효성 검사|SSL Verification|
|`cf_get_certificate_pack()`|SSL/TLS 엣지 인증서팩 나열|SSL/TLS Edge Certification List|
|`cf_set_browser_cache_ttl(0~31536000)`|브라우저 캐시 TTL|Browser Cache TTL|
|`cf_set_always_use_https(true or false)`|항상 HTTPS 사용|Always Use HTTPS|
|`cf_get_always_use_https()`|항상 HTTPS 사용 상태|Always Use HTTPS Status|
|`cf_get_security_header()`|HSTS(HTTP 엄격한 전송 보안) 상태|HSTS Status|
|`cf_set_min_tls_version(1.0, 1.1, 1.2, 1.3)`|최소 TLS 버전|Minimum TLS version|
|`cf_get_min_tls_version()`|최소 TLS 버전 상태|Minimum TLS version Status|
|`cf_set_opportunistic_encryption(true or false)`|편의적 암호화|Opportunistic Encryption|
|`cf_get_opportunistic_encryption()`|편의적 암호화 상태|Opportunistic Encryption Status|
|`cf_get_tls_1_3()`|TLS 1.3 사용하는 지역 상태|TLS 1.3 Using Area Status|
|`cf_set_auto_rewrite_https(true or false)`|자동 HTTPS 다시 쓰기|Automatic HTTPS Rewrite|
|`cf_set_auto_rewrite_https()`|자동 HTTPS 다시 쓰기 상태|Automatic HTTPS Rewrite Status|
|`cf_set_tls_client_auth(true or false)`|자동 HTTPS 다시 쓰기 상태|Automatic HTTPS Rewrite Status|

등등등 너무 많아서 나중에 쓸께요
