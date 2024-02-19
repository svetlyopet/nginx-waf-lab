# About
This repository contains the needed configuration files for setting up a lab environment to measure the effectiveness of NGINX + ModSecurity + ModSecurity CoreRuleSet as a Web application firewall(WAF) and using a NGINX with default configuration as reverse proxy as a base for comparison.

NGINX version             = 1.25.4
ModSecurity version       = v3.0.12
ModSecurity Core Rule Set = 4.0.0 

# Test cases
Testcases copied from GoTestWAF only for Application security as reference.

# Setup
Run `docker compose up -d` in the root directory to setup test targets.
To generate malicious traffic run the GoTestWAF software in the same network:
```bash
docker run --rm --network=waf-test-lab -v $PWD/reports:/app/reports wallarm/gotestwaf:latest --url=http://nginx-with-waf:80 --noEmailReport --skipWAFBlockCheck --skipWAFIdentification --nonBlockedAsPassed
```
