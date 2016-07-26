PHP SSL Certificate Tools
=========================

Manage SSL Certificate Signing Requests (CSRs) and SSL certificate chains with a PHP-based command-line all-in-one solution.  MIT or LGPL.

SSL certificates are hard to work with.  This tool dramatically simplifies the process of managing SSL certificates in a cross-platform solution.

Features
--------

* Creates Certificate Signing Requests (CSRs) the right way the first time.
* Saves answers to CSR questions.  Great for certificate renewals!  "How did I answer this question last year?"
* Import certificates signed elsewhere, form chains of certificates, and easily verify chain validity prior to use.
* Export complete certificate chains for use with most SSL enabled software products.
* Supports self-signing CSRs for personal use and running your own Certificate Authority (CA).
* Supports importing CSRs and then signing them using a CA certificate and private key.
* A complete, question/answer enabled command-line interface.
* Has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your project.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Getting Started
---------------

The command-line interface is question/answer enabled, which means all you have to do is run:

````
php ssl-certs.php
````

Which will enter interactive mode and guide you through the entire process.

Once you grow tired of manually entering information, you can pass in some or all the answers to the questions on the command-line:

````
php ssl-certs.php init

php ssl-certs.php csr

php ssl-certs.php -s csr id=www.domain.com bits= digest= domain=www.domain.com domain=domain.com domain= keyusage= country= state= city= org= orgunit= email= commonname=

php ssl-certs.php import-cert
````

The -s option suppresses normal output (except for fatal error conditions), which allows for the processed JSON result to be the only thing that is output.
