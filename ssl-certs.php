<?php
	// SSL/TLS certificate management tools in pure PHP.
	// (C) 2025 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/cli.php";
	require_once $rootpath . "/support/str_basics.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"s" => "suppressoutput",
			"?" => "help"
		),
		"rules" => array(
			"suppressoutput" => array("arg" => false),
			"help" => array("arg" => false)
		),
		"allow_opts_after_param" => false
	);
	$args = CLI::ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "SSL/TLS certificate command-line tool\n";
		echo "Purpose:  Create and manage SSL/TLS certificates and certificate chains.\n";
		echo "\n";
		echo "This tool is question/answer enabled.  Just running it will provide a guided interface.  It can also be run entirely from the command-line if you know all the answers.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options] [cmd [cmdoptions]]\n";
		echo "Options:\n";
		echo "\t-s   Suppress most output.  Useful for capturing JSON output.\n";
		echo "\n";
		echo "Examples:\n";
		echo "\tphp " . $args["file"] . "\n";
		echo "\tphp " . $args["file"] . " csr -name test\n";

		exit();
	}

	// Check enabled extensions.
	if (!extension_loaded("openssl"))  CLI::DisplayError("The 'openssl' PHP module is not enabled.  Please update the file '" . (php_ini_loaded_file() !== false ? php_ini_loaded_file() : "php.ini") . "' to enable the module.");

	$origargs = $args;
	$suppressoutput = (isset($args["opts"]["suppressoutput"]) && $args["opts"]["suppressoutput"]);

	// Get the command.
	$cmds = array("list" => "List all certificate storage objects", "init" => "Initialize a certificate storage object", "csr" => "Create a new Certificate Signing Request (CSR)", "self-sign" => "Self-sign a certificate (should only be used for roots and personal certs)", "sign" => "Sign a CSR using a CA enabled certificate with a private key", "get-info" => "Get detailed information about a certificate storage object", "set-signer" => "Sets the signer for a certificate for verify/export purposes", "verify" => "Verifies a certificate chain to the root", "export" => "Exports a certificate and certificate chain for use with other software products", "import-csr" => "Imports an externally generated CSR", "import-cert" => "Imports a signed certificate", "rename" => "Renames a certificate object and updates all child references to it", "delete" => "Deletes a certificate storage object");

	$cmd = CLI::GetLimitedUserInputWithArgs($args, false, "Command", false, "Available commands:", $cmds, true, $suppressoutput);

	// Make sure directories exist.
	@mkdir($rootpath . "/certs", 0700);
	@mkdir($rootpath . "/cache", 0700);

	function DisplayResult($result)
	{
		echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

		exit();
	}

	require_once $rootpath . "/support/phpseclib3/phpseclib3.php";

	function SSLObjectsList()
	{
		global $rootpath;

		$result = array("success" => true, "data" => array());
		$path = $rootpath . "/certs";
		$dir = opendir($path);
		if ($dir)
		{
			while (($file = readdir($dir)) !== false)
			{
				if ($file !== "." && $file !== ".." && is_file($path . "/" . $file) && substr($file, -5) == ".json")
				{
					$data = @json_decode(file_get_contents($path . "/" . $file), true);

					if (is_array($data))
					{
						$id = substr($file, 0, -5);

						$info = array();
						$info["id"] = $id;
						if (isset($data["csrinfo"]))  $info["csrinfo"] = $data["csrinfo"];
						if (isset($data["certinfo"]))  $info["certinfo"] = $data["certinfo"];
						$info["created"] = $data["created"];

						$result["data"][$id] = $info;
					}
				}
			}

			closedir($dir);
		}

		ksort($result["data"], SORT_NATURAL | SORT_FLAG_CASE);

		return $result;
	}

	function InitLastCSRAnswers($info)
	{
		$defaults = array(
			"pkimode" => "ec",
			"algorithm" => "secp256r1",
			"numbits" => "4096",
			"digest" => "sha256",
			"domains" => array(),
			"keyusage" => "digitalSignature, keyEncipherment, keyAgreement",
			"country" => "",
			"state" => "",
			"city" => "",
			"org" => "",
			"orgunit" => "",
			"email" => "",
		);

		return $info + $defaults;
	}

	function ExtractCSRInfo($info)
	{
		$csr = new \phpseclib3\File\X509();
		$csr->loadCSR($info["csr"]);

		$result = array();
		$result["privatekey"] = (isset($info["privatekey"]) && $info["privatekey"] !== "");
		$result["created"] = $info["created"];
		$result["dn"] = (string)$csr->getDN(\phpseclib3\File\X509::DN_STRING);

		$result["attrs"] = array();
		$attributes = $csr->getAttributes();
		foreach ($attributes as $attribute)
		{
			$result["attrs"][(string)$attribute] = json_decode(json_encode($csr->getAttribute($attribute)), true);
		}

		$result["exts"] = array();
		$extensions = $csr->getExtensions();
		foreach ($extensions as $extension)
		{
			$result["exts"][(string)$extension] = json_decode(json_encode($csr->getExtension($extension)), true);
		}

		return $result;
	}

	function ExtractCertInfo($info)
	{
		$decoder = new \phpseclib3\File\X509();
		$cert = $decoder->loadX509($info["cert"]);

		$result = array();
		$result["privatekey"] = (isset($info["privatekey"]) && $info["privatekey"] !== "");
		$result["created"] = $info["created"];
		$result["type"] = (string)$cert["tbsCertificate"]["version"];
		$result["serial"] = (string)$cert["tbsCertificate"]["serialNumber"];

		if (isset($cert["tbsCertificate"]["validity"]["notBefore"]["generalTime"]))  $result["validfrom"] = @strtotime($cert["tbsCertificate"]["validity"]["notBefore"]["generalTime"]);
		else if (isset($cert["tbsCertificate"]["validity"]["notBefore"]["utcTime"]))  $result["validfrom"] = @strtotime($cert["tbsCertificate"]["validity"]["notBefore"]["utcTime"]);
		else  $result["validfrom"] = -1;

		if (isset($cert["tbsCertificate"]["validity"]["notAfter"]["generalTime"]))  $result["validuntil"] = @strtotime($cert["tbsCertificate"]["validity"]["notAfter"]["generalTime"]);
		else if (isset($cert["tbsCertificate"]["validity"]["notAfter"]["utcTime"]))  $result["validuntil"] = @strtotime($cert["tbsCertificate"]["validity"]["notAfter"]["utcTime"]);
		else  $result["validuntil"] = -1;

		$result["signaturealgorithm"] = $cert["tbsCertificate"]["signature"]["algorithm"];
		$result["subjectalgorithm"] = $cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["algorithm"];

		$result["ca"] = $info["ca"];
		$result["signer"] = $info["signer"];

		$result["issuerdn"] = (string)$decoder->getIssuerDN(\phpseclib3\File\X509::DN_STRING);
		$result["subjectdn"] = (string)$decoder->getSubjectDN(\phpseclib3\File\X509::DN_STRING);

		$result["attrs"] = array();
		$attributes = $decoder->getAttributes();
		foreach ($attributes as $attribute)
		{
			$result["attrs"][(string)$attribute] = json_decode(json_encode($decoder->getAttribute($attribute)), true);
		}

		$result["exts"] = array();
		$extensions = $decoder->getExtensions();
		foreach ($extensions as $extension)
		{
			$result["exts"][(string)$extension] = json_decode(json_encode($decoder->getExtension($extension)), true);
		}

		return $result;
	}

	function GetSSLObject($question = "Storage object ID", $zeromsg = "No storage objects have been created.  Try creating your first storage object with the command:  init", $mode = "all", $ca = false, $withprivatekey = false)
	{
		global $suppressoutput, $args, $rootpath;

		if ($suppressoutput || CLI::CanGetUserInputWithArgs($args, "id"))  $id = CLI::GetUserInputWithArgs($args, "id", $question, false, "", $suppressoutput);
		else
		{
			$result = SSLObjectsList();
			if (!$result["success"])  DisplayResult($result);

			$ids = array();
			foreach ($result["data"] as $id => $info)
			{
				if ($mode === "csr" && !isset($info["csrinfo"]))  continue;
				if ($mode === "cert" && !isset($info["certinfo"]))  continue;
				if ($ca && (!isset($info["certinfo"]) || !$info["certinfo"]["ca"]))  continue;
				if (($mode === "all" || $mode === "csr") && $withprivatekey && isset($info["csrinfo"]) && !$info["csrinfo"]["privatekey"])  continue;
				if (($mode === "all" || $mode === "cert") && $withprivatekey && isset($info["certinfo"]) && !$info["certinfo"]["privatekey"])  continue;

				$options = array();
				if (isset($info["certinfo"]))  $options[] = "Certificate '" . $info["certinfo"]["subjectdn"] . "'" . ($info["certinfo"]["privatekey"] ? " with private key" : "");
				if (isset($info["certinfo"]) && $info["certinfo"]["signer"] !== "")  $options[] = "Signed by '" . $info["certinfo"]["signer"] . "'";
				if (isset($info["csrinfo"]))  $options[] = "CSR '" . $info["csrinfo"]["dn"] . "'";
				$options[] = "Object created " . date("M j, Y", $info["created"]);
				$ids[$id] = implode("\n\t", $options) . "\n";
			}
			if (!count($ids))  CLI::DisplayError($zeromsg);
			$id = CLI::GetLimitedUserInputWithArgs($args, "id", $question, false, "Available storage object IDs:", $ids, true, $suppressoutput);
		}

		$filename = $rootpath . "/certs/" . $id . ".json";
		if (!file_exists($filename))  CLI::DisplayError("File '" . $filename . "' does not exist.");

		$data = json_decode(file_get_contents($filename), true);

		if ($mode === "csr" && !isset($data["csrinfo"]))  CLI::DisplayError("The file '" . $filename . "' does not contain a Certificate Signing Request (CSR).");
		if ($mode === "cert" && !isset($data["certinfo"]))  CLI::DisplayError("The file '" . $filename . "' does not contain a certificate.");
		if ($ca && (!isset($data["certinfo"]) || !$data["certinfo"]["ca"]))  CLI::DisplayError("The file '" . $filename . "' is not declared to be a Certificate Authority (CA).");
		if (($mode === "all" || $mode === "csr") && $withprivatekey && isset($data["csrinfo"]) && !$data["csrinfo"]["privatekey"])  CLI::DisplayError("The file '" . $filename . "' does not contain a Certificate Signing Request (CSR) with a private key.");
		if (($mode === "all" || $mode === "cert") && $withprivatekey && isset($data["certinfo"]) && !$data["certinfo"]["privatekey"])  CLI::DisplayError("The file '" . $filename . "' does not contain a certificate with a private key.");

		// Upgrade old objects.
		if (!isset($data["last_csr_answers"]["pkimode"]))
		{
			$data["last_csr_answers"]["pkimode"] = "rsa";
			$data["last_csr_answers"]["algorithm"] = "rsa";
		}

		$data["last_csr_answers"] = InitLastCSRAnswers($data["last_csr_answers"]);

		$result = array(
			"id" => $id,
			"filename" => $filename,
			"data" => $data
		);

		return $result;
	}

	function GetSSLCSR($withprivatekey)
	{
		return GetSSLObject("CSR storage object ID", "No storage objects are available with a CSR" . ($withprivatekey ? " with a private key" : "") . ".", "csr", false, $withprivatekey);
	}

	function GetSSLCACert($withprivatekey)
	{
		return GetSSLObject("CA Certificate storage object ID", "No storage objects are available with a CA Certificate" . ($withprivatekey ? " with a private key" : "") . ".", "cert", true, $withprivatekey);
	}

	function GetSSLCert($withprivatekey)
	{
		return GetSSLObject("Certificate storage object ID", "No storage objects are available with a certificate" . ($withprivatekey ? " with a private key" : "") . ".", "cert", false, $withprivatekey);
	}

	function ReinitArgs($newargs)
	{
		global $args;

		// Process the parameters.
		$options = array(
			"shortmap" => array(
				"?" => "help"
			),
			"rules" => array(
			)
		);

		foreach ($newargs as $arg)  $options["rules"][$arg] = array("arg" => true, "multiple" => true);
		$options["rules"]["help"] = array("arg" => false);

		$args = CLI::ParseCommandLine($options, array_merge(array(""), $args["params"]));

		if (isset($args["opts"]["help"]))  DisplayResult(array("success" => true, "options" => array_keys($options["rules"])));
	}

	$pkimodes = array(
		"ec" => "Elliptic Curve - newer, slightly less software support",
		"rsa" => "RSA - broad software support"
	);

	$digests = array(
		"md2" => "MD2 is very old, very broken - do not use",
		"md5" => "MD5 is very old, very broken - do not use",
		"sha1" => "SHA-1 is old, quite broken - do not use",
		"sha224" => "SHA-224 is okay - less browser support",
		"sha256" => "SHA-256 is okay - excellent browser support",
		"sha384" => "SHA-384 is okay - less browser support",
		"sha512" => "SHA-512 is okay - less browser support",
	);

	if ($cmd === "list")
	{
		DisplayResult(SSLObjectsList());
	}
	else if ($cmd === "init")
	{
		ReinitArgs(array("id", "ca"));

		// Get the name of the new object.
		do
		{
			$id = CLI::GetUserInputWithArgs($args, "id", "Storage object ID", false, "A storage object contains everything pertinent to a single certificate:  CSR, answers to CSR questions for renewal purposes, private key, signed certificate, and parent/signer certificate object reference.  If this is for a domain (i.e. website), use the domain or subdomain name for easier tracking.", $suppressoutput);
			$id = Str::FilenameSafe($id);
			$filename = $rootpath . "/certs/" . $id . ".json";
			$found = file_exists($filename);
			if ($found)  CLI::DisplayError("A storage object with that ID already exists.  The file '" . $filename . "' already exists.", false, false);
		} while ($found);

		// Ask if this is going to be a CA.
		$ca = CLI::GetYesNoUserInputWithArgs($args, "ca", "Certificate Authority (CA)", "N", "The following question will set up the correct default key usage structure when you generate a Certificate Signing Request (CSR).", $suppressoutput);

		$data = array(
			"last_serial" => 0,
			"last_csr_answers" => InitLastCSRAnswers(array("keyusage" => ($ca ? "keyCertSign, cRLSign" : "digitalSignature, keyEncipherment, keyAgreement"))),
			"created" => time()
		);

		file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($filename, 0600);

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $id,
				"created" => $data["created"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "csr")
	{
		ReinitArgs(array("id", "pkimode", "algorithm", "bits", "digest", "domain", "keyusage", "country", "state", "city", "org", "orgunit", "email", "commonname"));

		// Get the object ID for the new CSR.
		$result = GetSSLObject();

		$id = $result["id"];
		$filename = $result["filename"];
		$data = $result["data"];

		// PKI mode.
		$pkimode = CLI::GetLimitedUserInputWithArgs($args, "pkimode", "PKI mode/type", $data["last_csr_answers"]["pkimode"], "Available PKI modes/types:", $pkimodes, true, $suppressoutput);

		if ($pkimode === "ec")
		{
			// Elliptic Curve.
			do
			{
				$algorithm = CLI::GetUserInputWithArgs($args, "algorithm", "Elliptic Curve name/algorithm", $data["last_csr_answers"]["algorithm"], "A named curve.  Popular names are:  secp256r1, Curve448, Curve25519, Ed448, Ed25519", $suppressoutput);
				if (!class_exists("\\phpseclib3\\Crypt\\EC\\Curves\\" . $algorithm, false))  CLI::DisplayError("Class not found.  Unknown named curve.", false, false);
				else  break;
			} while (true);

			$numbits = $data["last_csr_answers"]["numbits"];
		}
		else if ($pkimode === "rsa")
		{
			// RSA.
			$algorithm = "rsa";

			// Number of bits.
			do
			{
				$numbits = (int)CLI::GetUserInputWithArgs($args, "bits", "Number of bits", $data["last_csr_answers"]["numbits"], "The more bits in a generated certificate, the more secure the connection.  However, the more bits there are, the longer it takes to connect to a server.  Must be at least 1024 bits but the default of 4096 is reasonably strong.", $suppressoutput);
				if ($numbits < 1024)  CLI::DisplayError("Invalid number of bits specified.  Must be at least 1024.", false, false);
			} while ($numbits < 1024);
		}

		// Digest algorithm.
		$digest = CLI::GetLimitedUserInputWithArgs($args, "digest", "Digest algorithm", $data["last_csr_answers"]["digest"], "Available digests (hash algorithms):", $digests, true, $suppressoutput);

		// Get the domains.
		$domains = array();
		do
		{
			$domain = CLI::GetUserInputWithArgs($args, "domain", "Domain name #" . (count($domains) + 1), (isset($data["last_csr_answers"]["domains"][count($domains)]) ? $data["last_csr_answers"]["domains"][count($domains)] : "-"), "", $suppressoutput);
			if ($domain === "-")  $domain = "";
			if ($domain !== "")  $domains[] = $domain;
		} while ($domain !== "");

		// Get the key usage.
		$keyusage = CLI::GetUserInputWithArgs($args, "keyusage", "Key usage", $data["last_csr_answers"]["keyusage"], "Comma-separated list of key usages.  Can be any combination of:  digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly.\n\nMost Certificate Authorities (CAs) use:  keyCertSign, cRLSign.\nNormal certificates use:  digitalSignature, keyEncipherment, keyAgreement.", $suppressoutput);

		// Distinguished Name information.
		$country = CLI::GetUserInputWithArgs($args, "country", "Optional:  Country name (two-letter code)", $data["last_csr_answers"]["country"], "The next few questions are optional.  To declare a specific field as empty, use a hyphen.", $suppressoutput);
		$state = CLI::GetUserInputWithArgs($args, "state", "Optional:  State or province name (abbreviation)", $data["last_csr_answers"]["state"], "", $suppressoutput);
		$city = CLI::GetUserInputWithArgs($args, "city", "Optional:  City or locality", $data["last_csr_answers"]["city"], "", $suppressoutput);
		$org = CLI::GetUserInputWithArgs($args, "org", "Optional:  Organization name", $data["last_csr_answers"]["org"], "", $suppressoutput);
		$orgunit = CLI::GetUserInputWithArgs($args, "orgunit", "Optional:  Organizational unit name", $data["last_csr_answers"]["orgunit"], "", $suppressoutput);
		$email = CLI::GetUserInputWithArgs($args, "email", "Optional:  E-mail address", $data["last_csr_answers"]["email"], "", $suppressoutput);
		$commonname = CLI::GetUserInputWithArgs($args, "commonname", "Common name", (isset($data["last_csr_answers"]["commonname"]) ? $data["last_csr_answers"]["commonname"] : (count($domains) ? $domains[0] : false)), "", $suppressoutput);

		if ($country === "-")  $country = "";
		if ($state === "-")  $state = "";
		if ($city === "-")  $city = "";
		if ($org === "-")  $org = "";
		if ($orgunit === "-")  $orgunit = "";
		if ($email === "-")  $email = "";
		if ($commonname === "-")  $commonname = "";

		$data["last_csr_answers"] = InitLastCSRAnswers(array(
			"pkimode" => $pkimode,
			"algorithm" => $algorithm,
			"numbits" => (string)$numbits,
			"digest" => $digest,
			"domains" => $domains,
			"keyusage" => $keyusage,
			"country" => $country,
			"state" => $state,
			"city" => $city,
			"org" => $org,
			"orgunit" => $orgunit,
			"email" => $email,
			"commonname" => $commonname
		));

		// Generate the CSR.
		if (!$suppressoutput)  echo "\nGenerating CSR... (this can take a while!)\n";

		if ($pkimode === "ec")  $privatekey = \phpseclib3\Crypt\EC::createKey($algorithm)->withHash($digest);
		else  $privatekey = \phpseclib3\Crypt\RSA::createKey($numbits)->withHash($digest);

		$publickey = $privatekey->getPublicKey();

		$data["csr"] = array(
			"publickey" => (string)$publickey,
			"privatekey" => (string)$privatekey,
		);

		$csr = new \phpseclib3\File\X509();
		$csr->setPrivateKey($privatekey);
		$csr->setPublicKey($publickey);

		if ($country !== "")
		{
			if (!$csr->setDNProp("id-at-countryName", $country))  CLI::DisplayError("Unable to set countryName (country) in the CSR.");
		}

		if ($state !== "")
		{
			if (!$csr->setDNProp("id-at-stateOrProvinceName", $state))  CLI::DisplayError("Unable to set stateOrProvinceName (state) in the CSR.");
		}

		if ($city !== "")
		{
			if (!$csr->setDNProp("id-at-localityName", $city))  CLI::DisplayError("Unable to set localityName (city) in the CSR.");
		}

		if ($org !== "")
		{
			if (!$csr->setDNProp("id-at-organizationName", $org))  CLI::DisplayError("Unable to set organizationName (organization name) in the CSR.");
		}

		if ($orgunit !== "")
		{
			if (!$csr->setDNProp("id-at-organizationalUnitName", $orgunit))  CLI::DisplayError("Unable to set organizationalUnitName (organizational unit name) in the CSR.");
		}

		if ($email !== "")
		{
			if (!$csr->setDNProp("id-emailAddress", $email))  CLI::DisplayError("Unable to set emailAddress (e-mail address) in the CSR.");
		}

		if ($commonname !== "")
		{
			// Use the specified commonName.
			$csr->removeDNProp("id-at-commonName");
			if (!$csr->setDNProp("id-at-commonName", $commonname))  CLI::DisplayError("Unable to set commonName (common name) in the CSR.");
		}

		// Have to sign, save, and load the CSR to add extensions.
		$csr->loadCSR($csr->saveCSR($csr->signCSR()));

		$keyusage2 = explode(",", $keyusage);
		foreach ($keyusage2 as $num => $val)  $keyusage2[$num] = trim($val);
		if (!$csr->setExtension("id-ce-keyUsage", $keyusage2))  CLI::DisplayError("Unable to set extension keyUsage in the CSR.");

		if (count($domains))
		{
			$domains2 = array();
			foreach ($domains as $domain)
			{
				$domains2[] = array("dNSName" => $domain);
			}

			if (!$csr->setExtension("id-ce-subjectAltName", $domains2))  CLI::DisplayError("Unable to set extension subjectAltName in the CSR.");
		}

		// Sign and save the CSR.
		$data["csr"]["csr"] = $csr->saveCSR($csr->signCSR());
		$data["csr"]["created"] = time();

		// Extract information from the CSR.
		$data["csrinfo"] = ExtractCSRInfo($data["csr"]);

		file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($filename, 0600);

		if (!$suppressoutput)  echo "\nGenerated CSR:\n\n" . $data["csr"]["csr"] . "\n\n";

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $id,
				"csr" => $data["csr"]["csr"],
				"csrinfo" => $data["csrinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "self-sign")
	{
		ReinitArgs(array("id", "ca", "days", "digest"));

		// Get a CSR with a private key.
		$result = GetSSLCSR(true);

		$id = $result["id"];
		$filename = $result["filename"];
		$data = $result["data"];

		// Ask if this is a CA.
		$ca = CLI::GetYesNoUserInputWithArgs($args, "ca", "Certificate Authority (CA)", "N", "Declaring this self-signed certificate as a Certificate Authority implies it will be a root certificate that will be used to sign other certificates.  Preferably, root CA certs are stored in offline, air-gapped systems and used exclusively to generate intermediate CA certificates, which will then be used to sign server and client certificates.", $suppressoutput);

		// Ask how long to allow the certificate to be valid for.
		$days = (int)CLI::GetUserInputWithArgs($args, "days", "How many days to sign the certificate for", ($ca ? "3650" : "365"), "", $suppressoutput);
		if ($days < 0)  $days = 1;

		// Digest algorithm.
		$digest = CLI::GetLimitedUserInputWithArgs($args, "digest", "Digest algorithm", "sha256", "Available digests (hash algorithms):", $digests, true, $suppressoutput);

		// Generate the certificate.
		if (!$suppressoutput)  echo "\nSelf-signing CSR... (this can take a while!)\n";

		$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($data["csr"]["privatekey"])->withHash($digest);

		$issuer = new \phpseclib3\File\X509();
		$issuer->loadCSR($data["csr"]["csr"]);
		$issuer->setPrivateKey($privatekey);
		if ($issuer->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$subject = new \phpseclib3\File\X509();
		$subject->loadCSR($data["csr"]["csr"]);
		if ($subject->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$certsigner = new \phpseclib3\File\X509();
		if ($ca)  $certsigner->makeCA();
		$certsigner->setStartDate("-1 day");
		$certsigner->setEndDate("+" . $days . " day");
		$data["last_serial"]++;
		$certsigner->setSerialNumber($data["last_serial"], 10);

		$signed = $certsigner->sign($issuer, $subject);
		if ($signed === false)  CLI::DisplayError("Unable to self-sign CSR.");
		$cert = $certsigner->saveX509($signed);

		$data["cert"] = array(
			"privatekey" => $data["csr"]["privatekey"],
			"publickey" => $data["csr"]["publickey"],
			"cert" => $cert,
			"created" => time(),
			"ca" => $ca,
			"signer" => $id
		);

		// Extract information from the certificate.
		$data["certinfo"] = ExtractCertInfo($data["cert"]);

		// Remove the CSR since it is no longer needed.
		unset($data["csr"]);
		unset($data["csrinfo"]);

		file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($filename, 0600);

		if (!$suppressoutput)  echo "\nSigned Certificate:\n\n" . $data["cert"]["cert"] . "\n\n";

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $id,
				"cert" => $data["cert"]["cert"],
				"certinfo" => $data["certinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "sign")
	{
		ReinitArgs(array("id", "ca", "days", "digest", "bits", "redo", "domain", "keyusage", "country", "state", "city", "org", "orgunit", "email", "commonname"));

		// Get a CA certificate with private key that is allowed to sign certificates.
		do
		{
			$result = GetSSLCACert(true);

			$ca_id = $result["id"];
			$ca_filename = $result["filename"];
			$ca_data = $result["data"];

			// Load the CA certificate.
			$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($ca_data["cert"]["privatekey"]);

			$issuer = new \phpseclib3\File\X509();
			$issuer->loadX509($ca_data["cert"]["cert"]);

			// Confirm that the CA is allowed to sign certificates (keyCertSign).
			$keyusages = $issuer->getExtension("id-ce-keyUsage");
			$valid = (!is_array($keyusages) || in_array("keyCertSign", $keyusages));
			if (!$valid)  CLI::DisplayError("The selected Certificate Authority does not have the 'keyCertSign' key usage and therefore may not be used to sign certificates.  Select another Certificate Authority.", false, false);

		} while (!$valid);

		// Retrieve a CSR to sign.
		do
		{
			// Don't need a private key to exist (e.g. a temporary CSR import).
			$result = GetSSLCSR(false);

			$valid = ($result["id"] !== $ca_id);
			if (!$valid)  CLI::DisplayError("The CA object ID is identical to the CSR object ID.  Self-signing a certificate is not allowed in normal signing mode.", false, false);

		} while (!$valid);

		$csr_id = $result["id"];
		$csr_filename = $result["filename"];
		$csr_data = $result["data"];

		// Ask if this is a CA.
		$ca = CLI::GetYesNoUserInputWithArgs($args, "ca", "Certificate Authority (CA)", "N", "Declaring this certificate as a Certificate Authority implies it will be a intermediate certificate that will be used to sign other certificates.", $suppressoutput);

		// Ask how long to allow the certificate to be valid for.
		$days = (int)CLI::GetUserInputWithArgs($args, "days", "How many days to sign the certificate for", ($ca ? "3650" : "365"), "", $suppressoutput);
		if ($days < 0)  $days = 1;

		// Digest algorithm.
		$digest = CLI::GetLimitedUserInputWithArgs($args, "digest", "Digest algorithm", "sha256", "Available digests (hash algorithms):", $digests, true, $suppressoutput);

		$privatekey = $privatekey->withHash($digest);
		$issuer->setPrivateKey($privatekey);

		// Load the CSR.
		$subject = new \phpseclib3\File\X509();
		$subject->loadCSR($csr_data["csr"]["csr"]);
		if ($subject->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		$publickey = $subject->getPublicKey();

		// Ask for the minimum number of bits required for RSA public keys before signing.
		if ($publickey instanceof \phpseclib\Crypt\RSA)
		{
			do
			{
				$numbits = (int)CLI::GetUserInputWithArgs($args, "bits", "Minimum number of bits required", "4096", "The next question allows a minimum number of bits to be enforced for the CSR RSA public key prior to signing it.", $suppressoutput);
				if ($numbits < 1024)  CLI::DisplayError("Invalid number of bits specified.  Must be at least 1024.", false, false);
			} while ($numbits < 1024);

			if ($numbits > $publickey->getSize())  CLI::DisplayError("Invalid number of bits for the CSR RSA public key.  Expected at least " . $numbits . " bits.  CSR RSA public key is only " . $publickey->getSize() . " bits.");
		}

		$redo = CLI::GetYesNoUserInputWithArgs($args, "redo", "Re-enter CSR information (domains, key usage, common name, etc)", "Y", "CSR information:\n\n" . json_encode($csr_data["csrinfo"], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), $suppressoutput);

		if ($redo)
		{
			// Strip existing DNs, attributes, and extensions.
			$dn = $subject->getDN();
			$dn = $dn["rdnSequence"];
			for ($x = 0; $x < count($dn); $x++)
			{
				$subject->removeDNProp($dn[$x][0]["type"]);
			}
			$subject->removeDNProp("id-emailAddress");

			$extensions = $subject->getExtensions();
			foreach ($extensions as $extension)
			{
				$subject->removeExtension($extension);
			}

			$attributes = $subject->getAttributes();
			foreach ($attributes as $attribute)
			{
				$subject->removeAttribute($attribute);
			}

			// Get the domains.
			$domains = array();
			do
			{
				$domain = CLI::GetUserInputWithArgs($args, "domain", "Domain name #" . (count($domains) + 1), "-", "", $suppressoutput);
				if ($domain === "-")  $domain = "";
				if ($domain !== "")  $domains[] = $domain;
			} while ($domain !== "");

			// Get the key usage.
			$keyusage = CLI::GetUserInputWithArgs($args, "keyusage", "Key usage", ($ca ? "keyCertSign, cRLSign" : "digitalSignature, keyEncipherment, keyAgreement"), "Comma-separated list of key usages.  Can be any combination of:  digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly.  Most Certificate Authorities (CAs) use:  keyCertSign, cRLSign.  Normal certificates use:  digitalSignature, keyEncipherment, keyAgreement.", $suppressoutput);
			if ($keyusage === "-")  $keyusage = "";

			// Distinguished Name information.
			$country = CLI::GetUserInputWithArgs($args, "country", "Optional:  Country name (two-letter code)", "", "The next few questions are optional.", $suppressoutput);
			$state = CLI::GetUserInputWithArgs($args, "state", "Optional:  State or province name (abbreviation)", "", "", $suppressoutput);
			$city = CLI::GetUserInputWithArgs($args, "city", "Optional:  City or locality", "", "", $suppressoutput);
			$org = CLI::GetUserInputWithArgs($args, "org", "Optional:  Organization name", "", "", $suppressoutput);
			$orgunit = CLI::GetUserInputWithArgs($args, "orgunit", "Optional:  Organizational unit name", "", "", $suppressoutput);
			$email = CLI::GetUserInputWithArgs($args, "email", "Optional:  E-mail address", "", "", $suppressoutput);
			$commonname = CLI::GetUserInputWithArgs($args, "commonname", "Common name", (count($domains) ? $domains[0] : false), "", $suppressoutput);

			if ($country !== "")
			{
				if (!$subject->setDNProp("id-at-countryName", $country))  CLI::DisplayError("Unable to set countryName (country) in the CSR.");
			}

			if ($state !== "")
			{
				if (!$subject->setDNProp("id-at-stateOrProvinceName", $state))  CLI::DisplayError("Unable to set stateOrProvinceName (state) in the CSR.");
			}

			if ($city !== "")
			{
				if (!$subject->setDNProp("id-at-localityName", $city))  CLI::DisplayError("Unable to set localityName (city) in the CSR.");
			}

			if ($org !== "")
			{
				if (!$subject->setDNProp("id-at-organizationName", $org))  CLI::DisplayError("Unable to set organizationName (organization name) in the CSR.");
			}

			if ($orgunit !== "")
			{
				if (!$subject->setDNProp("id-at-organizationalUnitName", $orgunit))  CLI::DisplayError("Unable to set organizationalUnitName (organizational unit name) in the CSR.");
			}

			if ($email !== "")
			{
				if (!$subject->setDNProp("id-emailAddress", $email))  CLI::DisplayError("Unable to set emailAddress (e-mail address) in the CSR.");
			}

			if ($commonname !== "")
			{
				// Use the specified commonName.
				$subject->removeDNProp("id-at-commonName");
				if (!$subject->setDNProp("id-at-commonName", $commonname))  CLI::DisplayError("Unable to set commonName (common name) in the CSR.");
			}

			$keyusage2 = explode(",", $keyusage);
			foreach ($keyusage2 as $num => $val)  $keyusage2[$num] = trim($val);
			if (!$subject->setExtension("id-ce-keyUsage", $keyusage2))  CLI::DisplayError("Unable to set extension keyUsage in the CSR.");

			if (count($domains))
			{
				$domains2 = array();
				foreach ($domains as $domain)
				{
					$domains2[] = array("dNSName" => $domain);
				}
				if (!$subject->setExtension("id-ce-subjectAltName", $domains2))  CLI::DisplayError("Unable to set extension subjectAltName in the CSR.");
			}
		}

		// Generate the certificate.
		if (!$suppressoutput)  echo "\nSigning CSR... (this can take a while!)\n";

		$certsigner = new \phpseclib3\File\X509();
		if ($ca)  $certsigner->makeCA();
		$certsigner->setStartDate("-1 day");
		$certsigner->setEndDate("+" . $days . " day");
		$ca_data["last_serial"]++;
		$certsigner->setSerialNumber($ca_data["last_serial"], 10);

		$signed = $certsigner->sign($issuer, $subject);
		if ($signed === false)  CLI::DisplayError("Unable to sign CSR.");
		$cert = $certsigner->saveX509($signed);

		$csr_data["cert"] = array(
			"privatekey" => $csr_data["csr"]["privatekey"],
			"publickey" => $csr_data["csr"]["publickey"],
			"cert" => $cert,
			"created" => time(),
			"ca" => $ca,
			"signer" => $ca_id
		);

		// Extract information from the certificate.
		$csr_data["certinfo"] = ExtractCertInfo($csr_data["cert"]);

		// Remove the CSR since it is no longer needed.
		unset($csr_data["csr"]);
		unset($csr_data["csrinfo"]);

		file_put_contents($csr_filename, json_encode($csr_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($csr_filename, 0600);

		file_put_contents($ca_filename, json_encode($ca_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($ca_filename, 0600);

		if (!$suppressoutput)  echo "\nSigned Certificate:\n\n" . $csr_data["cert"]["cert"] . "\n\n";

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $csr_id,
				"ca_id" => $ca_id,
				"cert" => $csr_data["cert"]["cert"],
				"certinfo" => $csr_data["certinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "get-info")
	{
		ReinitArgs(array("id"));

		// Get the object ID.
		$result = GetSSLObject();

		if (isset($result["data"]["csr"]))  $result["data"]["csr"] = $result["data"]["csr"]["csr"];
		if (isset($result["data"]["cert"]))  $result["data"]["cert"] = $result["data"]["cert"]["cert"];

		$result = array(
			"sucess" => true,
			"info" => $result
		);

		DisplayResult($result);
	}
	else if ($cmd === "set-signer")
	{
		ReinitArgs(array("id"));

		// Get the certificate name.
		$result = GetSSLCert(false);

		$cert_id = $result["id"];
		$cert_filename = $result["filename"];
		$cert_data = $result["data"];

		// Get the CA signer name.
		$result = GetSSLCACert(false);

		$ca_id = $result["id"];
		$ca_filename = $result["filename"];
		$ca_data = $result["data"];

		$cert_data["cert"]["signer"] = $ca_id;

		// Extract information from the certificate.
		$cert_data["certinfo"] = ExtractCertInfo($cert_data["cert"]);

		file_put_contents($cert_filename, json_encode($cert_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($cert_filename, 0600);

		$result = array(
			"sucess" => true,
			"info" => array(
				"id" => $cert_id,
				"ca_id" => $ca_id,
				"cert" => $cert_data["cert"]["cert"],
				"certinfo" => $cert_data["certinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "verify")
	{
		ReinitArgs(array("id"));

		// Get the certificate name.
		$result = GetSSLCert(false);

		$currid = $result["id"];
		$lastid = "";
		$lastcert = "";
		$certs = array();
		while ($currid !== ""  && $currid !== $lastid)
		{
			$filename = $rootpath . "/certs/" . $currid . ".json";
			if (!file_exists($filename))  CLI::DisplayError("File '" . $filename . "' does not exist.");

			$data = json_decode(file_get_contents($filename), true);

			if (!isset($data["cert"]))  CLI::DisplayError("The file '" . $filename . "' does not contain a certificate.");

			$currcert = $data["cert"]["cert"];

			$cert = new \phpseclib3\File\X509();
			if (!$cert->loadX509($currcert))  CLI::DisplayError("Unable to load the certificate in '" . $currid . "'.");

			if ($lastid !== "")
			{
				$cert = new \phpseclib3\File\X509();
				if (!$cert->loadCA($currcert))  CLI::DisplayError("Unable to load the certificate in '" . $currid . "' as a CA.");
				if (!$cert->loadX509($lastcert))  CLI::DisplayError("Unable to load the certificate in '" . $lastid . "'.");
				if ($cert->validateSignature() !== true)  CLI::DisplayError("Unable to validate the signature of the certificate in '" . $lastid . "' using the certificate in '" . $currid . "'.  The certificate chain is invalid.");
			}

			$certs[$currid] = $currcert;

			$lastid = $currid;
			$lastcert = $currcert;

			$currid = $data["cert"]["signer"];
		}

		// Test the root certificate.
		if ($lastid !== "")
		{
			$cert = new \phpseclib3\File\X509();
			if (!$cert->loadX509($lastcert))  CLI::DisplayError("Unable to load the certificate in '" . $lastid . "'.");
			if ($cert->validateSignature() !== false || $cert->validateSignature(false) !== true)  CLI::DisplayError("Unable to validate the signature of the certificate in '" . $lastid . "' as a root/self-signed certificate.");
		}

		if (!$suppressoutput)  echo "\nThe entire certificate chain is valid.\n";

		$result = array(
			"success" => true,
			"ids" => array_keys($certs),
			"certs" => array_values($certs)
		);

		DisplayResult($result);
	}
	else if ($cmd === "export")
	{
		ReinitArgs(array("id"));

		// Get the certificate name.
		$result = GetSSLObject();

		$baseid = $result["id"];

		$paths = array();
		$datamap = array();
		$data = $result["data"];

		if (isset($data["csr"]))
		{
			$csr = new \phpseclib3\File\X509();
			if (!$csr->loadCSR($data["csr"]["csr"]))  CLI::DisplayError("Unable to load the CSR.");
			if ($csr->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

			// Write the private key to disk in PKCS#8 format if it is defined.
			if ($data["csr"]["privatekey"] !== "")
			{
				$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($data["csr"]["privatekey"]);

				$paths["csr_key"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_private_key.pem";
				$datamap["csr_key"] = (string)$privatekey;
			}

			// Write the CSR to disk in multiple formats.
			$paths["csr_pem"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_csr.pem";
			$datamap["csr_pem"] = $data["csr"]["csr"];

			$paths["csr_der"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_csr.der";
			$datamap["csr_der"] = $csr->saveCSR($csr->getCurrentCert(), \phpseclib3\File\X509::FORMAT_DER);
		}

		if (isset($data["cert"]))
		{
			$cert = new \phpseclib3\File\X509();
			if (!$cert->loadX509($data["cert"]["cert"]))  CLI::DisplayError("Unable to load the certificate.");

			// Write the private key to disk in PKCS#8 format if it is defined.
			if ($data["cert"]["privatekey"] !== "")
			{
				$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($data["cert"]["privatekey"]);

				// The path here is intentionally identical to the CSR path.  This key will overwrite the CSR key.
				$paths["cert_key"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_private_key.pem";
				$datamap["cert_key"] = (string)$privatekey;
			}

			// Write the base certificate to disk in multiple formats.
			$paths["cert_pem"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_cert.pem";
			$datamap["cert_pem"] = $data["cert"]["cert"];

			$paths["cert_der"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_cert.der";
			$datamap["cert_der"] = $cert->saveX509($cert->getCurrentCert(), \phpseclib3\File\X509::FORMAT_DER);

			// Now read the remaining certificates in the chain in leaf to root order.
			$currid = $baseid;
			$lastid = "";
			$rootcerts = array();
			$certchain = array();
			while ($currid !== ""  && $currid !== $lastid)
			{
				$filename = $rootpath . "/certs/" . $currid . ".json";
				if (!file_exists($filename))  CLI::DisplayError("File '" . $filename . "' does not exist.", false, false);

				$data = json_decode(file_get_contents($filename), true);

				if (!isset($data["cert"]))  break;

				if ($lastid !== "")  $rootcerts[] = $data["cert"]["cert"];
				$certchain[] = $data["cert"]["cert"];

				$lastid = $currid;

				$currid = $data["cert"]["signer"];
			}

			$paths["root_certs"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_root_certs.pem";
			$datamap["root_certs"] = implode("\r\n", $rootcerts);

			$paths["cert_chain"] = $rootpath . "/cache/" . $baseid . "/" . $baseid . "_chain.pem";
			$datamap["cert_chain"] = implode("\r\n", $certchain);
		}

		// Write the whole mess to disk.
		@mkdir($rootpath . "/cache/" . $baseid);
		foreach ($paths as $key => $filename)
		{
			file_put_contents($filename, $datamap[$key]);
			chmod($filename, 0600);
		}

		if (!$suppressoutput)  echo "\nExported information to '" . $rootpath . "/cache/" . $baseid . "/'.\n";

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $baseid,
				"paths" => $paths
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "import-csr")
	{
		ReinitArgs(array("id", "csrfile", "privatekey"));

		// Get the object ID.
		$result = GetSSLObject();

		$id = $result["id"];
		$filename = $result["filename"];
		$data = $result["data"];

		do
		{
			$csrfile = CLI::GetUserInputWithArgs($args, "csrfile", "CSR filename", false, "", $suppressoutput);
			$valid = file_exists($csrfile);
			if (!$valid)  CLI::DisplayError("File '" . $csrfile . "' does not exist.", false, false);
		} while (!$valid);

		do
		{
			$privatekeyfile = CLI::GetUserInputWithArgs($args, "privatekey", "Optional:  CSR private key filename", "", "", $suppressoutput);
			$valid = ($privatekeyfile === "" || file_exists($privatekeyfile));
			if (!$valid)  CLI::DisplayError("File '" . $privatekeyfile . "' does not exist.", false, false);
		} while (!$valid);

		$csr = new \phpseclib3\File\X509();
		if (!$csr->loadCSR(file_get_contents($csrfile)))  CLI::DisplayError("Unable to load the CSR.");
		if ($csr->validateSignature() !== true)  CLI::DisplayError("Unable to validate the CSR's signature.");

		// Extract the public key from the CSR.
		$publickey = $csr->getPublicKey();

		// Load the private key file.
		$privatekey = ($privatekeyfile !== "" ? \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey(file_get_contents($privatekeyfile)) : "");

		// Save CSR.
		$data["csr"] = array(
			"publickey" => (string)$publickey,
			"privatekey" => (string)$privatekey,
			"csr" => $csr->saveCSR($csr->getCurrentCert()),
			"created" => time()
		);

		// Extract information from the CSR.
		$data["csrinfo"] = ExtractCSRInfo($data["csr"]);

		file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($filename, 0600);

		if (!$suppressoutput)  echo "\nImported CSR:\n\n" . $data["csr"]["csr"] . "\n\n";

		$result = array(
			"success" => true,
			"info" => array(
				"id" => $id,
				"csr" => $data["csr"]["csr"],
				"csrinfo" => $data["csrinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "import-cert")
	{
		ReinitArgs(array("id", "certfile", "keysrc", "keyfile", "ca"));

		// Get the object ID.
		$result = GetSSLObject();

		$id = $result["id"];
		$filename = $result["filename"];
		$data = $result["data"];

		do
		{
			$certfile = CLI::GetUserInputWithArgs($args, "certfile", "Certificate filename", false, "", $suppressoutput);
			$valid = file_exists($certfile);
			if (!$valid)  CLI::DisplayError("File '" . $certfile . "' does not exist.", false, false);
			else
			{
				// Load the certificate.
				$cert = new \phpseclib3\File\X509();
				$valid = $cert->loadX509(file_get_contents($certfile));
				if (!$valid)  CLI::DisplayError("File '" . $certfile . "' is not a valid certificate.  Unable to load the certificate.", false, false);
			}
		} while (!$valid);

		$privatekeysources = array(
			"none" => "Do not import a private key",
			"file" => "Import a private key from a file"
		);

		if (isset($data["csrinfo"]) && $data["csrinfo"]["privatekey"])  $privatekeysources["csr"] = "Use the CSR private key";

		$privatekeysrc = CLI::GetLimitedUserInputWithArgs($args, "keysrc", "Private key source", false, "Available private key sources:", $privatekeysources, true, $suppressoutput);

		if ($privatekeysrc === "none")  $privatekey = "";
		else if ($privatekeysrc === "file")
		{
			do
			{
				$privatekeyfile = CLI::GetUserInputWithArgs($args, "keyfile", "Certificate private key filename", false, "", $suppressoutput);
				$valid = file_exists($privatekeyfile);
				if (!$valid)  CLI::DisplayError("File '" . $privatekeyfile . "' does not exist.", false, false);
				else
				{
					$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey(file_get_contents($privatekeyfile));
				}
			} while (!$valid);
		}
		else if ($privatekeysrc === "csr")
		{
			$privatekey = \phpseclib3\Crypt\PublicKeyLoader::loadPrivateKey($data["csr"]["privatekey"]);

			// Remove the CSR since it is no longer needed.
			unset($data["csr"]);
			unset($data["csrinfo"]);
		}

		// Ask if this is a CA.
		$ca = CLI::GetYesNoUserInputWithArgs($args, "ca", "Certificate Authority (CA)", "N", "The next question is primarily for importing root and intermediate certificates generated by an outside source.", $suppressoutput);

		// Extract the public key from the certificate.
		$publickey = $cert->getPublicKey();

		$data["cert"] = array(
			"privatekey" => (string)$privatekey,
			"publickey" => (string)$publickey,
			"cert" => $cert->saveX509($cert->getCurrentCert()),
			"created" => time(),
			"ca" => $ca,
			"signer" => ""
		);

		// Extract information from the certificate.
		$data["certinfo"] = ExtractCertInfo($data["cert"]);

		file_put_contents($filename, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
		chmod($filename, 0600);

		if (!$suppressoutput)  echo "\nImported Certificate:\n\n" . $data["cert"]["cert"] . "\n\n";

		$result = array(
			"sucess" => true,
			"info" => array(
				"id" => $id,
				"cert" => $data["cert"]["cert"],
				"certinfo" => $data["certinfo"]
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "rename")
	{
		ReinitArgs(array("id", "newid"));

		// Get the object ID.
		$result = GetSSLObject();

		$id = $result["id"];
		$filename = $result["filename"];

		// Get the new object ID.
		do
		{
			$newid = CLI::GetUserInputWithArgs($args, "newid", "New storage object ID", false, "", $suppressoutput);
			$newid = Str::FilenameSafe($newid);
			$newfilename = $rootpath . "/certs/" . $newid . ".json";
			$found = file_exists($newfilename);
			if ($found)  CLI::DisplayError("A storage object with that ID already exists.  The file '" . $filename . "' already exists.", false, false);
		} while ($found);

		rename($filename, $newfilename);

		// Update all certificate chain references.
		$updated = array();
		$path = $rootpath . "/certs";
		$dir = opendir($path);
		if ($dir)
		{
			while (($file = readdir($dir)) !== false)
			{
				if ($file !== "." && $file !== ".." && is_file($path . "/" . $file) && substr($file, -5) == ".json")
				{
					$data = @json_decode(file_get_contents($path . "/" . $file), true);

					if (isset($data["cert"]) && $data["cert"]["signer"] === $id)
					{
						$data["cert"]["signer"] = $newid;

						$data["certinfo"] = ExtractCertInfo($data["cert"]);

						file_put_contents($path . "/" . $file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
						chmod($path . "/" . $file, 0600);

						$updated[] = substr($file, 0, -5);
					}
				}
			}

			closedir($dir);
		}

		sort($updated, SORT_NATURAL | SORT_FLAG_CASE);

		$result = array(
			"sucess" => true,
			"info" => array(
				"id" => $id,
				"newid" => $newid,
				"updated" => $updated
			)
		);

		DisplayResult($result);
	}
	else if ($cmd === "delete")
	{
		ReinitArgs(array("id"));

		// Get the object ID.
		$result = GetSSLObject();

		$id = $result["id"];
		$filename = $result["filename"];

		unlink($filename);

		$result = array(
			"sucess" => true,
			"info" => array(
				"id" => $id
			)
		);

		DisplayResult($result);
	}
?>