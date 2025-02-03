<?php
	// Generated with Decomposer.

namespace {
if (extension_loaded('mbstring')) {

	if (version_compare(PHP_VERSION, '8.0.0') < 0 && ini_get('mbstring.func_overload') & 2) {
		throw new UnexpectedValueException(
			'Overloading of string functions using mbstring.func_overload ' .
			'is not supported by phpseclib.'
		);
	}
}

	class phpseclib3__Curves_DirectoryItem
	{
		private $name;

		public function __construct($name)
		{
			$this->name = $name;
		}

		public function getExtension()
		{
			$pos = strrpos($this->name, ".");
			if ($pos === false)	return "";

			return substr($this->name, $pos + 1);
		}

		public function getBasename($suffix)
		{
			if (substr($this->name, -strlen($suffix)) === $suffix)	return substr($this->name, 0, -strlen($suffix));

			return $this->name;
		}
	}

	$phpseclib3__curvemap = array (
	0 => 'brainpoolP160r1.php',
	1 => 'brainpoolP160t1.php',
	2 => 'brainpoolP192r1.php',
	3 => 'brainpoolP192t1.php',
	4 => 'brainpoolP224r1.php',
	5 => 'brainpoolP224t1.php',
	6 => 'brainpoolP256r1.php',
	7 => 'brainpoolP256t1.php',
	8 => 'brainpoolP320r1.php',
	9 => 'brainpoolP320t1.php',
	10 => 'brainpoolP384r1.php',
	11 => 'brainpoolP384t1.php',
	12 => 'brainpoolP512r1.php',
	13 => 'brainpoolP512t1.php',
	14 => 'Curve25519.php',
	15 => 'Curve448.php',
	16 => 'Ed25519.php',
	17 => 'Ed448.php',
	18 => 'nistb233.php',
	19 => 'nistb409.php',
	20 => 'nistk163.php',
	21 => 'nistk233.php',
	22 => 'nistk283.php',
	23 => 'nistk409.php',
	24 => 'nistp192.php',
	25 => 'nistp224.php',
	26 => 'nistp256.php',
	27 => 'nistp384.php',
	28 => 'nistp521.php',
	29 => 'nistt571.php',
	30 => 'prime192v1.php',
	31 => 'prime192v2.php',
	32 => 'prime192v3.php',
	33 => 'prime239v1.php',
	34 => 'prime239v2.php',
	35 => 'prime239v3.php',
	36 => 'prime256v1.php',
	37 => 'secp112r1.php',
	38 => 'secp112r2.php',
	39 => 'secp128r1.php',
	40 => 'secp128r2.php',
	41 => 'secp160k1.php',
	42 => 'secp160r1.php',
	43 => 'secp160r2.php',
	44 => 'secp192k1.php',
	45 => 'secp192r1.php',
	46 => 'secp224k1.php',
	47 => 'secp224r1.php',
	48 => 'secp256k1.php',
	49 => 'secp256r1.php',
	50 => 'secp384r1.php',
	51 => 'secp521r1.php',
	52 => 'sect113r1.php',
	53 => 'sect113r2.php',
	54 => 'sect131r1.php',
	55 => 'sect131r2.php',
	56 => 'sect163k1.php',
	57 => 'sect163r1.php',
	58 => 'sect163r2.php',
	59 => 'sect193r1.php',
	60 => 'sect193r2.php',
	61 => 'sect233k1.php',
	62 => 'sect233r1.php',
	63 => 'sect239k1.php',
	64 => 'sect283k1.php',
	65 => 'sect283r1.php',
	66 => 'sect409k1.php',
	67 => 'sect409r1.php',
	68 => 'sect571k1.php',
	69 => 'sect571r1.php',
);
	$phpseclib3__curvemap2 = null;

	function phpseclib3__GetECCurveMap()
	{
		global $phpseclib3__curvemap, $phpseclib3__curvemap2;

		if (!$phpseclib3__curvemap2)
		{
			$phpseclib3__curvemap2 = array();

			foreach ($phpseclib3__curvemap as $file)
			{
				$phpseclib3__curvemap2[] = new phpseclib3_Curves_DirectoryItem($file);
			}
		}

		return $phpseclib3_curvemap2;
	}}

namespace phpseclib3\Crypt\Common\Formats\Keys {

abstract class PKCS
{

	const MODE_ANY = 0;

	const MODE_PEM = 1;

	const MODE_DER = 2;

	protected static $format = self::MODE_ANY;

	public static function requirePEM()
	{
		self::$format = self::MODE_PEM;
	}

	public static function requireDER()
	{
		self::$format = self::MODE_DER;
	}

	public static function requireAny()
	{
		self::$format = self::MODE_ANY;
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\DES;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\TripleDES;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\File\ASN1;

abstract class PKCS1 extends PKCS
{

	private static $defaultEncryptionAlgorithm = 'AES-128-CBC';

	public static function setEncryptionAlgorithm($algo)
	{
		self::$defaultEncryptionAlgorithm = $algo;
	}

	private static function getEncryptionMode($mode)
	{
		switch ($mode) {
			case 'CBC':
			case 'ECB':
			case 'CFB':
			case 'OFB':
			case 'CTR':
				return $mode;
		}
		throw new \UnexpectedValueException('Unsupported block cipher mode of operation');
	}

	private static function getEncryptionObject($algo)
	{
		$modes = '(CBC|ECB|CFB|OFB|CTR)';
		switch (true) {
			case preg_match("#^AES-(128|192|256)-$modes$#", $algo, $matches):
				$cipher = new AES(self::getEncryptionMode($matches[2]));
				$cipher->setKeyLength($matches[1]);
				return $cipher;
			case preg_match("#^DES-EDE3-$modes$#", $algo, $matches):
				return new TripleDES(self::getEncryptionMode($matches[1]));
			case preg_match("#^DES-$modes$#", $algo, $matches):
				return new DES(self::getEncryptionMode($matches[1]));
			default:
				throw new UnsupportedAlgorithmException($algo . ' is not a supported algorithm');
		}
	}

	private static function generateSymmetricKey($password, $iv, $length)
	{
		$symkey = '';
		$iv = substr($iv, 0, 8);
		while (strlen($symkey) < $length) {
			$symkey .= md5($symkey . $password . $iv, true);
		}
		return substr($symkey, 0, $length);
	}

	protected static function load($key, $password)
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (preg_match('#DEK-Info: (.+),(.+)#', $key, $matches)) {
			$iv = Strings::hex2bin(trim($matches[2]));

			$key = preg_replace('#^(?:Proc-Type|DEK-Info): .*#m', '', $key);
			$ciphertext = ASN1::extractBER($key);
			if ($ciphertext === false) {
				$ciphertext = $key;
			}
			$crypto = self::getEncryptionObject($matches[1]);
			$crypto->setKey(self::generateSymmetricKey($password, $iv, $crypto->getKeyLength() >> 3));
			$crypto->setIV($iv);
			$key = $crypto->decrypt($ciphertext);
		} else {
			if (self::$format != self::MODE_DER) {
				$decoded = ASN1::extractBER($key);
				if ($decoded !== false) {
					$key = $decoded;
				} elseif (self::$format == self::MODE_PEM) {
					throw new \UnexpectedValueException('Expected base64-encoded PEM format but was unable to decode base64 text');
				}
			}
		}

		return $key;
	}

	protected static function wrapPrivateKey($key, $type, $password, array $options = [])
	{
		if (empty($password) || !is_string($password)) {
			return "-----BEGIN $type PRIVATE KEY-----\r\n" .
					chunk_split(Strings::base64_encode($key), 64) .
					"-----END $type PRIVATE KEY-----";
		}

		$encryptionAlgorithm = isset($options['encryptionAlgorithm']) ? $options['encryptionAlgorithm'] : self::$defaultEncryptionAlgorithm;

		$cipher = self::getEncryptionObject($encryptionAlgorithm);
		$iv = Random::string($cipher->getBlockLength() >> 3);
		$cipher->setKey(self::generateSymmetricKey($password, $iv, $cipher->getKeyLength() >> 3));
		$cipher->setIV($iv);
		$iv = strtoupper(Strings::bin2hex($iv));
		return "-----BEGIN $type PRIVATE KEY-----\r\n" .
				"Proc-Type: 4,ENCRYPTED\r\n" .
				"DEK-Info: " . $encryptionAlgorithm . ",$iv\r\n" .
				"\r\n" .
				chunk_split(Strings::base64_encode($cipher->encrypt($key)), 64) .
				"-----END $type PRIVATE KEY-----";
	}

	protected static function wrapPublicKey($key, $type)
	{
		return "-----BEGIN $type PUBLIC KEY-----\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				"-----END $type PUBLIC KEY-----";
	}
}
}

namespace phpseclib3\Crypt\DH\Formats\Keys {

use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS1 extends Progenitor
{

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		$decoded = ASN1::decodeBER($key);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}

		$components = ASN1::asn1map($decoded[0], Maps\DHParameter::MAP);
		if (!is_array($components)) {
			throw new \RuntimeException('Unable to perform ASN1 mapping on parameters');
		}

		return $components;
	}

	public static function saveParameters(BigInteger $prime, BigInteger $base, array $options = [])
	{
		$params = [
			'prime' => $prime,
			'base' => $base
		];
		$params = ASN1::encodeDER($params, Maps\DHParameter::MAP);

		return "-----BEGIN DH PARAMETERS-----\r\n" .
				chunk_split(base64_encode($params), 64) .
				"-----END DH PARAMETERS-----\r\n";
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\DES;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\RC2;
use phpseclib3\Crypt\RC4;
use phpseclib3\Crypt\TripleDES;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;

abstract class PKCS8 extends PKCS
{

	private static $defaultEncryptionAlgorithm = 'id-PBES2';

	private static $defaultEncryptionScheme = 'aes128-CBC-PAD';

	private static $defaultPRF = 'id-hmacWithSHA256';

	private static $defaultIterationCount = 2048;

	private static $oidsLoaded = false;

	private static $binary = false;

	public static function setEncryptionAlgorithm($algo)
	{
		self::$defaultEncryptionAlgorithm = $algo;
	}

	public static function setEncryptionScheme($algo)
	{
		self::$defaultEncryptionScheme = $algo;
	}

	public static function setIterationCount($count)
	{
		self::$defaultIterationCount = $count;
	}

	public static function setPRF($algo)
	{
		self::$defaultPRF = $algo;
	}

	private static function getPBES1EncryptionObject($algo)
	{
		$algo = preg_match('#^pbeWith(?:MD2|MD5|SHA1|SHA)And(.*?)-CBC$#', $algo, $matches) ?
			$matches[1] :
			substr($algo, 13);

		switch ($algo) {
			case 'DES':
				$cipher = new DES('cbc');
				break;
			case 'RC2':
				$cipher = new RC2('cbc');
				$cipher->setKeyLength(64);
				break;
			case '3-KeyTripleDES':
				$cipher = new TripleDES('cbc');
				break;
			case '2-KeyTripleDES':
				$cipher = new TripleDES('cbc');
				$cipher->setKeyLength(128);
				break;
			case '128BitRC2':
				$cipher = new RC2('cbc');
				$cipher->setKeyLength(128);
				break;
			case '40BitRC2':
				$cipher = new RC2('cbc');
				$cipher->setKeyLength(40);
				break;
			case '128BitRC4':
				$cipher = new RC4();
				$cipher->setKeyLength(128);
				break;
			case '40BitRC4':
				$cipher = new RC4();
				$cipher->setKeyLength(40);
				break;
			default:
				throw new UnsupportedAlgorithmException("$algo is not a supported algorithm");
		}

		return $cipher;
	}

	private static function getPBES1Hash($algo)
	{
		if (preg_match('#^pbeWith(MD2|MD5|SHA1|SHA)And.*?-CBC$#', $algo, $matches)) {
			return $matches[1] == 'SHA' ? 'sha1' : $matches[1];
		}

		return 'sha1';
	}

	private static function getPBES1KDF($algo)
	{
		switch ($algo) {
			case 'pbeWithMD2AndDES-CBC':
			case 'pbeWithMD2AndRC2-CBC':
			case 'pbeWithMD5AndDES-CBC':
			case 'pbeWithMD5AndRC2-CBC':
			case 'pbeWithSHA1AndDES-CBC':
			case 'pbeWithSHA1AndRC2-CBC':
				return 'pbkdf1';
		}

		return 'pkcs12';
	}

	private static function getPBES2EncryptionObject($algo)
	{
		switch ($algo) {
			case 'desCBC':
				$cipher = new DES('cbc');
				break;
			case 'des-EDE3-CBC':
				$cipher = new TripleDES('cbc');
				break;
			case 'rc2CBC':
				$cipher = new RC2('cbc');

				$cipher->setKeyLength(128);
				break;
			case 'rc5-CBC-PAD':
				throw new UnsupportedAlgorithmException('rc5-CBC-PAD is not supported for PBES2 PKCS#8 keys');
			case 'aes128-CBC-PAD':
			case 'aes192-CBC-PAD':
			case 'aes256-CBC-PAD':
				$cipher = new AES('cbc');
				$cipher->setKeyLength(substr($algo, 3, 3));
				break;
			default:
				throw new UnsupportedAlgorithmException("$algo is not supported");
		}

		return $cipher;
	}

	private static function initialize_static_variables()
	{
		if (!isset(static::$childOIDsLoaded)) {
			throw new InsufficientSetupException('This class should not be called directly');
		}

		if (!static::$childOIDsLoaded) {
			ASN1::loadOIDs(is_array(static::OID_NAME) ?
				array_combine(static::OID_NAME, static::OID_VALUE) :
				[static::OID_NAME => static::OID_VALUE]);
			static::$childOIDsLoaded = true;
		}
		if (!self::$oidsLoaded) {

			ASN1::loadOIDs([

				'pbeWithMD2AndDES-CBC' => '1.2.840.113549.1.5.1',
				'pbeWithMD2AndRC2-CBC' => '1.2.840.113549.1.5.4',
				'pbeWithMD5AndDES-CBC' => '1.2.840.113549.1.5.3',
				'pbeWithMD5AndRC2-CBC' => '1.2.840.113549.1.5.6',
				'pbeWithSHA1AndDES-CBC' => '1.2.840.113549.1.5.10',
				'pbeWithSHA1AndRC2-CBC' => '1.2.840.113549.1.5.11',

				'pbeWithSHAAnd128BitRC4' => '1.2.840.113549.1.12.1.1',
				'pbeWithSHAAnd40BitRC4' => '1.2.840.113549.1.12.1.2',
				'pbeWithSHAAnd3-KeyTripleDES-CBC' => '1.2.840.113549.1.12.1.3',
				'pbeWithSHAAnd2-KeyTripleDES-CBC' => '1.2.840.113549.1.12.1.4',
				'pbeWithSHAAnd128BitRC2-CBC' => '1.2.840.113549.1.12.1.5',
				'pbeWithSHAAnd40BitRC2-CBC' => '1.2.840.113549.1.12.1.6',

				'id-PBKDF2' => '1.2.840.113549.1.5.12',
				'id-PBES2' => '1.2.840.113549.1.5.13',
				'id-PBMAC1' => '1.2.840.113549.1.5.14',

				'id-hmacWithSHA1' => '1.2.840.113549.2.7',
				'id-hmacWithSHA224' => '1.2.840.113549.2.8',
				'id-hmacWithSHA256' => '1.2.840.113549.2.9',
				'id-hmacWithSHA384' => '1.2.840.113549.2.10',
				'id-hmacWithSHA512' => '1.2.840.113549.2.11',
				'id-hmacWithSHA512-224' => '1.2.840.113549.2.12',
				'id-hmacWithSHA512-256' => '1.2.840.113549.2.13',

				'desCBC'		=> '1.3.14.3.2.7',
				'des-EDE3-CBC' => '1.2.840.113549.3.7',
				'rc2CBC' => '1.2.840.113549.3.2',
				'rc5-CBC-PAD' => '1.2.840.113549.3.9',

				'aes128-CBC-PAD' => '2.16.840.1.101.3.4.1.2',
				'aes192-CBC-PAD' => '2.16.840.1.101.3.4.1.22',
				'aes256-CBC-PAD' => '2.16.840.1.101.3.4.1.42'
			]);
			self::$oidsLoaded = true;
		}
	}

	protected static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		$isPublic = strpos($key, 'PUBLIC') !== false;
		$isPrivate = strpos($key, 'PRIVATE') !== false;

		$decoded = self::preParse($key);

		$meta = [];

		$decrypted = ASN1::asn1map($decoded[0], Maps\EncryptedPrivateKeyInfo::MAP);
		if (strlen($password) && is_array($decrypted)) {
			$algorithm = $decrypted['encryptionAlgorithm']['algorithm'];
			switch ($algorithm) {

				case 'pbeWithMD2AndDES-CBC':
				case 'pbeWithMD2AndRC2-CBC':
				case 'pbeWithMD5AndDES-CBC':
				case 'pbeWithMD5AndRC2-CBC':
				case 'pbeWithSHA1AndDES-CBC':
				case 'pbeWithSHA1AndRC2-CBC':
				case 'pbeWithSHAAnd3-KeyTripleDES-CBC':
				case 'pbeWithSHAAnd2-KeyTripleDES-CBC':
				case 'pbeWithSHAAnd128BitRC2-CBC':
				case 'pbeWithSHAAnd40BitRC2-CBC':
				case 'pbeWithSHAAnd128BitRC4':
				case 'pbeWithSHAAnd40BitRC4':
					$cipher = self::getPBES1EncryptionObject($algorithm);
					$hash = self::getPBES1Hash($algorithm);
					$kdf = self::getPBES1KDF($algorithm);

					$meta['meta']['algorithm'] = $algorithm;

					$temp = ASN1::decodeBER($decrypted['encryptionAlgorithm']['parameters']);
					if (!$temp) {
						throw new \RuntimeException('Unable to decode BER');
					}
					extract(ASN1::asn1map($temp[0], Maps\PBEParameter::MAP));
					$iterationCount = (int) $iterationCount->toString();
					$cipher->setPassword($password, $kdf, $hash, $salt, $iterationCount);
					$key = $cipher->decrypt($decrypted['encryptedData']);
					$decoded = ASN1::decodeBER($key);
					if (!$decoded) {
						throw new \RuntimeException('Unable to decode BER 2');
					}

					break;
				case 'id-PBES2':
					$meta['meta']['algorithm'] = $algorithm;

					$temp = ASN1::decodeBER($decrypted['encryptionAlgorithm']['parameters']);
					if (!$temp) {
						throw new \RuntimeException('Unable to decode BER');
					}
					$temp = ASN1::asn1map($temp[0], Maps\PBES2params::MAP);
					extract($temp);

					$cipher = self::getPBES2EncryptionObject($encryptionScheme['algorithm']);
					$meta['meta']['cipher'] = $encryptionScheme['algorithm'];

					$temp = ASN1::decodeBER($decrypted['encryptionAlgorithm']['parameters']);
					if (!$temp) {
						throw new \RuntimeException('Unable to decode BER');
					}
					$temp = ASN1::asn1map($temp[0], Maps\PBES2params::MAP);
					extract($temp);

					if (!$cipher instanceof RC2) {
						$cipher->setIV($encryptionScheme['parameters']['octetString']);
					} else {
						$temp = ASN1::decodeBER($encryptionScheme['parameters']);
						if (!$temp) {
							throw new \RuntimeException('Unable to decode BER');
						}
						extract(ASN1::asn1map($temp[0], Maps\RC2CBCParameter::MAP));
						$effectiveKeyLength = (int) $rc2ParametersVersion->toString();
						switch ($effectiveKeyLength) {
							case 160:
								$effectiveKeyLength = 40;
								break;
							case 120:
								$effectiveKeyLength = 64;
								break;
							case 58:
								$effectiveKeyLength = 128;
								break;

						}
						$cipher->setIV($iv);
						$cipher->setKeyLength($effectiveKeyLength);
					}

					$meta['meta']['keyDerivationFunc'] = $keyDerivationFunc['algorithm'];
					switch ($keyDerivationFunc['algorithm']) {
						case 'id-PBKDF2':
							$temp = ASN1::decodeBER($keyDerivationFunc['parameters']);
							if (!$temp) {
								throw new \RuntimeException('Unable to decode BER');
							}
							$prf = ['algorithm' => 'id-hmacWithSHA1'];
							$params = ASN1::asn1map($temp[0], Maps\PBKDF2params::MAP);
							extract($params);
							$meta['meta']['prf'] = $prf['algorithm'];
							$hash = str_replace('-', '/', substr($prf['algorithm'], 11));
							$params = [
								$password,
								'pbkdf2',
								$hash,
								$salt,
								(int) $iterationCount->toString()
							];
							if (isset($keyLength)) {
								$params[] = (int) $keyLength->toString();
							}
							$cipher->setPassword(...$params);
							$key = $cipher->decrypt($decrypted['encryptedData']);
							$decoded = ASN1::decodeBER($key);
							if (!$decoded) {
								throw new \RuntimeException('Unable to decode BER 3');
							}
							break;
						default:
							throw new UnsupportedAlgorithmException('Only PBKDF2 is supported for PBES2 PKCS#8 keys');
					}
					break;
				case 'id-PBMAC1':

					throw new UnsupportedAlgorithmException('Only PBES1 and PBES2 PKCS#8 keys are supported.');

			}
		}

		$private = ASN1::asn1map($decoded[0], Maps\OneAsymmetricKey::MAP);
		if (is_array($private)) {
			if ($isPublic) {
				throw new \UnexpectedValueException('Human readable string claims public key but DER encoded string claims private key');
			}

			if (isset($private['privateKeyAlgorithm']['parameters']) && !$private['privateKeyAlgorithm']['parameters'] instanceof ASN1\Element && isset($decoded[0]['content'][1]['content'][1])) {
				$temp = $decoded[0]['content'][1]['content'][1];
				$private['privateKeyAlgorithm']['parameters'] = new ASN1\Element(substr($key, $temp['start'], $temp['length']));
			}
			if (is_array(static::OID_NAME)) {
				if (!in_array($private['privateKeyAlgorithm']['algorithm'], static::OID_NAME)) {
					throw new UnsupportedAlgorithmException($private['privateKeyAlgorithm']['algorithm'] . ' is not a supported key type');
				}
			} else {
				if ($private['privateKeyAlgorithm']['algorithm'] != static::OID_NAME) {
					throw new UnsupportedAlgorithmException('Only ' . static::OID_NAME . ' keys are supported; this is a ' . $private['privateKeyAlgorithm']['algorithm'] . ' key');
				}
			}
			if (isset($private['publicKey'])) {
				if ($private['publicKey'][0] != "\0") {
					throw new \UnexpectedValueException('The first byte of the public key should be null - not ' . bin2hex($private['publicKey'][0]));
				}
				$private['publicKey'] = substr($private['publicKey'], 1);
			}
			return $private + $meta;
		}

		$public = ASN1::asn1map($decoded[0], Maps\PublicKeyInfo::MAP);

		if (is_array($public)) {
			if ($isPrivate) {
				throw new \UnexpectedValueException('Human readable string claims private key but DER encoded string claims public key');
			}

			if ($public['publicKey'][0] != "\0") {
				throw new \UnexpectedValueException('The first byte of the public key should be null - not ' . bin2hex($public['publicKey'][0]));
			}
			if (is_array(static::OID_NAME)) {
				if (!in_array($public['publicKeyAlgorithm']['algorithm'], static::OID_NAME)) {
					throw new UnsupportedAlgorithmException($public['publicKeyAlgorithm']['algorithm'] . ' is not a supported key type');
				}
			} else {
				if ($public['publicKeyAlgorithm']['algorithm'] != static::OID_NAME) {
					throw new UnsupportedAlgorithmException('Only ' . static::OID_NAME . ' keys are supported; this is a ' . $public['publicKeyAlgorithm']['algorithm'] . ' key');
				}
			}
			if (isset($public['publicKeyAlgorithm']['parameters']) && !$public['publicKeyAlgorithm']['parameters'] instanceof ASN1\Element && isset($decoded[0]['content'][0]['content'][1])) {
				$temp = $decoded[0]['content'][0]['content'][1];
				$public['publicKeyAlgorithm']['parameters'] = new ASN1\Element(substr($key, $temp['start'], $temp['length']));
			}
			$public['publicKey'] = substr($public['publicKey'], 1);
			return $public;
		}

		throw new \RuntimeException('Unable to parse using either OneAsymmetricKey or PublicKeyInfo ASN1 maps');
	}

	public static function setBinaryOutput($enabled)
	{
		self::$binary = $enabled;
	}

	protected static function wrapPrivateKey($key, $attr, $params, $password, $oid = null, $publicKey = '', array $options = [])
	{
		self::initialize_static_variables();

		$key = [
			'version' => 'v1',
			'privateKeyAlgorithm' => [
				'algorithm' => is_string(static::OID_NAME) ? static::OID_NAME : $oid
			 ],
			'privateKey' => $key
		];
		if ($oid != 'id-Ed25519' && $oid != 'id-Ed448') {
			$key['privateKeyAlgorithm']['parameters'] = $params;
		}
		if (!empty($attr)) {
			$key['attributes'] = $attr;
		}
		if (!empty($publicKey)) {
			$key['version'] = 'v2';
			$key['publicKey'] = $publicKey;
		}
		$key = ASN1::encodeDER($key, Maps\OneAsymmetricKey::MAP);
		if (!empty($password) && is_string($password)) {
			$salt = Random::string(8);

			$iterationCount = isset($options['iterationCount']) ? $options['iterationCount'] : self::$defaultIterationCount;
			$encryptionAlgorithm = isset($options['encryptionAlgorithm']) ? $options['encryptionAlgorithm'] : self::$defaultEncryptionAlgorithm;
			$encryptionScheme = isset($options['encryptionScheme']) ? $options['encryptionScheme'] : self::$defaultEncryptionScheme;
			$prf = isset($options['PRF']) ? $options['PRF'] : self::$defaultPRF;

			if ($encryptionAlgorithm == 'id-PBES2') {
				$crypto = self::getPBES2EncryptionObject($encryptionScheme);
				$hash = str_replace('-', '/', substr($prf, 11));
				$kdf = 'pbkdf2';
				$iv = Random::string($crypto->getBlockLength() >> 3);

				$PBKDF2params = [
					'salt' => $salt,
					'iterationCount' => $iterationCount,
					'prf' => ['algorithm' => $prf, 'parameters' => null]
				];
				$PBKDF2params = ASN1::encodeDER($PBKDF2params, Maps\PBKDF2params::MAP);

				if (!$crypto instanceof RC2) {
					$params = ['octetString' => $iv];
				} else {
					$params = [
						'rc2ParametersVersion' => 58,
						'iv' => $iv
					];
					$params = ASN1::encodeDER($params, Maps\RC2CBCParameter::MAP);
					$params = new ASN1\Element($params);
				}

				$params = [
					'keyDerivationFunc' => [
						'algorithm' => 'id-PBKDF2',
						'parameters' => new ASN1\Element($PBKDF2params)
					],
					'encryptionScheme' => [
						'algorithm' => $encryptionScheme,
						'parameters' => $params
					]
				];
				$params = ASN1::encodeDER($params, Maps\PBES2params::MAP);

				$crypto->setIV($iv);
			} else {
				$crypto = self::getPBES1EncryptionObject($encryptionAlgorithm);
				$hash = self::getPBES1Hash($encryptionAlgorithm);
				$kdf = self::getPBES1KDF($encryptionAlgorithm);

				$params = [
					'salt' => $salt,
					'iterationCount' => $iterationCount
				];
				$params = ASN1::encodeDER($params, Maps\PBEParameter::MAP);
			}
			$crypto->setPassword($password, $kdf, $hash, $salt, $iterationCount);
			$key = $crypto->encrypt($key);

			$key = [
				'encryptionAlgorithm' => [
					'algorithm' => $encryptionAlgorithm,
					'parameters' => new ASN1\Element($params)
				],
				'encryptedData' => $key
			];

			$key = ASN1::encodeDER($key, Maps\EncryptedPrivateKeyInfo::MAP);

			if (isset($options['binary']) ? $options['binary'] : self::$binary) {
				return $key;
			}

			return "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n" .
					chunk_split(Strings::base64_encode($key), 64) .
					"-----END ENCRYPTED PRIVATE KEY-----";
		}

		if (isset($options['binary']) ? $options['binary'] : self::$binary) {
			return $key;
		}

		return "-----BEGIN PRIVATE KEY-----\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				"-----END PRIVATE KEY-----";
	}

	protected static function wrapPublicKey($key, $params, $oid = null, array $options = [])
	{
		self::initialize_static_variables();

		$key = [
			'publicKeyAlgorithm' => [
				'algorithm' => is_string(static::OID_NAME) ? static::OID_NAME : $oid
			],
			'publicKey' => "\0" . $key
		];

		if ($oid != 'id-Ed25519' && $oid != 'id-Ed448') {
			$key['publicKeyAlgorithm']['parameters'] = $params;
		}

		$key = ASN1::encodeDER($key, Maps\PublicKeyInfo::MAP);

		if (isset($options['binary']) ? $options['binary'] : self::$binary) {
			return $key;
		}

		return "-----BEGIN PUBLIC KEY-----\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				"-----END PUBLIC KEY-----";
	}

	private static function preParse(&$key)
	{
		self::initialize_static_variables();

		if (self::$format != self::MODE_DER) {
			$decoded = ASN1::extractBER($key);
			if ($decoded !== false) {
				$key = $decoded;
			} elseif (self::$format == self::MODE_PEM) {
				throw new \UnexpectedValueException('Expected base64-encoded PEM format but was unable to decode base64 text');
			}
		}

		$decoded = ASN1::decodeBER($key);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}

		return $decoded;
	}

	public static function extractEncryptionAlgorithm($key)
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		$decoded = self::preParse($key);

		$r = ASN1::asn1map($decoded[0], Maps\EncryptedPrivateKeyInfo::MAP);
		if (!is_array($r)) {
			throw new \RuntimeException('Unable to parse using EncryptedPrivateKeyInfo map');
		}

		if ($r['encryptionAlgorithm']['algorithm'] == 'id-PBES2') {
			$decoded = ASN1::decodeBER($r['encryptionAlgorithm']['parameters']->element);
			if (!$decoded) {
				throw new \RuntimeException('Unable to decode BER');
			}
			$r['encryptionAlgorithm']['parameters'] = ASN1::asn1map($decoded[0], Maps\PBES2params::MAP);

			$kdf = &$r['encryptionAlgorithm']['parameters']['keyDerivationFunc'];
			switch ($kdf['algorithm']) {
				case 'id-PBKDF2':
					$decoded = ASN1::decodeBER($kdf['parameters']->element);
					if (!$decoded) {
						throw new \RuntimeException('Unable to decode BER');
					}
					$kdf['parameters'] = ASN1::asn1map($decoded[0], Maps\PBKDF2params::MAP);
			}
		}

		return $r['encryptionAlgorithm'];
	}
}
}

namespace phpseclib3\Crypt\DH\Formats\Keys {

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS8 extends Progenitor
{

	const OID_NAME = 'dhKeyAgreement';

	const OID_VALUE = '1.2.840.113549.1.3.1';

	protected static $childOIDsLoaded = false;

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		$type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

		$decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
		if (empty($decoded)) {
			throw new \RuntimeException('Unable to decode BER of parameters');
		}
		$components = ASN1::asn1map($decoded[0], Maps\DHParameter::MAP);
		if (!is_array($components)) {
			throw new \RuntimeException('Unable to perform ASN1 mapping on parameters');
		}

		$decoded = ASN1::decodeBER($key[$type]);
		switch (true) {
			case !isset($decoded):
			case !isset($decoded[0]['content']):
			case !$decoded[0]['content'] instanceof BigInteger:
				throw new \RuntimeException('Unable to decode BER of parameters');
		}
		$components[$type] = $decoded[0]['content'];

		return $components;
	}

	public static function savePrivateKey(BigInteger $prime, BigInteger $base, BigInteger $privateKey, BigInteger $publicKey, $password = '', array $options = [])
	{
		$params = [
			'prime' => $prime,
			'base' => $base
		];
		$params = ASN1::encodeDER($params, Maps\DHParameter::MAP);
		$params = new ASN1\Element($params);
		$key = ASN1::encodeDER($privateKey, ['type' => ASN1::TYPE_INTEGER]);
		return self::wrapPrivateKey($key, [], $params, $password, null, '', $options);
	}

	public static function savePublicKey(BigInteger $prime, BigInteger $base, BigInteger $publicKey, array $options = [])
	{
		$params = [
			'prime' => $prime,
			'base' => $base
		];
		$params = ASN1::encodeDER($params, Maps\DHParameter::MAP);
		$params = new ASN1\Element($params);
		$key = ASN1::encodeDER($publicKey, ['type' => ASN1::TYPE_INTEGER]);
		return self::wrapPublicKey($key, $params, null, $options);
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Random;
use phpseclib3\Exception\BadDecryptionException;

abstract class OpenSSH
{

	protected static $comment = 'phpseclib-generated-key';

	protected static $binary = false;

	public static function setComment($comment)
	{
		self::$comment = str_replace(["\r", "\n"], '', $comment);
	}

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (strpos($key, 'BEGIN OPENSSH PRIVATE KEY') !== false) {
			$key = preg_replace('#(?:^-.*?-[\r\n]*$)|\s#ms', '', $key);
			$key = Strings::base64_decode($key);
			$magic = Strings::shift($key, 15);
			if ($magic != "openssh-key-v1\0") {
				throw new \RuntimeException('Expected openssh-key-v1');
			}
			list($ciphername, $kdfname, $kdfoptions, $numKeys) = Strings::unpackSSH2('sssN', $key);
			if ($numKeys != 1) {

				throw new \RuntimeException('Although the OpenSSH private key format supports multiple keys phpseclib does not');
			}
			switch ($ciphername) {
				case 'none':
					break;
				case 'aes256-ctr':
					if ($kdfname != 'bcrypt') {
						throw new \RuntimeException('Only the bcrypt kdf is supported (' . $kdfname . ' encountered)');
					}
					list($salt, $rounds) = Strings::unpackSSH2('sN', $kdfoptions);
					$crypto = new AES('ctr');

					$crypto->setPassword($password, 'bcrypt', $salt, $rounds, 32);
					break;
				default:
					throw new \RuntimeException('The only supported ciphers are: none, aes256-ctr (' . $ciphername . ' is being used)');
			}

			list($publicKey, $paddedKey) = Strings::unpackSSH2('ss', $key);
			list($type) = Strings::unpackSSH2('s', $publicKey);
			if (isset($crypto)) {
				$paddedKey = $crypto->decrypt($paddedKey);
			}
			list($checkint1, $checkint2) = Strings::unpackSSH2('NN', $paddedKey);

			if ($checkint1 != $checkint2) {
				if (isset($crypto)) {
					throw new BadDecryptionException('Unable to decrypt key - please verify the password you are using');
				}
				throw new \RuntimeException("The two checkints do not match ($checkint1 vs. $checkint2)");
			}
			self::checkType($type);

			return compact('type', 'publicKey', 'paddedKey');
		}

		$parts = explode(' ', $key, 3);

		if (!isset($parts[1])) {
			$key = base64_decode($parts[0]);
			$comment = false;
		} else {
			$asciiType = $parts[0];
			self::checkType($parts[0]);
			$key = base64_decode($parts[1]);
			$comment = isset($parts[2]) ? $parts[2] : false;
		}
		if ($key === false) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		list($type) = Strings::unpackSSH2('s', $key);
		self::checkType($type);
		if (isset($asciiType) && $asciiType != $type) {
			throw new \RuntimeException('Two different types of keys are claimed: ' . $asciiType . ' and ' . $type);
		}
		if (strlen($key) <= 4) {
			throw new \UnexpectedValueException('Key appears to be malformed');
		}

		$publicKey = $key;

		return compact('type', 'publicKey', 'comment');
	}

	public static function setBinaryOutput($enabled)
	{
		self::$binary = $enabled;
	}

	private static function checkType($candidate)
	{
		if (!in_array($candidate, static::$types)) {
			throw new \RuntimeException("The key type ($candidate) is not equal to: " . implode(',', static::$types));
		}
	}

	protected static function wrapPrivateKey($publicKey, $privateKey, $password, $options)
	{
		list(, $checkint) = unpack('N', Random::string(4));

		$comment = isset($options['comment']) ? $options['comment'] : self::$comment;
		$paddedKey = Strings::packSSH2('NN', $checkint, $checkint) .
					 $privateKey .
					 Strings::packSSH2('s', $comment);

		$usesEncryption = !empty($password) && is_string($password);

		$blockSize = $usesEncryption ? 16 : 8;
		$paddingLength = (($blockSize - 1) * strlen($paddedKey)) % $blockSize;
		for ($i = 1; $i <= $paddingLength; $i++) {
			$paddedKey .= chr($i);
		}
		if (!$usesEncryption) {
			$key = Strings::packSSH2('sssNss', 'none', 'none', '', 1, $publicKey, $paddedKey);
		} else {
			$rounds = isset($options['rounds']) ? $options['rounds'] : 16;
			$salt = Random::string(16);
			$kdfoptions = Strings::packSSH2('sN', $salt, $rounds);
			$crypto = new AES('ctr');
			$crypto->setPassword($password, 'bcrypt', $salt, $rounds, 32);
			$paddedKey = $crypto->encrypt($paddedKey);
			$key = Strings::packSSH2('sssNss', 'aes256-ctr', 'bcrypt', $kdfoptions, 1, $publicKey, $paddedKey);
		}
		$key = "openssh-key-v1\0$key";

		return "-----BEGIN OPENSSH PRIVATE KEY-----\n" .
				chunk_split(Strings::base64_encode($key), 70, "\n") .
				"-----END OPENSSH PRIVATE KEY-----\n";
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\OpenSSH as Progenitor;
use phpseclib3\Math\BigInteger;

abstract class OpenSSH extends Progenitor
{

	protected static $types = ['ssh-dss'];

	public static function load($key, $password = '')
	{
		$parsed = parent::load($key, $password);

		if (isset($parsed['paddedKey'])) {
			list($type) = Strings::unpackSSH2('s', $parsed['paddedKey']);
			if ($type != $parsed['type']) {
				throw new \RuntimeException("The public and private keys are not of the same type ($type vs $parsed[type])");
			}

			list($p, $q, $g, $y, $x, $comment) = Strings::unpackSSH2('i5s', $parsed['paddedKey']);

			return compact('p', 'q', 'g', 'y', 'x', 'comment');
		}

		list($p, $q, $g, $y) = Strings::unpackSSH2('iiii', $parsed['publicKey']);

		$comment = $parsed['comment'];

		return compact('p', 'q', 'g', 'y', 'comment');
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, array $options = [])
	{
		if ($q->getLength() != 160) {
			throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
		}

		$DSAPublicKey = Strings::packSSH2('siiii', 'ssh-dss', $p, $q, $g, $y);

		if (isset($options['binary']) ? $options['binary'] : self::$binary) {
			return $DSAPublicKey;
		}

		$comment = isset($options['comment']) ? $options['comment'] : self::$comment;
		$DSAPublicKey = 'ssh-dss ' . base64_encode($DSAPublicKey) . ' ' . $comment;

		return $DSAPublicKey;
	}

	public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '', array $options = [])
	{
		$publicKey = self::savePublicKey($p, $q, $g, $y, ['binary' => true]);
		$privateKey = Strings::packSSH2('si5', 'ssh-dss', $p, $q, $g, $y, $x);

		return self::wrapPrivateKey($publicKey, $privateKey, $password, $options);
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS1 extends Progenitor
{

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		$decoded = ASN1::decodeBER($key);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}

		$key = ASN1::asn1map($decoded[0], Maps\DSAParams::MAP);
		if (is_array($key)) {
			return $key;
		}

		$key = ASN1::asn1map($decoded[0], Maps\DSAPrivateKey::MAP);
		if (is_array($key)) {
			return $key;
		}

		$key = ASN1::asn1map($decoded[0], Maps\DSAPublicKey::MAP);
		if (is_array($key)) {
			return $key;
		}

		throw new \RuntimeException('Unable to perform ASN1 mapping');
	}

	public static function saveParameters(BigInteger $p, BigInteger $q, BigInteger $g)
	{
		$key = [
			'p' => $p,
			'q' => $q,
			'g' => $g
		];

		$key = ASN1::encodeDER($key, Maps\DSAParams::MAP);

		return "-----BEGIN DSA PARAMETERS-----\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				"-----END DSA PARAMETERS-----\r\n";
	}

	public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '', array $options = [])
	{
		$key = [
			'version' => 0,
			'p' => $p,
			'q' => $q,
			'g' => $g,
			'y' => $y,
			'x' => $x
		];

		$key = ASN1::encodeDER($key, Maps\DSAPrivateKey::MAP);

		return self::wrapPrivateKey($key, 'DSA', $password, $options);
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
	{
		$key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);

		return self::wrapPublicKey($key, 'DSA');
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS8 extends Progenitor
{

	const OID_NAME = 'id-dsa';

	const OID_VALUE = '1.2.840.10040.4.1';

	protected static $childOIDsLoaded = false;

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		$type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

		$decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER of parameters');
		}
		$components = ASN1::asn1map($decoded[0], Maps\DSAParams::MAP);
		if (!is_array($components)) {
			throw new \RuntimeException('Unable to perform ASN1 mapping on parameters');
		}

		$decoded = ASN1::decodeBER($key[$type]);
		if (empty($decoded)) {
			throw new \RuntimeException('Unable to decode BER');
		}

		$var = $type == 'privateKey' ? 'x' : 'y';
		$components[$var] = ASN1::asn1map($decoded[0], Maps\DSAPublicKey::MAP);
		if (!$components[$var] instanceof BigInteger) {
			throw new \RuntimeException('Unable to perform ASN1 mapping');
		}

		if (isset($key['meta'])) {
			$components['meta'] = $key['meta'];
		}

		return $components;
	}

	public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '', array $options = [])
	{
		$params = [
			'p' => $p,
			'q' => $q,
			'g' => $g
		];
		$params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
		$params = new ASN1\Element($params);
		$key = ASN1::encodeDER($x, Maps\DSAPublicKey::MAP);
		return self::wrapPrivateKey($key, [], $params, $password, null, '', $options);
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, array $options = [])
	{
		$params = [
			'p' => $p,
			'q' => $q,
			'g' => $g
		];
		$params = ASN1::encodeDER($params, Maps\DSAParams::MAP);
		$params = new ASN1\Element($params);
		$key = ASN1::encodeDER($y, Maps\DSAPublicKey::MAP);
		return self::wrapPublicKey($key, $params, null, $options);
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\AES;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\Random;
use phpseclib3\Exception\UnsupportedAlgorithmException;

abstract class PuTTY
{

	private static $comment = 'phpseclib-generated-key';

	private static $version = 2;

	public static function setComment($comment)
	{
		self::$comment = str_replace(["\r", "\n"], '', $comment);
	}

	public static function setVersion($version)
	{
		if ($version != 2 && $version != 3) {
			throw new \RuntimeException('Only supported versions are 2 and 3');
		}
		self::$version = $version;
	}

	private static function generateV2Key($password, $length)
	{
		$symkey = '';
		$sequence = 0;
		while (strlen($symkey) < $length) {
			$temp = pack('Na*', $sequence++, $password);
			$symkey .= Strings::hex2bin(sha1($temp));
		}
		return substr($symkey, 0, $length);
	}

	private static function generateV3Key($password, $flavour, $memory, $passes, $salt)
	{
		if (!function_exists('sodium_crypto_pwhash')) {
			throw new \RuntimeException('sodium_crypto_pwhash needs to exist for Argon2 password hasing');
		}

		switch ($flavour) {
			case 'Argon2i':
				$flavour = SODIUM_CRYPTO_PWHASH_ALG_ARGON2I13;
				break;
			case 'Argon2id':
				$flavour = SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13;
				break;
			default:
				throw new UnsupportedAlgorithmException('Only Argon2i and Argon2id are supported');
		}

		$length = 80;
		$temp = sodium_crypto_pwhash($length, $password, $salt, $passes, $memory << 10, $flavour);

		$symkey = substr($temp, 0, 32);
		$symiv = substr($temp, 32, 16);
		$hashkey = substr($temp, -32);

		return compact('symkey', 'symiv', 'hashkey');
	}

	public static function load($key, $password)
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (strpos($key, 'BEGIN SSH2 PUBLIC KEY') !== false) {
			$lines = preg_split('#[\r\n]+#', $key);
			switch (true) {
				case $lines[0] != '---- BEGIN SSH2 PUBLIC KEY ----':
					throw new \UnexpectedValueException('Key doesn\'t start with ---- BEGIN SSH2 PUBLIC KEY ----');
				case $lines[count($lines) - 1] != '---- END SSH2 PUBLIC KEY ----':
					throw new \UnexpectedValueException('Key doesn\'t end with ---- END SSH2 PUBLIC KEY ----');
			}
			$lines = array_splice($lines, 1, -1);
			$lines = array_map(function ($line) {
				return rtrim($line, "\r\n");
			}, $lines);
			$data = $current = '';
			$values = [];
			$in_value = false;
			foreach ($lines as $line) {
				switch (true) {
					case preg_match('#^(.*?): (.*)#', $line, $match):
						$in_value = $line[strlen($line) - 1] == '\\';
						$current = strtolower($match[1]);
						$values[$current] = $in_value ? substr($match[2], 0, -1) : $match[2];
						break;
					case $in_value:
						$in_value = $line[strlen($line) - 1] == '\\';
						$values[$current] .= $in_value ? substr($line, 0, -1) : $line;
						break;
					default:
						$data .= $line;
				}
			}

			$components = call_user_func([static::PUBLIC_HANDLER, 'load'], $data);
			if ($components === false) {
				throw new \UnexpectedValueException('Unable to decode public key');
			}
			$components += $values;
			$components['comment'] = str_replace(['\\\\', '\"'], ['\\', '"'], $values['comment']);

			return $components;
		}

		$components = [];

		$key = preg_split('#\r\n|\r|\n#', trim($key));
		if (Strings::shift($key[0], strlen('PuTTY-User-Key-File-')) != 'PuTTY-User-Key-File-') {
			return false;
		}
		$version = (int) Strings::shift($key[0], 3);
		if ($version != 2 && $version != 3) {
			throw new \RuntimeException('Only v2 and v3 PuTTY private keys are supported');
		}
		$components['type'] = $type = rtrim($key[0]);
		if (!in_array($type, static::$types)) {
			$error = count(static::$types) == 1 ?
				'Only ' . static::$types[0] . ' keys are supported. ' :
				'';
			throw new UnsupportedAlgorithmException($error . 'This is an unsupported ' . $type . ' key');
		}
		$encryption = trim(preg_replace('#Encryption: (.+)#', '$1', $key[1]));
		$components['comment'] = trim(preg_replace('#Comment: (.+)#', '$1', $key[2]));

		$publicLength = trim(preg_replace('#Public-Lines: (\d+)#', '$1', $key[3]));
		$public = Strings::base64_decode(implode('', array_map('trim', array_slice($key, 4, $publicLength))));

		$source = Strings::packSSH2('ssss', $type, $encryption, $components['comment'], $public);

		extract(unpack('Nlength', Strings::shift($public, 4)));
		$newtype = Strings::shift($public, $length);
		if ($newtype != $type) {
			throw new \RuntimeException('The binary type does not match the human readable type field');
		}

		$components['public'] = $public;

		switch ($version) {
			case 3:
				$hashkey = '';
				break;
			case 2:
				$hashkey = 'putty-private-key-file-mac-key';
		}

		$offset = $publicLength + 4;
		switch ($encryption) {
			case 'aes256-cbc':
				$crypto = new AES('cbc');
				switch ($version) {
					case 3:
						$flavour = trim(preg_replace('#Key-Derivation: (.*)#', '$1', $key[$offset++]));
						$memory = trim(preg_replace('#Argon2-Memory: (\d+)#', '$1', $key[$offset++]));
						$passes = trim(preg_replace('#Argon2-Passes: (\d+)#', '$1', $key[$offset++]));
						$parallelism = trim(preg_replace('#Argon2-Parallelism: (\d+)#', '$1', $key[$offset++]));
						$salt = Strings::hex2bin(trim(preg_replace('#Argon2-Salt: ([0-9a-f]+)#', '$1', $key[$offset++])));

						extract(self::generateV3Key($password, $flavour, $memory, $passes, $salt));

						break;
					case 2:
						$symkey = self::generateV2Key($password, 32);
						$symiv = str_repeat("\0", $crypto->getBlockLength() >> 3);
						$hashkey .= $password;
				}
		}

		switch ($version) {
			case 3:
				$hash = new Hash('sha256');
				$hash->setKey($hashkey);
				break;
			case 2:
				$hash = new Hash('sha1');
				$hash->setKey(sha1($hashkey, true));
		}

		$privateLength = trim(preg_replace('#Private-Lines: (\d+)#', '$1', $key[$offset++]));
		$private = Strings::base64_decode(implode('', array_map('trim', array_slice($key, $offset, $privateLength))));

		if ($encryption != 'none') {
			$crypto->setKey($symkey);
			$crypto->setIV($symiv);
			$crypto->disablePadding();
			$private = $crypto->decrypt($private);
		}

		$source .= Strings::packSSH2('s', $private);

		$hmac = trim(preg_replace('#Private-MAC: (.+)#', '$1', $key[$offset + $privateLength]));
		$hmac = Strings::hex2bin($hmac);

		if (!hash_equals($hash->hash($source), $hmac)) {
			throw new \UnexpectedValueException('MAC validation error');
		}

		$components['private'] = $private;

		return $components;
	}

	protected static function wrapPrivateKey($public, $private, $type, $password, array $options = [])
	{
		$encryption = (!empty($password) || is_string($password)) ? 'aes256-cbc' : 'none';
		$comment = isset($options['comment']) ? $options['comment'] : self::$comment;
		$version = isset($options['version']) ? $options['version'] : self::$version;

		$key = "PuTTY-User-Key-File-$version: $type\r\n";
		$key .= "Encryption: $encryption\r\n";
		$key .= "Comment: $comment\r\n";

		$public = Strings::packSSH2('s', $type) . $public;

		$source = Strings::packSSH2('ssss', $type, $encryption, $comment, $public);

		$public = Strings::base64_encode($public);
		$key .= "Public-Lines: " . ((strlen($public) + 63) >> 6) . "\r\n";
		$key .= chunk_split($public, 64);

		if (empty($password) && !is_string($password)) {
			$source .= Strings::packSSH2('s', $private);
			switch ($version) {
				case 3:
					$hash = new Hash('sha256');
					$hash->setKey('');
					break;
				case 2:
					$hash = new Hash('sha1');
					$hash->setKey(sha1('putty-private-key-file-mac-key', true));
			}
		} else {
			$private .= Random::string(16 - (strlen($private) & 15));
			$source .= Strings::packSSH2('s', $private);
			$crypto = new AES('cbc');

			switch ($version) {
				case 3:
					$salt = Random::string(16);
					$key .= "Key-Derivation: Argon2id\r\n";
					$key .= "Argon2-Memory: 8192\r\n";
					$key .= "Argon2-Passes: 13\r\n";
					$key .= "Argon2-Parallelism: 1\r\n";
					$key .= "Argon2-Salt: " . Strings::bin2hex($salt) . "\r\n";
					extract(self::generateV3Key($password, 'Argon2id', 8192, 13, $salt));

					$hash = new Hash('sha256');
					$hash->setKey($hashkey);

					break;
				case 2:
					$symkey = self::generateV2Key($password, 32);
					$symiv = str_repeat("\0", $crypto->getBlockLength() >> 3);
					$hashkey = 'putty-private-key-file-mac-key' . $password;

					$hash = new Hash('sha1');
					$hash->setKey(sha1($hashkey, true));
			}

			$crypto->setKey($symkey);
			$crypto->setIV($symiv);
			$crypto->disablePadding();
			$private = $crypto->encrypt($private);
			$mac = $hash->hash($source);
		}

		$private = Strings::base64_encode($private);
		$key .= 'Private-Lines: ' . ((strlen($private) + 63) >> 6) . "\r\n";
		$key .= chunk_split($private, 64);
		$key .= 'Private-MAC: ' . Strings::bin2hex($hash->hash($source)) . "\r\n";

		return $key;
	}

	protected static function wrapPublicKey($key, $type)
	{
		$key = pack('Na*a*', strlen($type), $type, $key);
		$key = "---- BEGIN SSH2 PUBLIC KEY ----\r\n" .
				'Comment: "' . str_replace(['\\', '"'], ['\\\\', '\"'], self::$comment) . "\"\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				'---- END SSH2 PUBLIC KEY ----';
		return $key;
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PuTTY as Progenitor;
use phpseclib3\Math\BigInteger;

abstract class PuTTY extends Progenitor
{

	const PUBLIC_HANDLER = 'phpseclib3\Crypt\DSA\Formats\Keys\OpenSSH';

	protected static $types = ['ssh-dss'];

	public static function load($key, $password = '')
	{
		$components = parent::load($key, $password);
		if (!isset($components['private'])) {
			return $components;
		}
		extract($components);
		unset($components['public'], $components['private']);

		list($p, $q, $g, $y) = Strings::unpackSSH2('iiii', $public);
		list($x) = Strings::unpackSSH2('i', $private);

		return compact('p', 'q', 'g', 'y', 'x', 'comment');
	}

	public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = false, array $options = [])
	{
		if ($q->getLength() != 160) {
			throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
		}

		$public = Strings::packSSH2('iiii', $p, $q, $g, $y);
		$private = Strings::packSSH2('i', $x);

		return self::wrapPrivateKey($public, $private, 'ssh-dss', $password, $options);
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
	{
		if ($q->getLength() != 160) {
			throw new \InvalidArgumentException('SSH only supports keys with an N (length of Group Order q) of 160');
		}

		return self::wrapPublicKey(Strings::packSSH2('iiii', $p, $q, $g, $y), 'ssh-dss');
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Math\BigInteger;

abstract class Raw
{

	public static function load($key, $password = '')
	{
		if (!is_array($key)) {
			throw new \UnexpectedValueException('Key should be a array - not a ' . gettype($key));
		}

		switch (true) {
			case !isset($key['p']) || !isset($key['q']) || !isset($key['g']):
			case !$key['p'] instanceof BigInteger:
			case !$key['q'] instanceof BigInteger:
			case !$key['g'] instanceof BigInteger:
			case !isset($key['x']) && !isset($key['y']):
			case isset($key['x']) && !$key['x'] instanceof BigInteger:
			case isset($key['y']) && !$key['y'] instanceof BigInteger:
				throw new \UnexpectedValueException('Key appears to be malformed');
		}

		$options = ['p' => 1, 'q' => 1, 'g' => 1, 'x' => 1, 'y' => 1];

		return array_intersect_key($key, $options);
	}

	public static function savePrivateKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y, BigInteger $x, $password = '')
	{
		return compact('p', 'q', 'g', 'y', 'x');
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
	{
		return compact('p', 'q', 'g', 'y');
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Math\BigInteger;

abstract class XML
{

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (!class_exists('DOMDocument')) {
			throw new BadConfigurationException('The dom extension is not setup correctly on this system');
		}

		$use_errors = libxml_use_internal_errors(true);

		$dom = new \DOMDocument();
		if (substr($key, 0, 5) != '<?xml') {
			$key = '<xml>' . $key . '</xml>';
		}
		if (!$dom->loadXML($key)) {
			libxml_use_internal_errors($use_errors);
			throw new \UnexpectedValueException('Key does not appear to contain XML');
		}
		$xpath = new \DOMXPath($dom);
		$keys = ['p', 'q', 'g', 'y', 'j', 'seed', 'pgencounter'];
		foreach ($keys as $key) {

			$temp = $xpath->query("//*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$key']");
			if (!$temp->length) {
				continue;
			}
			$value = new BigInteger(Strings::base64_decode($temp->item(0)->nodeValue), 256);
			switch ($key) {
				case 'p':

					$components['p'] = $value;
					break;
				case 'q':
					$components['q'] = $value;
					break;
				case 'g':
					$components['g'] = $value;
					break;
				case 'y':
					$components['y'] = $value;

				case 'j':

				case 'seed':

				case 'pgencounter':
			}
		}

		libxml_use_internal_errors($use_errors);

		if (!isset($components['y'])) {
			throw new \UnexpectedValueException('Key is missing y component');
		}

		switch (true) {
			case !isset($components['p']):
			case !isset($components['q']):
			case !isset($components['g']):
				return ['y' => $components['y']];
		}

		return $components;
	}

	public static function savePublicKey(BigInteger $p, BigInteger $q, BigInteger $g, BigInteger $y)
	{
		return "<DSAKeyValue>\r\n" .
				'  <P>' . Strings::base64_encode($p->toBytes()) . "</P>\r\n" .
				'  <Q>' . Strings::base64_encode($q->toBytes()) . "</Q>\r\n" .
				'  <G>' . Strings::base64_encode($g->toBytes()) . "</G>\r\n" .
				'  <Y>' . Strings::base64_encode($y->toBytes()) . "</Y>\r\n" .
				'</DSAKeyValue>';
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Signature {

use phpseclib3\File\ASN1 as Encoder;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class ASN1
{

	public static function load($sig)
	{
		if (!is_string($sig)) {
			return false;
		}

		$decoded = Encoder::decodeBER($sig);
		if (empty($decoded)) {
			return false;
		}
		$components = Encoder::asn1map($decoded[0], Maps\DssSigValue::MAP);

		return $components;
	}

	public static function save(BigInteger $r, BigInteger $s)
	{
		return Encoder::encodeDER(compact('r', 's'), Maps\DssSigValue::MAP);
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Signature {

use phpseclib3\Math\BigInteger;

abstract class Raw
{

	public static function load($sig)
	{
		switch (true) {
			case !is_array($sig):
			case !isset($sig['r']) || !isset($sig['s']):
			case !$sig['r'] instanceof BigInteger:
			case !$sig['s'] instanceof BigInteger:
				return false;
		}

		return [
			'r' => $sig['r'],
			's' => $sig['s']
		];
	}

	public static function save(BigInteger $r, BigInteger $s)
	{
		return compact('r', 's');
	}
}
}

namespace phpseclib3\Crypt\DSA\Formats\Signature {

use phpseclib3\Crypt\Common\Formats\Signature\Raw as Progenitor;

abstract class Raw extends Progenitor
{
}
}

namespace phpseclib3\Crypt\DSA\Formats\Signature {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;

abstract class SSH2
{

	public static function load($sig)
	{
		if (!is_string($sig)) {
			return false;
		}

		$result = Strings::unpackSSH2('ss', $sig);
		if ($result === false) {
			return false;
		}
		list($type, $blob) = $result;
		if ($type != 'ssh-dss' || strlen($blob) != 40) {
			return false;
		}

		return [
			'r' => new BigInteger(substr($blob, 0, 20), 256),
			's' => new BigInteger(substr($blob, 20), 256)
		];
	}

	public static function save(BigInteger $r, BigInteger $s)
	{
		if ($r->getLength() > 160 || $s->getLength() > 160) {
			return false;
		}
		return Strings::packSSH2(
			'ss',
			'ssh-dss',
			str_pad($r->toBytes(), 20, "\0", STR_PAD_LEFT) .
			str_pad($s->toBytes(), 20, "\0", STR_PAD_LEFT)
		);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\Binary as BinaryCurve;
use phpseclib3\Crypt\EC\BaseCurves\Prime as PrimeCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

trait Common
{

	private static $curveOIDs = [];

	protected static $childOIDsLoaded = false;

	private static $useNamedCurves = true;

	private static function initialize_static_variables()
	{
		if (empty(self::$curveOIDs)) {

			self::$curveOIDs = [
				'prime192v1' => '1.2.840.10045.3.1.1',
				'prime192v2' => '1.2.840.10045.3.1.2',
				'prime192v3' => '1.2.840.10045.3.1.3',
				'prime239v1' => '1.2.840.10045.3.1.4',
				'prime239v2' => '1.2.840.10045.3.1.5',
				'prime239v3' => '1.2.840.10045.3.1.6',
				'prime256v1' => '1.2.840.10045.3.1.7',

				'nistp256' => '1.2.840.10045.3.1.7',
				'nistp384' => '1.3.132.0.34',
				'nistp521' => '1.3.132.0.35',

				'nistk163' => '1.3.132.0.1',
				'nistp192' => '1.2.840.10045.3.1.1',
				'nistp224' => '1.3.132.0.33',
				'nistk233' => '1.3.132.0.26',
				'nistb233' => '1.3.132.0.27',
				'nistk283' => '1.3.132.0.16',
				'nistk409' => '1.3.132.0.36',
				'nistb409' => '1.3.132.0.37',
				'nistt571' => '1.3.132.0.38',

				'secp192r1' => '1.2.840.10045.3.1.1',
				'sect163k1' => '1.3.132.0.1',
				'sect163r2' => '1.3.132.0.15',
				'secp224r1' => '1.3.132.0.33',
				'sect233k1' => '1.3.132.0.26',
				'sect233r1' => '1.3.132.0.27',
				'secp256r1' => '1.2.840.10045.3.1.7',
				'sect283k1' => '1.3.132.0.16',
				'sect283r1' => '1.3.132.0.17',
				'secp384r1' => '1.3.132.0.34',
				'sect409k1' => '1.3.132.0.36',
				'sect409r1' => '1.3.132.0.37',
				'secp521r1' => '1.3.132.0.35',
				'sect571k1' => '1.3.132.0.38',
				'sect571r1' => '1.3.132.0.39',

				'secp112r1' => '1.3.132.0.6',
				'secp112r2' => '1.3.132.0.7',
				'secp128r1' => '1.3.132.0.28',
				'secp128r2' => '1.3.132.0.29',
				'secp160k1' => '1.3.132.0.9',
				'secp160r1' => '1.3.132.0.8',
				'secp160r2' => '1.3.132.0.30',
				'secp192k1' => '1.3.132.0.31',
				'secp224k1' => '1.3.132.0.32',
				'secp256k1' => '1.3.132.0.10',

				'sect113r1' => '1.3.132.0.4',
				'sect113r2' => '1.3.132.0.5',
				'sect131r1' => '1.3.132.0.22',
				'sect131r2' => '1.3.132.0.23',
				'sect163r1' => '1.3.132.0.2',
				'sect193r1' => '1.3.132.0.24',
				'sect193r2' => '1.3.132.0.25',
				'sect239k1' => '1.3.132.0.3',

				'brainpoolP160r1' => '1.3.36.3.3.2.8.1.1.1',
				'brainpoolP160t1' => '1.3.36.3.3.2.8.1.1.2',
				'brainpoolP192r1' => '1.3.36.3.3.2.8.1.1.3',
				'brainpoolP192t1' => '1.3.36.3.3.2.8.1.1.4',
				'brainpoolP224r1' => '1.3.36.3.3.2.8.1.1.5',
				'brainpoolP224t1' => '1.3.36.3.3.2.8.1.1.6',
				'brainpoolP256r1' => '1.3.36.3.3.2.8.1.1.7',
				'brainpoolP256t1' => '1.3.36.3.3.2.8.1.1.8',
				'brainpoolP320r1' => '1.3.36.3.3.2.8.1.1.9',
				'brainpoolP320t1' => '1.3.36.3.3.2.8.1.1.10',
				'brainpoolP384r1' => '1.3.36.3.3.2.8.1.1.11',
				'brainpoolP384t1' => '1.3.36.3.3.2.8.1.1.12',
				'brainpoolP512r1' => '1.3.36.3.3.2.8.1.1.13',
				'brainpoolP512t1' => '1.3.36.3.3.2.8.1.1.14'
			];
			ASN1::loadOIDs([
				'prime-field' => '1.2.840.10045.1.1',
				'characteristic-two-field' => '1.2.840.10045.1.2',
				'characteristic-two-basis' => '1.2.840.10045.1.2.3',

				'gnBasis' => '1.2.840.10045.1.2.3.1',
				'tpBasis' => '1.2.840.10045.1.2.3.2',
				'ppBasis' => '1.2.840.10045.1.2.3.3'
			] + self::$curveOIDs);
		}
	}

	public static function setImplicitCurve(BaseCurve $curve)
	{
		self::$implicitCurve = $curve;
	}

	protected static function loadCurveByParam(array $params)
	{
		if (count($params) > 1) {
			throw new \RuntimeException('No parameters are present');
		}
		if (isset($params['namedCurve'])) {
			$curve = '\phpseclib3\Crypt\EC\Curves\\' . $params['namedCurve'];
			if (!class_exists($curve)) {
				throw new UnsupportedCurveException('Named Curve of ' . $params['namedCurve'] . ' is not supported');
			}
			return new $curve();
		}
		if (isset($params['implicitCurve'])) {
			if (!isset(self::$implicitCurve)) {
				throw new \RuntimeException('Implicit curves can be provided by calling setImplicitCurve');
			}
			return self::$implicitCurve;
		}
		if (isset($params['specifiedCurve'])) {
			$data = $params['specifiedCurve'];
			switch ($data['fieldID']['fieldType']) {
				case 'prime-field':
					$curve = new PrimeCurve();
					$curve->setModulo($data['fieldID']['parameters']);
					$curve->setCoefficients(
						new BigInteger($data['curve']['a'], 256),
						new BigInteger($data['curve']['b'], 256)
					);
					$point = self::extractPoint("\0" . $data['base'], $curve);
					$curve->setBasePoint(...$point);
					$curve->setOrder($data['order']);
					return $curve;
				case 'characteristic-two-field':
					$curve = new BinaryCurve();
					$params = ASN1::decodeBER($data['fieldID']['parameters']);
					$params = ASN1::asn1map($params[0], Maps\Characteristic_two::MAP);
					$modulo = [(int) $params['m']->toString()];
					switch ($params['basis']) {
						case 'tpBasis':
							$modulo[] = (int) $params['parameters']->toString();
							break;
						case 'ppBasis':
							$temp = ASN1::decodeBER($params['parameters']);
							$temp = ASN1::asn1map($temp[0], Maps\Pentanomial::MAP);
							$modulo[] = (int) $temp['k3']->toString();
							$modulo[] = (int) $temp['k2']->toString();
							$modulo[] = (int) $temp['k1']->toString();
					}
					$modulo[] = 0;
					$curve->setModulo(...$modulo);
					$len = ceil($modulo[0] / 8);
					$curve->setCoefficients(
						Strings::bin2hex($data['curve']['a']),
						Strings::bin2hex($data['curve']['b'])
					);
					$point = self::extractPoint("\0" . $data['base'], $curve);
					$curve->setBasePoint(...$point);
					$curve->setOrder($data['order']);
					return $curve;
				default:
					throw new UnsupportedCurveException('Field Type of ' . $data['fieldID']['fieldType'] . ' is not supported');
			}
		}
		throw new \RuntimeException('No valid parameters are present');
	}

	public static function extractPoint($str, BaseCurve $curve)
	{
		if ($curve instanceof TwistedEdwardsCurve) {

			$y = $str;
			$y = strrev($y);
			$sign = (bool) (ord($y[0]) & 0x80);
			$y[0] = $y[0] & chr(0x7F);
			$y = new BigInteger($y, 256);
			if ($y->compare($curve->getModulo()) >= 0) {
				throw new \RuntimeException('The Y coordinate should not be >= the modulo');
			}
			$point = $curve->recoverX($y, $sign);
			if (!$curve->verifyPoint($point)) {
				throw new \RuntimeException('Unable to verify that point exists on curve');
			}
			return $point;
		}

		if (($val = Strings::shift($str)) != "\0") {
			throw new \UnexpectedValueException('extractPoint expects the first byte to be null - not ' . Strings::bin2hex($val));
		}
		if ($str == "\0") {
			return [];
		}

		$keylen = strlen($str);
		$order = $curve->getLengthInBytes();

		if ($keylen == $order + 1) {
			return $curve->derivePoint($str);
		}

		if ($keylen == 2 * $order + 1) {
			preg_match("#(.)(.{{$order}})(.{{$order}})#s", $str, $matches);
			list(, $w, $x, $y) = $matches;
			if ($w != "\4") {
				throw new \UnexpectedValueException('The first byte of an uncompressed point should be 04 - not ' . Strings::bin2hex($val));
			}
			$point = [
				$curve->convertInteger(new BigInteger($x, 256)),
				$curve->convertInteger(new BigInteger($y, 256))
			];

			if (!$curve->verifyPoint($point)) {
				throw new \RuntimeException('Unable to verify that point exists on curve');
			}

			return $point;
		}

		throw new \UnexpectedValueException('The string representation of the points is not of an appropriate length');
	}

	private static function encodeParameters(BaseCurve $curve, $returnArray = false, array $options = [])
	{
		$useNamedCurves = isset($options['namedCurve']) ? $options['namedCurve'] : self::$useNamedCurves;

		$reflect = new \ReflectionClass($curve);
		$name = $reflect->getShortName();
		if ($useNamedCurves) {
			if (isset(self::$curveOIDs[$name])) {
				if ($reflect->isFinal()) {
					$reflect = $reflect->getParentClass();
					$name = $reflect->getShortName();
				}
				return $returnArray ?
					['namedCurve' => $name] :
					ASN1::encodeDER(['namedCurve' => $name], Maps\ECParameters::MAP);
			}
			foreach (phpseclib3__GetECCurveMap() as $file) {
				if ($file->getExtension() != 'php') {
					continue;
				}
				$testName = $file->getBasename('.php');
				$class = 'phpseclib3\Crypt\EC\Curves\\' . $testName;
				$reflect = new \ReflectionClass($class);
				if ($reflect->isFinal()) {
					continue;
				}
				$candidate = new $class();
				switch ($name) {
					case 'Prime':
						if (!$candidate instanceof PrimeCurve) {
							break;
						}
						if (!$candidate->getModulo()->equals($curve->getModulo())) {
							break;
						}
						if ($candidate->getA()->toBytes() != $curve->getA()->toBytes()) {
							break;
						}
						if ($candidate->getB()->toBytes() != $curve->getB()->toBytes()) {
							break;
						}

						list($candidateX, $candidateY) = $candidate->getBasePoint();
						list($curveX, $curveY) = $curve->getBasePoint();
						if ($candidateX->toBytes() != $curveX->toBytes()) {
							break;
						}
						if ($candidateY->toBytes() != $curveY->toBytes()) {
							break;
						}

						return $returnArray ?
							['namedCurve' => $testName] :
							ASN1::encodeDER(['namedCurve' => $testName], Maps\ECParameters::MAP);
					case 'Binary':
						if (!$candidate instanceof BinaryCurve) {
							break;
						}
						if ($candidate->getModulo() != $curve->getModulo()) {
							break;
						}
						if ($candidate->getA()->toBytes() != $curve->getA()->toBytes()) {
							break;
						}
						if ($candidate->getB()->toBytes() != $curve->getB()->toBytes()) {
							break;
						}

						list($candidateX, $candidateY) = $candidate->getBasePoint();
						list($curveX, $curveY) = $curve->getBasePoint();
						if ($candidateX->toBytes() != $curveX->toBytes()) {
							break;
						}
						if ($candidateY->toBytes() != $curveY->toBytes()) {
							break;
						}

						return $returnArray ?
							['namedCurve' => $testName] :
							ASN1::encodeDER(['namedCurve' => $testName], Maps\ECParameters::MAP);
				}
			}
		}

		$order = $curve->getOrder();

		if (!$order) {
			throw new \RuntimeException('Specified Curves need the order to be specified');
		}
		$point = $curve->getBasePoint();
		$x = $point[0]->toBytes();
		$y = $point[1]->toBytes();

		if ($curve instanceof PrimeCurve) {

			$data = [
				'version' => 'ecdpVer1',
				'fieldID' => [
					'fieldType' => 'prime-field',
					'parameters' => $curve->getModulo()
				],
				'curve' => [
					'a' => $curve->getA()->toBytes(),
					'b' => $curve->getB()->toBytes()
				],
				'base' => "\4" . $x . $y,
				'order' => $order
			];

			return $returnArray ?
				['specifiedCurve' => $data] :
				ASN1::encodeDER(['specifiedCurve' => $data], Maps\ECParameters::MAP);
		}
		if ($curve instanceof BinaryCurve) {
			$modulo = $curve->getModulo();
			$basis = count($modulo);
			$m = array_shift($modulo);
			array_pop($modulo);

			switch ($basis) {
				case 3:
					$basis = 'tpBasis';
					$modulo = new BigInteger($modulo[0]);
					break;
				case 5:
					$basis = 'ppBasis';

					$modulo = [
						'k1' => new BigInteger($modulo[2]),
						'k2' => new BigInteger($modulo[1]),
						'k3' => new BigInteger($modulo[0])
					];
					$modulo = ASN1::encodeDER($modulo, Maps\Pentanomial::MAP);
					$modulo = new ASN1\Element($modulo);
			}
			$params = ASN1::encodeDER([
				'm' => new BigInteger($m),
				'basis' => $basis,
				'parameters' => $modulo
			], Maps\Characteristic_two::MAP);
			$params = new ASN1\Element($params);
			$a = ltrim($curve->getA()->toBytes(), "\0");
			if (!strlen($a)) {
				$a = "\0";
			}
			$b = ltrim($curve->getB()->toBytes(), "\0");
			if (!strlen($b)) {
				$b = "\0";
			}
			$data = [
				'version' => 'ecdpVer1',
				'fieldID' => [
					'fieldType' => 'characteristic-two-field',
					'parameters' => $params
				],
				'curve' => [
					'a' => $a,
					'b' => $b
				],
				'base' => "\4" . $x . $y,
				'order' => $order
			];

			return $returnArray ?
				['specifiedCurve' => $data] :
				ASN1::encodeDER(['specifiedCurve' => $data], Maps\ECParameters::MAP);
		}

		throw new UnsupportedCurveException('Curve cannot be serialized');
	}

	public static function useSpecifiedCurve()
	{
		self::$useNamedCurves = false;
	}

	public static function useNamedCurve()
	{
		self::$useNamedCurves = true;
	}
}
}

namespace phpseclib3\Crypt\Common\Formats\Keys {

use phpseclib3\Common\Functions\Strings;

abstract class JWK
{

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		$key = preg_replace('#\s#', '', $key);

		if (PHP_VERSION_ID >= 73000) {
			$key = json_decode($key, null, 512, JSON_THROW_ON_ERROR);
		} else {
			$key = json_decode($key);
			if (!$key) {
				throw new \RuntimeException('Unable to decode JSON');
			}
		}

		if (isset($key->kty)) {
			return $key;
		}

		if (count($key->keys) != 1) {
			throw new \RuntimeException('Although the JWK key format supports multiple keys phpseclib does not');
		}

		return $key->keys[0];
	}

	protected static function wrapKey(array $key, array $options)
	{
		return json_encode(['keys' => [$key + $options]]);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\JWK as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Curves\secp256k1;
use phpseclib3\Crypt\EC\Curves\secp256r1;
use phpseclib3\Crypt\EC\Curves\secp384r1;
use phpseclib3\Crypt\EC\Curves\secp521r1;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\Math\BigInteger;

abstract class JWK extends Progenitor
{
	use Common;

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		switch ($key->kty) {
			case 'EC':
				switch ($key->crv) {
					case 'P-256':
					case 'P-384':
					case 'P-521':
					case 'secp256k1':
						break;
					default:
						throw new UnsupportedCurveException('Only P-256, P-384, P-521 and secp256k1 curves are accepted (' . $key->crv . ' provided)');
				}
				break;
			case 'OKP':
				switch ($key->crv) {
					case 'Ed25519':
					case 'Ed448':
						break;
					default:
						throw new UnsupportedCurveException('Only Ed25519 and Ed448 curves are accepted (' . $key->crv . ' provided)');
				}
				break;
			default:
				throw new \Exception('Only EC and OKP JWK keys are supported');
		}

		$curve = '\phpseclib3\Crypt\EC\Curves\\' . str_replace('P-', 'nistp', $key->crv);
		$curve = new $curve();

		if ($curve instanceof TwistedEdwardsCurve) {
			$QA = self::extractPoint(Strings::base64url_decode($key->x), $curve);
			if (!isset($key->d)) {
				return compact('curve', 'QA');
			}
			$arr = $curve->extractSecret(Strings::base64url_decode($key->d));
			return compact('curve', 'QA') + $arr;
		}

		$QA = [
			$curve->convertInteger(new BigInteger(Strings::base64url_decode($key->x), 256)),
			$curve->convertInteger(new BigInteger(Strings::base64url_decode($key->y), 256))
		];

		if (!$curve->verifyPoint($QA)) {
			throw new \RuntimeException('Unable to verify that point exists on curve');
		}

		if (!isset($key->d)) {
			return compact('curve', 'QA');
		}

		$dA = new BigInteger(Strings::base64url_decode($key->d), 256);

		$curve->rangeCheck($dA);

		return compact('curve', 'dA', 'QA');
	}

	private static function getAlias(BaseCurve $curve)
	{
		switch (true) {
			case $curve instanceof secp256r1:
				return 'P-256';
			case $curve instanceof secp384r1:
				return 'P-384';
			case $curve instanceof secp521r1:
				return 'P-521';
			case $curve instanceof secp256k1:
				return 'secp256k1';
		}

		$reflect = new \ReflectionClass($curve);
		$curveName = $reflect->isFinal() ?
			$reflect->getParentClass()->getShortName() :
			$reflect->getShortName();
		throw new UnsupportedCurveException("$curveName is not a supported curve");
	}

	private static function savePublicKeyHelper(BaseCurve $curve, array $publicKey)
	{
		if ($curve instanceof TwistedEdwardsCurve) {
			return [
				'kty' => 'OKP',
				'crv' => $curve instanceof Ed25519 ? 'Ed25519' : 'Ed448',
				'x' => Strings::base64url_encode($curve->encodePoint($publicKey))
			];
		}

		return [
			'kty' => 'EC',
			'crv' => self::getAlias($curve),
			'x' => Strings::base64url_encode($publicKey[0]->toBytes()),
			'y' => Strings::base64url_encode($publicKey[1]->toBytes())
		];
	}

	public static function savePublicKey(BaseCurve $curve, array $publicKey, array $options = [])
	{
		$key = self::savePublicKeyHelper($curve, $publicKey);

		return self::wrapKey($key, $options);
	}

	public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = '', array $options = [])
	{
		$key = self::savePublicKeyHelper($curve, $publicKey);
		$key['d'] = $curve instanceof TwistedEdwardsCurve ? $secret : $privateKey->toBytes();
		$key['d'] = Strings::base64url_encode($key['d']);

		return self::wrapKey($key, $options);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

abstract class libsodium
{
	use Common;

	const IS_INVISIBLE = true;

	public static function load($key, $password = '')
	{
		switch (strlen($key)) {
			case 32:
				$public = $key;
				break;
			case 64:
				$private = substr($key, 0, 32);
				$public = substr($key, -32);
				break;
			case 96:
				$public = substr($key, -32);
				if (substr($key, 32, 32) != $public) {
					throw new \RuntimeException('Keys with 96 bytes should have the 2nd and 3rd set of 32 bytes match');
				}
				$private = substr($key, 0, 32);
				break;
			default:
				throw new \RuntimeException('libsodium keys need to either be 32 bytes long, 64 bytes long or 96 bytes long');
		}

		$curve = new Ed25519();
		$components = ['curve' => $curve];
		if (isset($private)) {
			$arr = $curve->extractSecret($private);
			$components['dA'] = $arr['dA'];
			$components['secret'] = $arr['secret'];
		}
		$components['QA'] = isset($public) ?
			self::extractPoint($public, $curve) :
			$curve->multiplyPoint($curve->getBasePoint(), $components['dA']);

		return $components;
	}

	public static function savePublicKey(Ed25519 $curve, array $publicKey)
	{
		return $curve->encodePoint($publicKey);
	}

	public static function savePrivateKey(BigInteger $privateKey, Ed25519 $curve, array $publicKey, $secret = null, $password = '')
	{
		if (!isset($secret)) {
			throw new \RuntimeException('Private Key does not have a secret set');
		}
		if (strlen($secret) != 32) {
			throw new \RuntimeException('Private Key secret is not of the correct length');
		}
		if (!empty($password) && is_string($password)) {
			throw new UnsupportedFormatException('libsodium private keys do not support encryption');
		}
		return $secret . $curve->encodePoint($publicKey);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Crypt\EC\Curves\Curve448;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

abstract class MontgomeryPrivate
{

	const IS_INVISIBLE = true;

	public static function load($key, $password = '')
	{
		switch (strlen($key)) {
			case 32:
				$curve = new Curve25519();
				break;
			case 56:
				$curve = new Curve448();
				break;
			default:
				throw new \LengthException('The only supported lengths are 32 and 56');
		}

		$components = ['curve' => $curve];
		$components['dA'] = new BigInteger($key, 256);
		$curve->rangeCheck($components['dA']);

		$components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

		return $components;
	}

	public static function savePublicKey(MontgomeryCurve $curve, array $publicKey)
	{
		return strrev($publicKey[0]->toBytes());
	}

	public static function savePrivateKey(BigInteger $privateKey, MontgomeryCurve $curve, array $publicKey, $secret = null, $password = '')
	{
		if (!empty($password) && is_string($password)) {
			throw new UnsupportedFormatException('MontgomeryPrivate private keys do not support encryption');
		}

		return $privateKey->toBytes();
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Crypt\EC\Curves\Curve448;
use phpseclib3\Math\BigInteger;

abstract class MontgomeryPublic
{

	const IS_INVISIBLE = true;

	public static function load($key, $password = '')
	{
		switch (strlen($key)) {
			case 32:
				$curve = new Curve25519();
				break;
			case 56:
				$curve = new Curve448();
				break;
			default:
				throw new \LengthException('The only supported lengths are 32 and 56');
		}

		$components = ['curve' => $curve];
		$components['QA'] = [$components['curve']->convertInteger(new BigInteger(strrev($key), 256))];

		return $components;
	}

	public static function savePublicKey(MontgomeryCurve $curve, array $publicKey)
	{
		return strrev($publicKey[0]->toBytes());
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\OpenSSH as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\Math\BigInteger;

abstract class OpenSSH extends Progenitor
{
	use Common;

	protected static $types = [
		'ecdsa-sha2-nistp256',
		'ecdsa-sha2-nistp384',
		'ecdsa-sha2-nistp521',
		'ssh-ed25519'
	];

	public static function load($key, $password = '')
	{
		$parsed = parent::load($key, $password);

		if (isset($parsed['paddedKey'])) {
			$paddedKey = $parsed['paddedKey'];
			list($type) = Strings::unpackSSH2('s', $paddedKey);
			if ($type != $parsed['type']) {
				throw new \RuntimeException("The public and private keys are not of the same type ($type vs $parsed[type])");
			}
			if ($type == 'ssh-ed25519') {
				list(, $key, $comment) = Strings::unpackSSH2('sss', $paddedKey);
				$key = libsodium::load($key);
				$key['comment'] = $comment;
				return $key;
			}
			list($curveName, $publicKey, $privateKey, $comment) = Strings::unpackSSH2('ssis', $paddedKey);
			$curve = self::loadCurveByParam(['namedCurve' => $curveName]);
			$curve->rangeCheck($privateKey);
			return [
				'curve' => $curve,
				'dA' => $privateKey,
				'QA' => self::extractPoint("\0$publicKey", $curve),
				'comment' => $comment
			];
		}

		if ($parsed['type'] == 'ssh-ed25519') {
			if (Strings::shift($parsed['publicKey'], 4) != "\0\0\0\x20") {
				throw new \RuntimeException('Length of ssh-ed25519 key should be 32');
			}

			$curve = new Ed25519();
			$qa = self::extractPoint($parsed['publicKey'], $curve);
		} else {
			list($curveName, $publicKey) = Strings::unpackSSH2('ss', $parsed['publicKey']);
			$curveName = '\phpseclib3\Crypt\EC\Curves\\' . $curveName;
			$curve = new $curveName();

			$qa = self::extractPoint("\0" . $publicKey, $curve);
		}

		return [
			'curve' => $curve,
			'QA' => $qa,
			'comment' => $parsed['comment']
		];
	}

	private static function getAlias(BaseCurve $curve)
	{
		self::initialize_static_variables();

		$reflect = new \ReflectionClass($curve);
		$name = $reflect->getShortName();

		$oid = self::$curveOIDs[$name];
		$aliases = array_filter(self::$curveOIDs, function ($v) use ($oid) {
			return $v == $oid;
		});
		$aliases = array_keys($aliases);

		for ($i = 0; $i < count($aliases); $i++) {
			if (in_array('ecdsa-sha2-' . $aliases[$i], self::$types)) {
				$alias = $aliases[$i];
				break;
			}
		}

		if (!isset($alias)) {
			throw new UnsupportedCurveException($name . ' is not a curve that the OpenSSH plugin supports');
		}

		return $alias;
	}

	public static function savePublicKey(BaseCurve $curve, array $publicKey, array $options = [])
	{
		$comment = isset($options['comment']) ? $options['comment'] : self::$comment;

		if ($curve instanceof Ed25519) {
			$key = Strings::packSSH2('ss', 'ssh-ed25519', $curve->encodePoint($publicKey));

			if (isset($options['binary']) ? $options['binary'] : self::$binary) {
				return $key;
			}

			$key = 'ssh-ed25519 ' . base64_encode($key) . ' ' . $comment;
			return $key;
		}

		$alias = self::getAlias($curve);

		$points = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();
		$key = Strings::packSSH2('sss', 'ecdsa-sha2-' . $alias, $alias, $points);

		if (isset($options['binary']) ? $options['binary'] : self::$binary) {
			return $key;
		}

		$key = 'ecdsa-sha2-' . $alias . ' ' . base64_encode($key) . ' ' . $comment;

		return $key;
	}

	public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = '', array $options = [])
	{
		if ($curve instanceof Ed25519) {
			if (!isset($secret)) {
				throw new \RuntimeException('Private Key does not have a secret set');
			}
			if (strlen($secret) != 32) {
				throw new \RuntimeException('Private Key secret is not of the correct length');
			}

			$pubKey = $curve->encodePoint($publicKey);

			$publicKey = Strings::packSSH2('ss', 'ssh-ed25519', $pubKey);
			$privateKey = Strings::packSSH2('sss', 'ssh-ed25519', $pubKey, $secret . $pubKey);

			return self::wrapPrivateKey($publicKey, $privateKey, $password, $options);
		}

		$alias = self::getAlias($curve);

		$points = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();
		$publicKey = self::savePublicKey($curve, $publicKey, ['binary' => true]);

		$privateKey = Strings::packSSH2('sssi', 'ecdsa-sha2-' . $alias, $alias, $points, $privateKey);

		return self::wrapPrivateKey($publicKey, $privateKey, $password, $options);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS1 extends Progenitor
{
	use Common;

	public static function load($key, $password = '')
	{
		self::initialize_static_variables();

		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (strpos($key, 'BEGIN EC PARAMETERS') && strpos($key, 'BEGIN EC PRIVATE KEY')) {
			$components = [];

			preg_match('#-*BEGIN EC PRIVATE KEY-*[^-]*-*END EC PRIVATE KEY-*#s', $key, $matches);
			$decoded = parent::load($matches[0], $password);
			$decoded = ASN1::decodeBER($decoded);
			if (!$decoded) {
				throw new \RuntimeException('Unable to decode BER');
			}

			$ecPrivate = ASN1::asn1map($decoded[0], Maps\ECPrivateKey::MAP);
			if (!is_array($ecPrivate)) {
				throw new \RuntimeException('Unable to perform ASN1 mapping');
			}

			if (isset($ecPrivate['parameters'])) {
				$components['curve'] = self::loadCurveByParam($ecPrivate['parameters']);
			}

			preg_match('#-*BEGIN EC PARAMETERS-*[^-]*-*END EC PARAMETERS-*#s', $key, $matches);
			$decoded = parent::load($matches[0], '');
			$decoded = ASN1::decodeBER($decoded);
			if (!$decoded) {
				throw new \RuntimeException('Unable to decode BER');
			}
			$ecParams = ASN1::asn1map($decoded[0], Maps\ECParameters::MAP);
			if (!is_array($ecParams)) {
				throw new \RuntimeException('Unable to perform ASN1 mapping');
			}
			$ecParams = self::loadCurveByParam($ecParams);

			if (isset($components['curve']) && self::encodeParameters($ecParams, false, []) != self::encodeParameters($components['curve'], false, [])) {
				throw new \RuntimeException('EC PARAMETERS does not correspond to EC PRIVATE KEY');
			}

			if (!isset($components['curve'])) {
				$components['curve'] = $ecParams;
			}

			$components['dA'] = new BigInteger($ecPrivate['privateKey'], 256);
			$components['curve']->rangeCheck($components['dA']);
			$components['QA'] = isset($ecPrivate['publicKey']) ?
				self::extractPoint($ecPrivate['publicKey'], $components['curve']) :
				$components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

			return $components;
		}

		$key = parent::load($key, $password);

		$decoded = ASN1::decodeBER($key);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}

		$key = ASN1::asn1map($decoded[0], Maps\ECParameters::MAP);
		if (is_array($key)) {
			return ['curve' => self::loadCurveByParam($key)];
		}

		$key = ASN1::asn1map($decoded[0], Maps\ECPrivateKey::MAP);
		if (!is_array($key)) {
			throw new \RuntimeException('Unable to perform ASN1 mapping');
		}
		if (!isset($key['parameters'])) {
			throw new \RuntimeException('Key cannot be loaded without parameters');
		}

		$components = [];
		$components['curve'] = self::loadCurveByParam($key['parameters']);
		$components['dA'] = new BigInteger($key['privateKey'], 256);
		$components['QA'] = isset($ecPrivate['publicKey']) ?
			self::extractPoint($ecPrivate['publicKey'], $components['curve']) :
			$components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

		return $components;
	}

	public static function saveParameters(BaseCurve $curve, array $options = [])
	{
		self::initialize_static_variables();

		if ($curve instanceof TwistedEdwardsCurve || $curve instanceof MontgomeryCurve) {
			throw new UnsupportedCurveException('TwistedEdwards and Montgomery Curves are not supported');
		}

		$key = self::encodeParameters($curve, false, $options);

		return "-----BEGIN EC PARAMETERS-----\r\n" .
				chunk_split(Strings::base64_encode($key), 64) .
				"-----END EC PARAMETERS-----\r\n";
	}

	public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = '', array $options = [])
	{
		self::initialize_static_variables();

		if ($curve instanceof TwistedEdwardsCurve	|| $curve instanceof MontgomeryCurve) {
			throw new UnsupportedCurveException('TwistedEdwards Curves are not supported');
		}

		$publicKey = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();

		$key = [
			'version' => 'ecPrivkeyVer1',
			'privateKey' => $privateKey->toBytes(),
			'parameters' => new ASN1\Element(self::encodeParameters($curve)),
			'publicKey' => "\0" . $publicKey
		];

		$key = ASN1::encodeDER($key, Maps\ECPrivateKey::MAP);

		return self::wrapPrivateKey($key, 'EC', $password, $options);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS8 extends Progenitor
{
	use Common;

	const OID_NAME = ['id-ecPublicKey', 'id-Ed25519', 'id-Ed448'];

	const OID_VALUE = ['1.2.840.10045.2.1', '1.3.101.112', '1.3.101.113'];

	public static function load($key, $password = '')
	{

		self::initialize_static_variables();

		$key = parent::load($key, $password);

		$type = isset($key['privateKey']) ? 'privateKey' : 'publicKey';

		switch ($key[$type . 'Algorithm']['algorithm']) {
			case 'id-Ed25519':
			case 'id-Ed448':
				return self::loadEdDSA($key);
		}

		$decoded = ASN1::decodeBER($key[$type . 'Algorithm']['parameters']->element);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}
		$params = ASN1::asn1map($decoded[0], Maps\ECParameters::MAP);
		if (!$params) {
			throw new \RuntimeException('Unable to decode the parameters using Maps\ECParameters');
		}

		$components = [];
		$components['curve'] = self::loadCurveByParam($params);

		if ($type == 'publicKey') {
			$components['QA'] = self::extractPoint("\0" . $key['publicKey'], $components['curve']);

			return $components;
		}

		$decoded = ASN1::decodeBER($key['privateKey']);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}
		$key = ASN1::asn1map($decoded[0], Maps\ECPrivateKey::MAP);
		if (isset($key['parameters']) && $params != $key['parameters']) {
			throw new \RuntimeException('The PKCS8 parameter field does not match the private key parameter field');
		}

		$components['dA'] = new BigInteger($key['privateKey'], 256);
		$components['curve']->rangeCheck($components['dA']);
		$components['QA'] = isset($key['publicKey']) ?
			self::extractPoint($key['publicKey'], $components['curve']) :
			$components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);

		return $components;
	}

	private static function loadEdDSA(array $key)
	{
		$components = [];

		if (isset($key['privateKey'])) {
			$components['curve'] = $key['privateKeyAlgorithm']['algorithm'] == 'id-Ed25519' ? new Ed25519() : new Ed448();
			$expected = chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength($components['curve']::SIZE);
			if (substr($key['privateKey'], 0, 2) != $expected) {
				throw new \RuntimeException(
					'The first two bytes of the ' .
					$key['privateKeyAlgorithm']['algorithm'] .
					' private key field should be 0x' . bin2hex($expected)
				);
			}
			$arr = $components['curve']->extractSecret(substr($key['privateKey'], 2));
			$components['dA'] = $arr['dA'];
			$components['secret'] = $arr['secret'];
		}

		if (isset($key['publicKey'])) {
			if (!isset($components['curve'])) {
				$components['curve'] = $key['publicKeyAlgorithm']['algorithm'] == 'id-Ed25519' ? new Ed25519() : new Ed448();
			}

			$components['QA'] = self::extractPoint($key['publicKey'], $components['curve']);
		}

		if (isset($key['privateKey']) && !isset($components['QA'])) {
			$components['QA'] = $components['curve']->multiplyPoint($components['curve']->getBasePoint(), $components['dA']);
		}

		return $components;
	}

	public static function savePublicKey(BaseCurve $curve, array $publicKey, array $options = [])
	{
		self::initialize_static_variables();

		if ($curve instanceof MontgomeryCurve) {
			throw new UnsupportedCurveException('Montgomery Curves are not supported');
		}

		if ($curve instanceof TwistedEdwardsCurve) {
			return self::wrapPublicKey(
				$curve->encodePoint($publicKey),
				null,
				$curve instanceof Ed25519 ? 'id-Ed25519' : 'id-Ed448',
				$options
			);
		}

		$params = new ASN1\Element(self::encodeParameters($curve, false, $options));

		$key = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();

		return self::wrapPublicKey($key, $params, 'id-ecPublicKey', $options);
	}

	public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = '', array $options = [])
	{
		self::initialize_static_variables();

		if ($curve instanceof MontgomeryCurve) {
			throw new UnsupportedCurveException('Montgomery Curves are not supported');
		}

		if ($curve instanceof TwistedEdwardsCurve) {
			return self::wrapPrivateKey(
				chr(ASN1::TYPE_OCTET_STRING) . ASN1::encodeLength($curve::SIZE) . $secret,
				[],
				null,
				$password,
				$curve instanceof Ed25519 ? 'id-Ed25519' : 'id-Ed448'
			);
		}

		$publicKey = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();

		$params = new ASN1\Element(self::encodeParameters($curve, false, $options));

		$key = [
			'version' => 'ecPrivkeyVer1',
			'privateKey' => $privateKey->toBytes(),

			'publicKey' => "\0" . $publicKey
		];

		$key = ASN1::encodeDER($key, Maps\ECPrivateKey::MAP);

		return self::wrapPrivateKey($key, [], $params, $password, 'id-ecPublicKey', '', $options);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PuTTY as Progenitor;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Math\BigInteger;

abstract class PuTTY extends Progenitor
{
	use Common;

	const PUBLIC_HANDLER = 'phpseclib3\Crypt\EC\Formats\Keys\OpenSSH';

	protected static $types = [
		'ecdsa-sha2-nistp256',
		'ecdsa-sha2-nistp384',
		'ecdsa-sha2-nistp521',
		'ssh-ed25519'
	];

	public static function load($key, $password = '')
	{
		$components = parent::load($key, $password);
		if (!isset($components['private'])) {
			return $components;
		}

		$private = $components['private'];

		$temp = Strings::base64_encode(Strings::packSSH2('s', $components['type']) . $components['public']);
		$components = OpenSSH::load($components['type'] . ' ' . $temp . ' ' . $components['comment']);

		if ($components['curve'] instanceof TwistedEdwardsCurve) {
			if (Strings::shift($private, 4) != "\0\0\0\x20") {
				throw new \RuntimeException('Length of ssh-ed25519 key should be 32');
			}
			$arr = $components['curve']->extractSecret($private);
			$components['dA'] = $arr['dA'];
			$components['secret'] = $arr['secret'];
		} else {
			list($components['dA']) = Strings::unpackSSH2('i', $private);
			$components['curve']->rangeCheck($components['dA']);
		}

		return $components;
	}

	public static function savePrivateKey(BigInteger $privateKey, BaseCurve $curve, array $publicKey, $secret = null, $password = false, array $options = [])
	{
		self::initialize_static_variables();

		$public = explode(' ', OpenSSH::savePublicKey($curve, $publicKey));
		$name = $public[0];
		$public = Strings::base64_decode($public[1]);
		list(, $length) = unpack('N', Strings::shift($public, 4));
		Strings::shift($public, $length);

		if (!$curve instanceof TwistedEdwardsCurve) {
			$private = $privateKey->toBytes();
			if (!(strlen($privateKey->toBits()) & 7)) {
				$private = "\0$private";
			}
		}

		$private = $curve instanceof TwistedEdwardsCurve ?
			Strings::packSSH2('s', $secret) :
			Strings::packSSH2('s', $private);

		return self::wrapPrivateKey($public, $private, $name, $password, $options);
	}

	public static function savePublicKey(BaseCurve $curve, array $publicKey)
	{
		$public = explode(' ', OpenSSH::savePublicKey($curve, $publicKey));
		$type = $public[0];
		$public = Strings::base64_decode($public[1]);
		list(, $length) = unpack('N', Strings::shift($public, 4));
		Strings::shift($public, $length);

		return self::wrapPublicKey($public, $type);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\EC\BaseCurves\Base as BaseCurve;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\Prime as PrimeCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\Math\BigInteger;

abstract class XML
{
	use Common;

	private static $namespace;

	private static $rfc4050 = false;

	public static function load($key, $password = '')
	{
		self::initialize_static_variables();

		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (!class_exists('DOMDocument')) {
			throw new BadConfigurationException('The dom extension is not setup correctly on this system');
		}

		$use_errors = libxml_use_internal_errors(true);

		$temp = self::isolateNamespace($key, 'http://www.w3.org/2009/xmldsig11#');
		if ($temp) {
			$key = $temp;
		}

		$temp = self::isolateNamespace($key, 'http://www.w3.org/2001/04/xmldsig-more#');
		if ($temp) {
			$key = $temp;
		}

		$dom = new \DOMDocument();
		if (substr($key, 0, 5) != '<?xml') {
			$key = '<xml>' . $key . '</xml>';
		}

		if (!$dom->loadXML($key)) {
			libxml_use_internal_errors($use_errors);
			throw new \UnexpectedValueException('Key does not appear to contain XML');
		}
		$xpath = new \DOMXPath($dom);
		libxml_use_internal_errors($use_errors);
		$curve = self::loadCurveByParam($xpath);

		$pubkey = self::query($xpath, 'publickey', 'Public Key is not present');

		$QA = self::query($xpath, 'ecdsakeyvalue')->length ?
			self::extractPointRFC4050($xpath, $curve) :
			self::extractPoint("\0" . $pubkey, $curve);

		libxml_use_internal_errors($use_errors);

		return compact('curve', 'QA');
	}

	private static function query(\DOMXPath $xpath, $name, $error = null, $decode = true)
	{
		$query = '/';
		$names = explode('/', $name);
		foreach ($names as $name) {
			$query .= "/*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$name']";
		}
		$result = $xpath->query($query);
		if (!isset($error)) {
			return $result;
		}

		if (!$result->length) {
			throw new \RuntimeException($error);
		}
		return $decode ? self::decodeValue($result->item(0)->textContent) : $result->item(0)->textContent;
	}

	private static function isolateNamespace($xml, $ns)
	{
		$dom = new \DOMDocument();
		if (!$dom->loadXML($xml)) {
			return false;
		}
		$xpath = new \DOMXPath($dom);
		$nodes = $xpath->query("//*[namespace::*[.='$ns'] and not(../namespace::*[.='$ns'])]");
		if (!$nodes->length) {
			return false;
		}
		$node = $nodes->item(0);
		$ns_name = $node->lookupPrefix($ns);
		if ($ns_name) {
			$node->removeAttributeNS($ns, $ns_name);
		}
		return $dom->saveXML($node);
	}

	private static function decodeValue($value)
	{
		return Strings::base64_decode(str_replace(["\r", "\n", ' ', "\t"], '', $value));
	}

	private static function extractPointRFC4050(\DOMXPath $xpath, BaseCurve $curve)
	{
		$x = self::query($xpath, 'publickey/x');
		$y = self::query($xpath, 'publickey/y');
		if (!$x->length || !$x->item(0)->hasAttribute('Value')) {
			throw new \RuntimeException('Public Key / X coordinate not found');
		}
		if (!$y->length || !$y->item(0)->hasAttribute('Value')) {
			throw new \RuntimeException('Public Key / Y coordinate not found');
		}
		$point = [
			$curve->convertInteger(new BigInteger($x->item(0)->getAttribute('Value'))),
			$curve->convertInteger(new BigInteger($y->item(0)->getAttribute('Value')))
		];
		if (!$curve->verifyPoint($point)) {
			throw new \RuntimeException('Unable to verify that point exists on curve');
		}
		return $point;
	}

	private static function loadCurveByParam(\DOMXPath $xpath)
	{
		$namedCurve = self::query($xpath, 'namedcurve');
		if ($namedCurve->length == 1) {
			$oid = $namedCurve->item(0)->getAttribute('URN');
			$oid = preg_replace('#[^\d.]#', '', $oid);
			$name = array_search($oid, self::$curveOIDs);
			if ($name === false) {
				throw new UnsupportedCurveException('Curve with OID of ' . $oid . ' is not supported');
			}

			$curve = '\phpseclib3\Crypt\EC\Curves\\' . $name;
			if (!class_exists($curve)) {
				throw new UnsupportedCurveException('Named Curve of ' . $name . ' is not supported');
			}
			return new $curve();
		}

		$params = self::query($xpath, 'explicitparams');
		if ($params->length) {
			return self::loadCurveByParamRFC4050($xpath);
		}

		$params = self::query($xpath, 'ecparameters');
		if (!$params->length) {
			throw new \RuntimeException('No parameters are present');
		}

		$fieldTypes = [
			'prime-field' => ['fieldid/prime/p'],
			'gnb' => ['fieldid/gnb/m'],
			'tnb' => ['fieldid/tnb/k'],
			'pnb' => ['fieldid/pnb/k1', 'fieldid/pnb/k2', 'fieldid/pnb/k3'],
			'unknown' => []
		];

		foreach ($fieldTypes as $type => $queries) {
			foreach ($queries as $query) {
				$result = self::query($xpath, $query);
				if (!$result->length) {
					continue 2;
				}
				$param = preg_replace('#.*/#', '', $query);
				$$param = self::decodeValue($result->item(0)->textContent);
			}
			break;
		}

		$a = self::query($xpath, 'curve/a', 'A coefficient is not present');
		$b = self::query($xpath, 'curve/b', 'B coefficient is not present');
		$base = self::query($xpath, 'base', 'Base point is not present');
		$order = self::query($xpath, 'order', 'Order is not present');

		switch ($type) {
			case 'prime-field':
				$curve = new PrimeCurve();
				$curve->setModulo(new BigInteger($p, 256));
				$curve->setCoefficients(
					new BigInteger($a, 256),
					new BigInteger($b, 256)
				);
				$point = self::extractPoint("\0" . $base, $curve);
				$curve->setBasePoint(...$point);
				$curve->setOrder(new BigInteger($order, 256));
				return $curve;
			case 'gnb':
			case 'tnb':
			case 'pnb':
			default:
				throw new UnsupportedCurveException('Field Type of ' . $type . ' is not supported');
		}
	}

	private static function loadCurveByParamRFC4050(\DOMXPath $xpath)
	{
		$fieldTypes = [
			'prime-field' => ['primefieldparamstype/p'],
			'unknown' => []
		];

		foreach ($fieldTypes as $type => $queries) {
			foreach ($queries as $query) {
				$result = self::query($xpath, $query);
				if (!$result->length) {
					continue 2;
				}
				$param = preg_replace('#.*/#', '', $query);
				$$param = $result->item(0)->textContent;
			}
			break;
		}

		$a = self::query($xpath, 'curveparamstype/a', 'A coefficient is not present', false);
		$b = self::query($xpath, 'curveparamstype/b', 'B coefficient is not present', false);
		$x = self::query($xpath, 'basepointparams/basepoint/ecpointtype/x', 'Base Point X is not present', false);
		$y = self::query($xpath, 'basepointparams/basepoint/ecpointtype/y', 'Base Point Y is not present', false);
		$order = self::query($xpath, 'order', 'Order is not present', false);

		switch ($type) {
			case 'prime-field':
				$curve = new PrimeCurve();

				$p = str_replace(["\r", "\n", ' ', "\t"], '', $p);
				$curve->setModulo(new BigInteger($p));

				$a = str_replace(["\r", "\n", ' ', "\t"], '', $a);
				$b = str_replace(["\r", "\n", ' ', "\t"], '', $b);
				$curve->setCoefficients(
					new BigInteger($a),
					new BigInteger($b)
				);

				$x = str_replace(["\r", "\n", ' ', "\t"], '', $x);
				$y = str_replace(["\r", "\n", ' ', "\t"], '', $y);
				$curve->setBasePoint(
					new BigInteger($x),
					new BigInteger($y)
				);

				$order = str_replace(["\r", "\n", ' ', "\t"], '', $order);
				$curve->setOrder(new BigInteger($order));
				return $curve;
			default:
				throw new UnsupportedCurveException('Field Type of ' . $type . ' is not supported');
		}
	}

	public static function setNamespace($namespace)
	{
		self::$namespace = $namespace;
	}

	public static function enableRFC4050Syntax()
	{
		self::$rfc4050 = true;
	}

	public static function disableRFC4050Syntax()
	{
		self::$rfc4050 = false;
	}

	public static function savePublicKey(BaseCurve $curve, array $publicKey, array $options = [])
	{
		self::initialize_static_variables();

		if ($curve instanceof TwistedEdwardsCurve || $curve instanceof MontgomeryCurve) {
			throw new UnsupportedCurveException('TwistedEdwards and Montgomery Curves are not supported');
		}

		if (empty(static::$namespace)) {
			$pre = $post = '';
		} else {
			$pre = static::$namespace . ':';
			$post = ':' . static::$namespace;
		}

		if (self::$rfc4050) {
			return '<' . $pre . 'ECDSAKeyValue xmlns' . $post . '="http://www.w3.org/2001/04/xmldsig-more#">' . "\r\n" .
					self::encodeXMLParameters($curve, $pre, $options) . "\r\n" .
					'<' . $pre . 'PublicKey>' . "\r\n" .
					'<' . $pre . 'X Value="' . $publicKey[0] . '" />' . "\r\n" .
					'<' . $pre . 'Y Value="' . $publicKey[1] . '" />' . "\r\n" .
					'</' . $pre . 'PublicKey>' . "\r\n" .
					'</' . $pre . 'ECDSAKeyValue>';
		}

		$publicKey = "\4" . $publicKey[0]->toBytes() . $publicKey[1]->toBytes();

		return '<' . $pre . 'ECDSAKeyValue xmlns' . $post . '="http://www.w3.org/2009/xmldsig11#">' . "\r\n" .
				self::encodeXMLParameters($curve, $pre, $options) . "\r\n" .
				'<' . $pre . 'PublicKey>' . Strings::base64_encode($publicKey) . '</' . $pre . 'PublicKey>' . "\r\n" .
				'</' . $pre . 'ECDSAKeyValue>';
	}

	private static function encodeXMLParameters(BaseCurve $curve, $pre, array $options = [])
	{
		$result = self::encodeParameters($curve, true, $options);

		if (isset($result['namedCurve'])) {
			$namedCurve = '<' . $pre . 'NamedCurve URI="urn:oid:' . self::$curveOIDs[$result['namedCurve']] . '" />';
			return self::$rfc4050 ?
				'<DomainParameters>' . str_replace('URI', 'URN', $namedCurve) . '</DomainParameters>' :
				$namedCurve;
		}

		if (self::$rfc4050) {
			$xml = '<' . $pre . 'ExplicitParams>' . "\r\n" .
					'<' . $pre . 'FieldParams>' . "\r\n";
			$temp = $result['specifiedCurve'];
			switch ($temp['fieldID']['fieldType']) {
				case 'prime-field':
					$xml .= '<' . $pre . 'PrimeFieldParamsType>' . "\r\n" .
							'<' . $pre . 'P>' . $temp['fieldID']['parameters'] . '</' . $pre . 'P>' . "\r\n" .
							'</' . $pre . 'PrimeFieldParamsType>' . "\r\n";
					$a = $curve->getA();
					$b = $curve->getB();
					list($x, $y) = $curve->getBasePoint();
					break;
				default:
					throw new UnsupportedCurveException('Field Type of ' . $temp['fieldID']['fieldType'] . ' is not supported');
			}
			$xml .= '</' . $pre . 'FieldParams>' . "\r\n" .
					'<' . $pre . 'CurveParamsType>' . "\r\n" .
					'<' . $pre . 'A>' . $a . '</' . $pre . 'A>' . "\r\n" .
					'<' . $pre . 'B>' . $b . '</' . $pre . 'B>' . "\r\n" .
					'</' . $pre . 'CurveParamsType>' . "\r\n" .
					'<' . $pre . 'BasePointParams>' . "\r\n" .
					'<' . $pre . 'BasePoint>' . "\r\n" .
					'<' . $pre . 'ECPointType>' . "\r\n" .
					'<' . $pre . 'X>' . $x . '</' . $pre . 'X>' . "\r\n" .
					'<' . $pre . 'Y>' . $y . '</' . $pre . 'Y>' . "\r\n" .
					'</' . $pre . 'ECPointType>' . "\r\n" .
					'</' . $pre . 'BasePoint>' . "\r\n" .
					'<' . $pre . 'Order>' . $curve->getOrder() . '</' . $pre . 'Order>' . "\r\n" .
					'</' . $pre . 'BasePointParams>' . "\r\n" .
					'</' . $pre . 'ExplicitParams>' . "\r\n";

			return $xml;
		}

		if (isset($result['specifiedCurve'])) {
			$xml = '<' . $pre . 'ECParameters>' . "\r\n" .
					'<' . $pre . 'FieldID>' . "\r\n";
			$temp = $result['specifiedCurve'];
			switch ($temp['fieldID']['fieldType']) {
				case 'prime-field':
					$xml .= '<' . $pre . 'Prime>' . "\r\n" .
							'<' . $pre . 'P>' . Strings::base64_encode($temp['fieldID']['parameters']->toBytes()) . '</' . $pre . 'P>' . "\r\n" .
							'</' . $pre . 'Prime>' . "\r\n" ;
					break;
				default:
					throw new UnsupportedCurveException('Field Type of ' . $temp['fieldID']['fieldType'] . ' is not supported');
			}
			$xml .= '</' . $pre . 'FieldID>' . "\r\n" .
					'<' . $pre . 'Curve>' . "\r\n" .
					'<' . $pre . 'A>' . Strings::base64_encode($temp['curve']['a']) . '</' . $pre . 'A>' . "\r\n" .
					'<' . $pre . 'B>' . Strings::base64_encode($temp['curve']['b']) . '</' . $pre . 'B>' . "\r\n" .
					'</' . $pre . 'Curve>' . "\r\n" .
					'<' . $pre . 'Base>' . Strings::base64_encode($temp['base']) . '</' . $pre . 'Base>' . "\r\n" .
					'<' . $pre . 'Order>' . Strings::base64_encode($temp['order']) . '</' . $pre . 'Order>' . "\r\n" .
					'</' . $pre . 'ECParameters>';
			return $xml;
		}
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Signature {

use phpseclib3\File\ASN1 as Encoder;
use phpseclib3\File\ASN1\Maps\EcdsaSigValue;
use phpseclib3\Math\BigInteger;

abstract class ASN1
{

	public static function load($sig)
	{
		if (!is_string($sig)) {
			return false;
		}

		$decoded = Encoder::decodeBER($sig);
		if (empty($decoded)) {
			return false;
		}
		$components = Encoder::asn1map($decoded[0], EcdsaSigValue::MAP);

		return $components;
	}

	public static function save(BigInteger $r, BigInteger $s)
	{
		return Encoder::encodeDER(compact('r', 's'), EcdsaSigValue::MAP);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Signature {

use phpseclib3\Math\BigInteger;

abstract class IEEE
{

	public static function load($sig)
	{
		if (!is_string($sig)) {
			return false;
		}

		$len = strlen($sig);
		if ($len & 1) {
			return false;
		}

		$r = new BigInteger(substr($sig, 0, $len >> 1), 256);
		$s = new BigInteger(substr($sig, $len >> 1), 256);

		return compact('r', 's');
	}

	public static function save(BigInteger $r, BigInteger $s, $curve, $length)
	{
		$r = $r->toBytes();
		$s = $s->toBytes();
		$length = (int) ceil($length / 8);
		return str_pad($r, $length, "\0", STR_PAD_LEFT) . str_pad($s, $length, "\0", STR_PAD_LEFT);
	}
}
}

namespace phpseclib3\Crypt\EC\Formats\Signature {

use phpseclib3\Crypt\Common\Formats\Signature\Raw as Progenitor;

abstract class Raw extends Progenitor
{
}
}

namespace phpseclib3\Crypt\EC\Formats\Signature {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;

abstract class SSH2
{

	public static function load($sig)
	{
		if (!is_string($sig)) {
			return false;
		}

		$result = Strings::unpackSSH2('ss', $sig);
		if ($result === false) {
			return false;
		}
		list($type, $blob) = $result;
		switch ($type) {

			case 'ecdsa-sha2-nistp256':
			case 'ecdsa-sha2-nistp384':
			case 'ecdsa-sha2-nistp521':
				break;
			default:
				return false;
		}

		$result = Strings::unpackSSH2('ii', $blob);
		if ($result === false) {
			return false;
		}

		return [
			'r' => $result[0],
			's' => $result[1]
		];
	}

	public static function save(BigInteger $r, BigInteger $s, $curve)
	{
		switch ($curve) {
			case 'secp256r1':
				$curve = 'nistp256';
				break;
			case 'secp384r1':
				$curve = 'nistp384';
				break;
			case 'secp521r1':
				$curve = 'nistp521';
				break;
			default:
				return false;
		}

		$blob = Strings::packSSH2('ii', $r, $s);

		return Strings::packSSH2('ss', 'ecdsa-sha2-' . $curve, $blob);
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\JWK as Progenitor;
use phpseclib3\Math\BigInteger;

abstract class JWK extends Progenitor
{

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		if ($key->kty != 'RSA') {
			throw new \RuntimeException('Only RSA JWK keys are supported');
		}

		$count = $publicCount = 0;
		$vars = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'];
		foreach ($vars as $var) {
			if (!isset($key->$var) || !is_string($key->$var)) {
				continue;
			}
			$count++;
			$value = new BigInteger(Strings::base64url_decode($key->$var), 256);
			switch ($var) {
				case 'n':
					$publicCount++;
					$components['modulus'] = $value;
					break;
				case 'e':
					$publicCount++;
					$components['publicExponent'] = $value;
					break;
				case 'd':
					$components['privateExponent'] = $value;
					break;
				case 'p':
					$components['primes'][1] = $value;
					break;
				case 'q':
					$components['primes'][2] = $value;
					break;
				case 'dp':
					$components['exponents'][1] = $value;
					break;
				case 'dq':
					$components['exponents'][2] = $value;
					break;
				case 'qi':
					$components['coefficients'][2] = $value;
			}
		}

		if ($count == count($vars)) {
			return $components + ['isPublicKey' => false];
		}

		if ($count == 2 && $publicCount == 2) {
			return $components + ['isPublicKey' => true];
		}

		throw new \UnexpectedValueException('Key does not have an appropriate number of RSA parameters');
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		if (count($primes) != 2) {
			throw new \InvalidArgumentException('JWK does not support multi-prime RSA keys');
		}

		$key = [
			'kty' => 'RSA',
			'n' => Strings::base64url_encode($n->toBytes()),
			'e' => Strings::base64url_encode($e->toBytes()),
			'd' => Strings::base64url_encode($d->toBytes()),
			'p' => Strings::base64url_encode($primes[1]->toBytes()),
			'q' => Strings::base64url_encode($primes[2]->toBytes()),
			'dp' => Strings::base64url_encode($exponents[1]->toBytes()),
			'dq' => Strings::base64url_encode($exponents[2]->toBytes()),
			'qi' => Strings::base64url_encode($coefficients[2]->toBytes())
		];

		return self::wrapKey($key, $options);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = [])
	{
		$key = [
			'kty' => 'RSA',
			'n' => Strings::base64url_encode($n->toBytes()),
			'e' => Strings::base64url_encode($e->toBytes())
		];

		return self::wrapKey($key, $options);
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

abstract class MSBLOB
{

	const PRIVATEKEYBLOB = 0x7;

	const PUBLICKEYBLOB = 0x6;

	const PUBLICKEYBLOBEX = 0xA;

	const CALG_RSA_KEYX = 0x0000A400;

	const CALG_RSA_SIGN = 0x00002400;

	const RSA1 = 0x31415352;

	const RSA2 = 0x32415352;

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		$key = Strings::base64_decode($key);

		if (!is_string($key)) {
			throw new \UnexpectedValueException('Base64 decoding produced an error');
		}
		if (strlen($key) < 20) {
			throw new \UnexpectedValueException('Key appears to be malformed');
		}

		extract(unpack('atype/aversion/vreserved/Valgo', Strings::shift($key, 8)));

		switch (ord($type)) {
			case self::PUBLICKEYBLOB:
			case self::PUBLICKEYBLOBEX:
				$publickey = true;
				break;
			case self::PRIVATEKEYBLOB:
				$publickey = false;
				break;
			default:
				throw new \UnexpectedValueException('Key appears to be malformed');
		}

		$components = ['isPublicKey' => $publickey];

		switch ($algo) {
			case self::CALG_RSA_KEYX:
			case self::CALG_RSA_SIGN:
				break;
			default:
				throw new \UnexpectedValueException('Key appears to be malformed');
		}

		extract(unpack('Vmagic/Vbitlen/a4pubexp', Strings::shift($key, 12)));

		switch ($magic) {
			case self::RSA2:
				$components['isPublicKey'] = false;

			case self::RSA1:
				break;
			default:
				throw new \UnexpectedValueException('Key appears to be malformed');
		}

		$baseLength = $bitlen / 16;
		if (strlen($key) != 2 * $baseLength && strlen($key) != 9 * $baseLength) {
			throw new \UnexpectedValueException('Key appears to be malformed');
		}

		$components[$components['isPublicKey'] ? 'publicExponent' : 'privateExponent'] = new BigInteger(strrev($pubexp), 256);

		$components['modulus'] = new BigInteger(strrev(Strings::shift($key, $bitlen / 8)), 256);

		if ($publickey) {
			return $components;
		}

		$components['isPublicKey'] = false;

		$components['primes'] = [1 => new BigInteger(strrev(Strings::shift($key, $bitlen / 16)), 256)];

		$components['primes'][] = new BigInteger(strrev(Strings::shift($key, $bitlen / 16)), 256);

		$components['exponents'] = [1 => new BigInteger(strrev(Strings::shift($key, $bitlen / 16)), 256)];

		$components['exponents'][] = new BigInteger(strrev(Strings::shift($key, $bitlen / 16)), 256);

		$components['coefficients'] = [2 => new BigInteger(strrev(Strings::shift($key, $bitlen / 16)), 256)];
		if (isset($components['privateExponent'])) {
			$components['publicExponent'] = $components['privateExponent'];
		}

		$components['privateExponent'] = new BigInteger(strrev(Strings::shift($key, $bitlen / 8)), 256);

		return $components;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '')
	{
		if (count($primes) != 2) {
			throw new \InvalidArgumentException('MSBLOB does not support multi-prime RSA keys');
		}

		if (!empty($password) && is_string($password)) {
			throw new UnsupportedFormatException('MSBLOB private keys do not support encryption');
		}

		$n = strrev($n->toBytes());
		$e = str_pad(strrev($e->toBytes()), 4, "\0");
		$key = pack('aavV', chr(self::PRIVATEKEYBLOB), chr(2), 0, self::CALG_RSA_KEYX);
		$key .= pack('VVa*', self::RSA2, 8 * strlen($n), $e);
		$key .= $n;
		$key .= strrev($primes[1]->toBytes());
		$key .= strrev($primes[2]->toBytes());
		$key .= strrev($exponents[1]->toBytes());
		$key .= strrev($exponents[2]->toBytes());
		$key .= strrev($coefficients[2]->toBytes());
		$key .= strrev($d->toBytes());

		return Strings::base64_encode($key);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e)
	{
		$n = strrev($n->toBytes());
		$e = str_pad(strrev($e->toBytes()), 4, "\0");
		$key = pack('aavV', chr(self::PUBLICKEYBLOB), chr(2), 0, self::CALG_RSA_KEYX);
		$key .= pack('VVa*', self::RSA1, 8 * strlen($n), $e);
		$key .= $n;

		return Strings::base64_encode($key);
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\OpenSSH as Progenitor;
use phpseclib3\Math\BigInteger;

abstract class OpenSSH extends Progenitor
{

	protected static $types = ['ssh-rsa'];

	public static function load($key, $password = '')
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		$parsed = parent::load($key, $password);

		if (isset($parsed['paddedKey'])) {
			list($type) = Strings::unpackSSH2('s', $parsed['paddedKey']);
			if ($type != $parsed['type']) {
				throw new \RuntimeException("The public and private keys are not of the same type ($type vs $parsed[type])");
			}

			$primes = $coefficients = [];

			list(
				$modulus,
				$publicExponent,
				$privateExponent,
				$coefficients[2],
				$primes[1],
				$primes[2],
				$comment,
			) = Strings::unpackSSH2('i6s', $parsed['paddedKey']);

			$temp = $primes[1]->subtract($one);
			$exponents = [1 => $publicExponent->modInverse($temp)];
			$temp = $primes[2]->subtract($one);
			$exponents[] = $publicExponent->modInverse($temp);

			$isPublicKey = false;

			return compact('publicExponent', 'modulus', 'privateExponent', 'primes', 'coefficients', 'exponents', 'comment', 'isPublicKey');
		}

		list($publicExponent, $modulus) = Strings::unpackSSH2('ii', $parsed['publicKey']);

		return [
			'isPublicKey' => true,
			'modulus' => $modulus,
			'publicExponent' => $publicExponent,
			'comment' => $parsed['comment']
		];
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = [])
	{
		$RSAPublicKey = Strings::packSSH2('sii', 'ssh-rsa', $e, $n);

		if (isset($options['binary']) ? $options['binary'] : self::$binary) {
			return $RSAPublicKey;
		}

		$comment = isset($options['comment']) ? $options['comment'] : self::$comment;
		$RSAPublicKey = 'ssh-rsa ' . base64_encode($RSAPublicKey) . ' ' . $comment;

		return $RSAPublicKey;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		$publicKey = self::savePublicKey($n, $e, ['binary' => true]);
		$privateKey = Strings::packSSH2('si6', 'ssh-rsa', $n, $e, $d, $coefficients[2], $primes[1], $primes[2]);

		return self::wrapPrivateKey($publicKey, $privateKey, $password, $options);
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS1 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PKCS1 extends Progenitor
{

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (strpos($key, 'PUBLIC') !== false) {
			$components = ['isPublicKey' => true];
		} elseif (strpos($key, 'PRIVATE') !== false) {
			$components = ['isPublicKey' => false];
		} else {
			$components = [];
		}

		$key = parent::load($key, $password);

		$decoded = ASN1::decodeBER($key);
		if (!$decoded) {
			throw new \RuntimeException('Unable to decode BER');
		}

		$key = ASN1::asn1map($decoded[0], Maps\RSAPrivateKey::MAP);
		if (is_array($key)) {
			$components += [
				'modulus' => $key['modulus'],
				'publicExponent' => $key['publicExponent'],
				'privateExponent' => $key['privateExponent'],
				'primes' => [1 => $key['prime1'], $key['prime2']],
				'exponents' => [1 => $key['exponent1'], $key['exponent2']],
				'coefficients' => [2 => $key['coefficient']]
			];
			if ($key['version'] == 'multi') {
				foreach ($key['otherPrimeInfos'] as $primeInfo) {
					$components['primes'][] = $primeInfo['prime'];
					$components['exponents'][] = $primeInfo['exponent'];
					$components['coefficients'][] = $primeInfo['coefficient'];
				}
			}
			if (!isset($components['isPublicKey'])) {
				$components['isPublicKey'] = false;
			}
			return $components;
		}

		$key = ASN1::asn1map($decoded[0], Maps\RSAPublicKey::MAP);

		if (!is_array($key)) {
			throw new \RuntimeException('Unable to perform ASN1 mapping');
		}

		if (!isset($components['isPublicKey'])) {
			$components['isPublicKey'] = true;
		}

		return $components + $key;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		$num_primes = count($primes);
		$key = [
			'version' => $num_primes == 2 ? 'two-prime' : 'multi',
			'modulus' => $n,
			'publicExponent' => $e,
			'privateExponent' => $d,
			'prime1' => $primes[1],
			'prime2' => $primes[2],
			'exponent1' => $exponents[1],
			'exponent2' => $exponents[2],
			'coefficient' => $coefficients[2]
		];
		for ($i = 3; $i <= $num_primes; $i++) {
			$key['otherPrimeInfos'][] = [
				'prime' => $primes[$i],
				'exponent' => $exponents[$i],
				'coefficient' => $coefficients[$i]
			];
		}

		$key = ASN1::encodeDER($key, Maps\RSAPrivateKey::MAP);

		return self::wrapPrivateKey($key, 'RSA', $password, $options);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e)
	{
		$key = [
			'modulus' => $n,
			'publicExponent' => $e
		];

		$key = ASN1::encodeDER($key, Maps\RSAPublicKey::MAP);

		return self::wrapPublicKey($key, 'RSA');
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\Math\BigInteger;

abstract class PKCS8 extends Progenitor
{

	const OID_NAME = 'rsaEncryption';

	const OID_VALUE = '1.2.840.113549.1.1.1';

	protected static $childOIDsLoaded = false;

	public static function load($key, $password = '')
	{
		$key = parent::load($key, $password);

		if (isset($key['privateKey'])) {
			$components['isPublicKey'] = false;
			$type = 'private';
		} else {
			$components['isPublicKey'] = true;
			$type = 'public';
		}

		$result = $components + PKCS1::load($key[$type . 'Key']);

		if (isset($key['meta'])) {
			$result['meta'] = $key['meta'];
		}

		return $result;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		$key = PKCS1::savePrivateKey($n, $e, $d, $primes, $exponents, $coefficients);
		$key = ASN1::extractBER($key);
		return self::wrapPrivateKey($key, [], null, $password, null, '', $options);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = [])
	{
		$key = PKCS1::savePublicKey($n, $e);
		$key = ASN1::extractBER($key);
		return self::wrapPublicKey($key, null, null, $options);
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PKCS8 as Progenitor;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

abstract class PSS extends Progenitor
{

	const OID_NAME = 'id-RSASSA-PSS';

	const OID_VALUE = '1.2.840.113549.1.1.10';

	private static $oidsLoaded = false;

	protected static $childOIDsLoaded = false;

	private static function initialize_static_variables()
	{
		if (!self::$oidsLoaded) {
			ASN1::loadOIDs([
				'md2' => '1.2.840.113549.2.2',
				'md4' => '1.2.840.113549.2.4',
				'md5' => '1.2.840.113549.2.5',
				'id-sha1' => '1.3.14.3.2.26',
				'id-sha256' => '2.16.840.1.101.3.4.2.1',
				'id-sha384' => '2.16.840.1.101.3.4.2.2',
				'id-sha512' => '2.16.840.1.101.3.4.2.3',
				'id-sha224' => '2.16.840.1.101.3.4.2.4',
				'id-sha512/224' => '2.16.840.1.101.3.4.2.5',
				'id-sha512/256' => '2.16.840.1.101.3.4.2.6',

				'id-mgf1' => '1.2.840.113549.1.1.8'
			]);
			self::$oidsLoaded = true;
		}
	}

	public static function load($key, $password = '')
	{
		self::initialize_static_variables();

		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		$components = ['isPublicKey' => strpos($key, 'PUBLIC') !== false];

		$key = parent::load($key, $password);

		$type = isset($key['privateKey']) ? 'private' : 'public';

		$result = $components + PKCS1::load($key[$type . 'Key']);

		if (isset($key[$type . 'KeyAlgorithm']['parameters'])) {
			$decoded = ASN1::decodeBER($key[$type . 'KeyAlgorithm']['parameters']);
			if ($decoded === false) {
				throw new \UnexpectedValueException('Unable to decode parameters');
			}
			$params = ASN1::asn1map($decoded[0], Maps\RSASSA_PSS_params::MAP);
		} else {
			$params = [];
		}

		if (isset($params['maskGenAlgorithm']['parameters'])) {
			$decoded = ASN1::decodeBER($params['maskGenAlgorithm']['parameters']);
			if ($decoded === false) {
				throw new \UnexpectedValueException('Unable to decode parameters');
			}
			$params['maskGenAlgorithm']['parameters'] = ASN1::asn1map($decoded[0], Maps\HashAlgorithm::MAP);
		} else {
			$params['maskGenAlgorithm'] = [
				'algorithm' => 'id-mgf1',
				'parameters' => ['algorithm' => 'id-sha1']
			];
		}

		if (!isset($params['hashAlgorithm']['algorithm'])) {
			$params['hashAlgorithm']['algorithm'] = 'id-sha1';
		}

		$result['hash'] = str_replace('id-', '', $params['hashAlgorithm']['algorithm']);
		$result['MGFHash'] = str_replace('id-', '', $params['maskGenAlgorithm']['parameters']['algorithm']);
		if (isset($params['saltLength'])) {
			$result['saltLength'] = (int) $params['saltLength']->toString();
		}

		if (isset($key['meta'])) {
			$result['meta'] = $key['meta'];
		}

		return $result;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		self::initialize_static_variables();

		$key = PKCS1::savePrivateKey($n, $e, $d, $primes, $exponents, $coefficients);
		$key = ASN1::extractBER($key);
		$params = self::savePSSParams($options);
		return self::wrapPrivateKey($key, [], $params, $password, null, '', $options);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e, array $options = [])
	{
		self::initialize_static_variables();

		$key = PKCS1::savePublicKey($n, $e);
		$key = ASN1::extractBER($key);
		$params = self::savePSSParams($options);
		return self::wrapPublicKey($key, $params);
	}

	public static function savePSSParams(array $options)
	{

		$params = [
			'trailerField' => new BigInteger(1)
		];
		if (isset($options['hash'])) {
			$params['hashAlgorithm']['algorithm'] = 'id-' . $options['hash'];
		}
		if (isset($options['MGFHash'])) {
			$temp = ['algorithm' => 'id-' . $options['MGFHash']];
			$temp = ASN1::encodeDER($temp, Maps\HashAlgorithm::MAP);
			$params['maskGenAlgorithm'] = [
				'algorithm' => 'id-mgf1',
				'parameters' => new ASN1\Element($temp)
			];
		}
		if (isset($options['saltLength'])) {
			$params['saltLength'] = new BigInteger($options['saltLength']);
		}

		return new ASN1\Element(ASN1::encodeDER($params, Maps\RSASSA_PSS_params::MAP));
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\Formats\Keys\PuTTY as Progenitor;
use phpseclib3\Math\BigInteger;

abstract class PuTTY extends Progenitor
{

	const PUBLIC_HANDLER = 'phpseclib3\Crypt\RSA\Formats\Keys\OpenSSH';

	protected static $types = ['ssh-rsa'];

	public static function load($key, $password = '')
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		$components = parent::load($key, $password);
		if (!isset($components['private'])) {
			return $components;
		}
		extract($components);
		unset($components['public'], $components['private']);

		$isPublicKey = false;

		$result = Strings::unpackSSH2('ii', $public);
		if ($result === false) {
			throw new \UnexpectedValueException('Key appears to be malformed');
		}
		list($publicExponent, $modulus) = $result;

		$result = Strings::unpackSSH2('iiii', $private);
		if ($result === false) {
			throw new \UnexpectedValueException('Key appears to be malformed');
		}
		$primes = $coefficients = [];
		list($privateExponent, $primes[1], $primes[2], $coefficients[2]) = $result;

		$temp = $primes[1]->subtract($one);
		$exponents = [1 => $publicExponent->modInverse($temp)];
		$temp = $primes[2]->subtract($one);
		$exponents[] = $publicExponent->modInverse($temp);

		return compact('publicExponent', 'modulus', 'privateExponent', 'primes', 'coefficients', 'exponents', 'comment', 'isPublicKey');
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		if (count($primes) != 2) {
			throw new \InvalidArgumentException('PuTTY does not support multi-prime RSA keys');
		}

		$public =	Strings::packSSH2('ii', $e, $n);
		$private = Strings::packSSH2('iiii', $d, $primes[1], $primes[2], $coefficients[2]);

		return self::wrapPrivateKey($public, $private, 'ssh-rsa', $password, $options);
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e)
	{
		return self::wrapPublicKey(Strings::packSSH2('ii', $e, $n), 'ssh-rsa');
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Math\BigInteger;

abstract class Raw
{

	public static function load($key, $password = '')
	{
		if (!is_array($key)) {
			throw new \UnexpectedValueException('Key should be a array - not a ' . gettype($key));
		}

		$key = array_change_key_case($key, CASE_LOWER);

		$components = ['isPublicKey' => false];

		foreach (['e', 'exponent', 'publicexponent', 0, 'privateexponent', 'd'] as $index) {
			if (isset($key[$index])) {
				$components['publicExponent'] = $key[$index];
				break;
			}
		}

		foreach (['n', 'modulo', 'modulus', 1] as $index) {
			if (isset($key[$index])) {
				$components['modulus'] = $key[$index];
				break;
			}
		}

		if (!isset($components['publicExponent']) || !isset($components['modulus'])) {
			throw new \UnexpectedValueException('Modulus / exponent not present');
		}

		if (isset($key['primes'])) {
			$components['primes'] = $key['primes'];
		} elseif (isset($key['p']) && isset($key['q'])) {
			$indices = [
				['p', 'q'],
				['prime1', 'prime2']
			];
			foreach ($indices as $index) {
				list($i0, $i1) = $index;
				if (isset($key[$i0]) && isset($key[$i1])) {
					$components['primes'] = [1 => $key[$i0], $key[$i1]];
				}
			}
		}

		if (isset($key['exponents'])) {
			$components['exponents'] = $key['exponents'];
		} else {
			$indices = [
				['dp', 'dq'],
				['exponent1', 'exponent2']
			];
			foreach ($indices as $index) {
				list($i0, $i1) = $index;
				if (isset($key[$i0]) && isset($key[$i1])) {
					$components['exponents'] = [1 => $key[$i0], $key[$i1]];
				}
			}
		}

		if (isset($key['coefficients'])) {
			$components['coefficients'] = $key['coefficients'];
		} else {
			foreach (['inverseq', 'q\'', 'coefficient'] as $index) {
				if (isset($key[$index])) {
					$components['coefficients'] = [2 => $key[$index]];
				}
			}
		}

		if (!isset($components['primes'])) {
			$components['isPublicKey'] = true;
			return $components;
		}

		if (!isset($components['exponents'])) {
			$one = new BigInteger(1);
			$temp = $components['primes'][1]->subtract($one);
			$exponents = [1 => $components['publicExponent']->modInverse($temp)];
			$temp = $components['primes'][2]->subtract($one);
			$exponents[] = $components['publicExponent']->modInverse($temp);
			$components['exponents'] = $exponents;
		}

		if (!isset($components['coefficients'])) {
			$components['coefficients'] = [2 => $components['primes'][2]->modInverse($components['primes'][1])];
		}

		foreach (['privateexponent', 'd'] as $index) {
			if (isset($key[$index])) {
				$components['privateExponent'] = $key[$index];
				break;
			}
		}

		return $components;
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '', array $options = [])
	{
		if (!empty($password) && is_string($password)) {
			throw new UnsupportedFormatException('Raw private keys do not support encryption');
		}

		return [
			'e' => clone $e,
			'n' => clone $n,
			'd' => clone $d,
			'primes' => array_map(function ($var) {
				return clone $var;
			}, $primes),
			'exponents' => array_map(function ($var) {
				return clone $var;
			}, $exponents),
			'coefficients' => array_map(function ($var) {
				return clone $var;
			}, $coefficients)
		];
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e)
	{
		return ['e' => clone $e, 'n' => clone $n];
	}
}
}

namespace phpseclib3\Crypt\RSA\Formats\Keys {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

abstract class XML
{

	public static function load($key, $password = '')
	{
		if (!Strings::is_stringable($key)) {
			throw new \UnexpectedValueException('Key should be a string - not a ' . gettype($key));
		}

		if (!class_exists('DOMDocument')) {
			throw new BadConfigurationException('The dom extension is not setup correctly on this system');
		}

		$components = [
			'isPublicKey' => false,
			'primes' => [],
			'exponents' => [],
			'coefficients' => []
		];

		$use_errors = libxml_use_internal_errors(true);

		$dom = new \DOMDocument();
		if (substr($key, 0, 5) != '<?xml') {
			$key = '<xml>' . $key . '</xml>';
		}
		if (!$dom->loadXML($key)) {
			libxml_use_internal_errors($use_errors);
			throw new \UnexpectedValueException('Key does not appear to contain XML');
		}
		$xpath = new \DOMXPath($dom);
		$keys = ['modulus', 'exponent', 'p', 'q', 'dp', 'dq', 'inverseq', 'd'];
		foreach ($keys as $key) {

			$temp = $xpath->query("//*[translate(local-name(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$key']");
			if (!$temp->length) {
				continue;
			}
			$value = new BigInteger(Strings::base64_decode($temp->item(0)->nodeValue), 256);
			switch ($key) {
				case 'modulus':
					$components['modulus'] = $value;
					break;
				case 'exponent':
					$components['publicExponent'] = $value;
					break;
				case 'p':
					$components['primes'][1] = $value;
					break;
				case 'q':
					$components['primes'][2] = $value;
					break;
				case 'dp':
					$components['exponents'][1] = $value;
					break;
				case 'dq':
					$components['exponents'][2] = $value;
					break;
				case 'inverseq':
					$components['coefficients'][2] = $value;
					break;
				case 'd':
					$components['privateExponent'] = $value;
			}
		}

		libxml_use_internal_errors($use_errors);

		foreach ($components as $key => $value) {
			if (is_array($value) && !count($value)) {
				unset($components[$key]);
			}
		}

		if (isset($components['modulus']) && isset($components['publicExponent'])) {
			if (count($components) == 3) {
				$components['isPublicKey'] = true;
			}
			return $components;
		}

		throw new \UnexpectedValueException('Modulus / exponent not present');
	}

	public static function savePrivateKey(BigInteger $n, BigInteger $e, BigInteger $d, array $primes, array $exponents, array $coefficients, $password = '')
	{
		if (count($primes) != 2) {
			throw new \InvalidArgumentException('XML does not support multi-prime RSA keys');
		}

		if (!empty($password) && is_string($password)) {
			throw new UnsupportedFormatException('XML private keys do not support encryption');
		}

		return "<RSAKeyPair>\r\n" .
				'  <Modulus>' . Strings::base64_encode($n->toBytes()) . "</Modulus>\r\n" .
				'  <Exponent>' . Strings::base64_encode($e->toBytes()) . "</Exponent>\r\n" .
				'  <P>' . Strings::base64_encode($primes[1]->toBytes()) . "</P>\r\n" .
				'  <Q>' . Strings::base64_encode($primes[2]->toBytes()) . "</Q>\r\n" .
				'  <DP>' . Strings::base64_encode($exponents[1]->toBytes()) . "</DP>\r\n" .
				'  <DQ>' . Strings::base64_encode($exponents[2]->toBytes()) . "</DQ>\r\n" .
				'  <InverseQ>' . Strings::base64_encode($coefficients[2]->toBytes()) . "</InverseQ>\r\n" .
				'  <D>' . Strings::base64_encode($d->toBytes()) . "</D>\r\n" .
				'</RSAKeyPair>';
	}

	public static function savePublicKey(BigInteger $n, BigInteger $e)
	{
		return "<RSAKeyValue>\r\n" .
				'  <Modulus>' . Strings::base64_encode($n->toBytes()) . "</Modulus>\r\n" .
				'  <Exponent>' . Strings::base64_encode($e->toBytes()) . "</Exponent>\r\n" .
				'</RSAKeyValue>';
	}
}
}

namespace ParagonIE\ConstantTime {

interface EncoderInterface
{

	public static function encode(string $binString): string;

	public static function decode(string $encodedString, bool $strictPadding = false): string;
}
}

namespace ParagonIE\ConstantTime {

use InvalidArgumentException;
use RangeException;
use TypeError;

abstract class Base32 implements EncoderInterface
{

	public static function decode(
		#[\SensitiveParameter]
		string $encodedString,
		bool $strictPadding = false
	): string {
		return static::doDecode($encodedString, false, $strictPadding);
	}

	public static function decodeUpper(
		#[\SensitiveParameter]
		string $src,
		bool $strictPadding = false
	): string {
		return static::doDecode($src, true, $strictPadding);
	}

	public static function encode(
		#[\SensitiveParameter]
		string $binString
	): string {
		return static::doEncode($binString, false, true);
	}

	public static function encodeUnpadded(
		#[\SensitiveParameter]
		string $src
	): string {
		return static::doEncode($src, false, false);
	}

	public static function encodeUpper(
		#[\SensitiveParameter]
		string $src
	): string {
		return static::doEncode($src, true, true);
	}

	public static function encodeUpperUnpadded(
		#[\SensitiveParameter]
		string $src
	): string {
		return static::doEncode($src, true, false);
	}

	protected static function decode5Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x60 - $src) & ($src - 0x7b)) >> 8) & ($src - 96);

		$ret += (((0x31 - $src) & ($src - 0x38)) >> 8) & ($src - 23);

		return $ret;
	}

	protected static function decode5BitsUpper(int $src): int
	{
		$ret = -1;

		$ret += (((0x40 - $src) & ($src - 0x5b)) >> 8) & ($src - 64);

		$ret += (((0x31 - $src) & ($src - 0x38)) >> 8) & ($src - 23);

		return $ret;
	}

	protected static function encode5Bits(int $src): string
	{
		$diff = 0x61;

		$diff -= ((25 - $src) >> 8) & 73;

		return \pack('C', $src + $diff);
	}

	protected static function encode5BitsUpper(int $src): string
	{
		$diff = 0x41;

		$diff -= ((25 - $src) >> 8) & 41;

		return \pack('C', $src + $diff);
	}

	public static function decodeNoPadding(
		#[\SensitiveParameter]
		string $encodedString,
		bool $upper = false
	): string {
		$srcLen = Binary::safeStrlen($encodedString);
		if ($srcLen === 0) {
			return '';
		}
		if (($srcLen & 7) === 0) {
			for ($j = 0; $j < 7 && $j < $srcLen; ++$j) {
				if ($encodedString[$srcLen - $j - 1] === '=') {
					throw new InvalidArgumentException(
						"decodeNoPadding() doesn't tolerate padding"
					);
				}
			}
		}
		return static::doDecode(
			$encodedString,
			$upper,
			true
		);
	}

	protected static function doDecode(
		#[\SensitiveParameter]
		string $src,
		bool $upper = false,
		bool $strictPadding = false
	): string {

		$method = $upper
			? 'decode5BitsUpper'
			: 'decode5Bits';

		$srcLen = Binary::safeStrlen($src);
		if ($srcLen === 0) {
			return '';
		}
		if ($strictPadding) {
			if (($srcLen & 7) === 0) {
				for ($j = 0; $j < 7; ++$j) {
					if ($src[$srcLen - 1] === '=') {
						$srcLen--;
					} else {
						break;
					}
				}
			}
			if (($srcLen & 7) === 1) {
				throw new RangeException(
					'Incorrect padding'
				);
			}
		} else {
			$src = \rtrim($src, '=');
			$srcLen = Binary::safeStrlen($src);
		}

		$err = 0;
		$dest = '';

		for ($i = 0; $i + 8 <= $srcLen; $i += 8) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, 8));

			$c0 = static::$method($chunk[1]);

			$c1 = static::$method($chunk[2]);

			$c2 = static::$method($chunk[3]);

			$c3 = static::$method($chunk[4]);

			$c4 = static::$method($chunk[5]);

			$c5 = static::$method($chunk[6]);

			$c6 = static::$method($chunk[7]);

			$c7 = static::$method($chunk[8]);

			$dest .= \pack(
				'CCCCC',
				(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
				(($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff,
				(($c3 << 4) | ($c4 >> 1)			 ) & 0xff,
				(($c4 << 7) | ($c5 << 2) | ($c6 >> 3)) & 0xff,
				(($c6 << 5) | ($c7	 )			 ) & 0xff
			);
			$err |= ($c0 | $c1 | $c2 | $c3 | $c4 | $c5 | $c6 | $c7) >> 8;
		}

		if ($i < $srcLen) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, $srcLen - $i));

			$c0 = static::$method($chunk[1]);

			if ($i + 6 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$c2 = static::$method($chunk[3]);

				$c3 = static::$method($chunk[4]);

				$c4 = static::$method($chunk[5]);

				$c5 = static::$method($chunk[6]);

				$c6 = static::$method($chunk[7]);

				$dest .= \pack(
					'CCCC',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
					(($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff,
					(($c3 << 4) | ($c4 >> 1)			 ) & 0xff,
					(($c4 << 7) | ($c5 << 2) | ($c6 >> 3)) & 0xff
				);
				$err |= ($c0 | $c1 | $c2 | $c3 | $c4 | $c5 | $c6) >> 8;
				if ($strictPadding) {
					$err |= ($c6 << 5) & 0xff;
				}
			} elseif ($i + 5 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$c2 = static::$method($chunk[3]);

				$c3 = static::$method($chunk[4]);

				$c4 = static::$method($chunk[5]);

				$c5 = static::$method($chunk[6]);

				$dest .= \pack(
					'CCCC',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
					(($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff,
					(($c3 << 4) | ($c4 >> 1)			 ) & 0xff,
					(($c4 << 7) | ($c5 << 2)			 ) & 0xff
				);
				$err |= ($c0 | $c1 | $c2 | $c3 | $c4 | $c5) >> 8;
			} elseif ($i + 4 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$c2 = static::$method($chunk[3]);

				$c3 = static::$method($chunk[4]);

				$c4 = static::$method($chunk[5]);

				$dest .= \pack(
					'CCC',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
					(($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff,
					(($c3 << 4) | ($c4 >> 1)			 ) & 0xff
				);
				$err |= ($c0 | $c1 | $c2 | $c3 | $c4) >> 8;
				if ($strictPadding) {
					$err |= ($c4 << 7) & 0xff;
				}
			} elseif ($i + 3 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$c2 = static::$method($chunk[3]);

				$c3 = static::$method($chunk[4]);

				$dest .= \pack(
					'CC',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
					(($c1 << 6) | ($c2 << 1) | ($c3 >> 4)) & 0xff
				);
				$err |= ($c0 | $c1 | $c2 | $c3) >> 8;
				if ($strictPadding) {
					$err |= ($c3 << 4) & 0xff;
				}
			} elseif ($i + 2 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$c2 = static::$method($chunk[3]);

				$dest .= \pack(
					'CC',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff,
					(($c1 << 6) | ($c2 << 1)			 ) & 0xff
				);
				$err |= ($c0 | $c1 | $c2) >> 8;
				if ($strictPadding) {
					$err |= ($c2 << 6) & 0xff;
				}
			} elseif ($i + 1 < $srcLen) {

				$c1 = static::$method($chunk[2]);

				$dest .= \pack(
					'C',
					(($c0 << 3) | ($c1 >> 2)			 ) & 0xff
				);
				$err |= ($c0 | $c1) >> 8;
				if ($strictPadding) {
					$err |= ($c1 << 6) & 0xff;
				}
			} else {
				$dest .= \pack(
					'C',
					(($c0 << 3)							) & 0xff
				);
				$err |= ($c0) >> 8;
			}
		}
		$check = ($err === 0);
		if (!$check) {
			throw new RangeException(
				'Base32::doDecode() only expects characters in the correct base32 alphabet'
			);
		}
		return $dest;
	}

	protected static function doEncode(
		#[\SensitiveParameter]
		string $src,
		bool $upper = false,
		$pad = true
	): string {

		$method = $upper
			? 'encode5BitsUpper'
			: 'encode5Bits';

		$dest = '';
		$srcLen = Binary::safeStrlen($src);

		for ($i = 0; $i + 5 <= $srcLen; $i += 5) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, 5));
			$b0 = $chunk[1];
			$b1 = $chunk[2];
			$b2 = $chunk[3];
			$b3 = $chunk[4];
			$b4 = $chunk[5];
			$dest .=
				static::$method(				($b0 >> 3)	& 31) .
				static::$method((($b0 << 2) | ($b1 >> 6)) & 31) .
				static::$method((($b1 >> 1)			 ) & 31) .
				static::$method((($b1 << 4) | ($b2 >> 4)) & 31) .
				static::$method((($b2 << 1) | ($b3 >> 7)) & 31) .
				static::$method((($b3 >> 2)			 ) & 31) .
				static::$method((($b3 << 3) | ($b4 >> 5)) & 31) .
				static::$method(	$b4					 & 31);
		}

		if ($i < $srcLen) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, $srcLen - $i));
			$b0 = $chunk[1];
			if ($i + 3 < $srcLen) {
				$b1 = $chunk[2];
				$b2 = $chunk[3];
				$b3 = $chunk[4];
				$dest .=
					static::$method(				($b0 >> 3)	& 31) .
					static::$method((($b0 << 2) | ($b1 >> 6)) & 31) .
					static::$method((($b1 >> 1)			 ) & 31) .
					static::$method((($b1 << 4) | ($b2 >> 4)) & 31) .
					static::$method((($b2 << 1) | ($b3 >> 7)) & 31) .
					static::$method((($b3 >> 2)			 ) & 31) .
					static::$method((($b3 << 3)			 ) & 31);
				if ($pad) {
					$dest .= '=';
				}
			} elseif ($i + 2 < $srcLen) {
				$b1 = $chunk[2];
				$b2 = $chunk[3];
				$dest .=
					static::$method(				($b0 >> 3)	& 31) .
					static::$method((($b0 << 2) | ($b1 >> 6)) & 31) .
					static::$method((($b1 >> 1)			 ) & 31) .
					static::$method((($b1 << 4) | ($b2 >> 4)) & 31) .
					static::$method((($b2 << 1)			 ) & 31);
				if ($pad) {
					$dest .= '===';
				}
			} elseif ($i + 1 < $srcLen) {
				$b1 = $chunk[2];
				$dest .=
					static::$method(				($b0 >> 3)	& 31) .
					static::$method((($b0 << 2) | ($b1 >> 6)) & 31) .
					static::$method((($b1 >> 1)			 ) & 31) .
					static::$method((($b1 << 4)			 ) & 31);
				if ($pad) {
					$dest .= '====';
				}
			} else {
				$dest .=
					static::$method(				($b0 >> 3)	& 31) .
					static::$method( ($b0 << 2)				& 31);
				if ($pad) {
					$dest .= '======';
				}
			}
		}
		return $dest;
	}
}
}

namespace ParagonIE\ConstantTime {

abstract class Base32Hex extends Base32
{

	protected static function decode5Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x2f - $src) & ($src - 0x3a)) >> 8) & ($src - 47);

		$ret += (((0x60 - $src) & ($src - 0x77)) >> 8) & ($src - 86);

		return $ret;
	}

	protected static function decode5BitsUpper(int $src): int
	{
		$ret = -1;

		$ret += (((0x2f - $src) & ($src - 0x3a)) >> 8) & ($src - 47);

		$ret += (((0x40 - $src) & ($src - 0x57)) >> 8) & ($src - 54);

		return $ret;
	}

	protected static function encode5Bits(int $src): string
	{
		$src += 0x30;

		$src += ((0x39 - $src) >> 8) & 39;

		return \pack('C', $src);
	}

	protected static function encode5BitsUpper(int $src): string
	{
		$src += 0x30;

		$src += ((0x39 - $src) >> 8) & 7;

		return \pack('C', $src);
	}
}
}

namespace ParagonIE\ConstantTime {

use InvalidArgumentException;
use RangeException;
use TypeError;

abstract class Base64 implements EncoderInterface
{

	public static function encode(
		#[\SensitiveParameter]
		string $binString
	): string {
		return static::doEncode($binString, true);
	}

	public static function encodeUnpadded(
		#[\SensitiveParameter]
		string $src
	): string {
		return static::doEncode($src, false);
	}

	protected static function doEncode(
		#[\SensitiveParameter]
		string $src,
		bool $pad = true
	): string {
		$dest = '';
		$srcLen = Binary::safeStrlen($src);

		for ($i = 0; $i + 3 <= $srcLen; $i += 3) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, 3));
			$b0 = $chunk[1];
			$b1 = $chunk[2];
			$b2 = $chunk[3];

			$dest .=
				static::encode6Bits(				$b0 >> 2		) .
				static::encode6Bits((($b0 << 4) | ($b1 >> 4)) & 63) .
				static::encode6Bits((($b1 << 2) | ($b2 >> 6)) & 63) .
				static::encode6Bits(	$b2					 & 63);
		}

		if ($i < $srcLen) {

			$chunk = \unpack('C*', Binary::safeSubstr($src, $i, $srcLen - $i));
			$b0 = $chunk[1];
			if ($i + 1 < $srcLen) {
				$b1 = $chunk[2];
				$dest .=
					static::encode6Bits($b0 >> 2) .
					static::encode6Bits((($b0 << 4) | ($b1 >> 4)) & 63) .
					static::encode6Bits(($b1 << 2) & 63);
				if ($pad) {
					$dest .= '=';
				}
			} else {
				$dest .=
					static::encode6Bits( $b0 >> 2) .
					static::encode6Bits(($b0 << 4) & 63);
				if ($pad) {
					$dest .= '==';
				}
			}
		}
		return $dest;
	}

	public static function decode(
		#[\SensitiveParameter]
		string $encodedString,
		bool $strictPadding = false
	): string {

		$srcLen = Binary::safeStrlen($encodedString);
		if ($srcLen === 0) {
			return '';
		}

		if ($strictPadding) {
			if (($srcLen & 3) === 0) {
				if ($encodedString[$srcLen - 1] === '=') {
					$srcLen--;
					if ($encodedString[$srcLen - 1] === '=') {
						$srcLen--;
					}
				}
			}
			if (($srcLen & 3) === 1) {
				throw new RangeException(
					'Incorrect padding'
				);
			}
			if ($encodedString[$srcLen - 1] === '=') {
				throw new RangeException(
					'Incorrect padding'
				);
			}
		} else {
			$encodedString = \rtrim($encodedString, '=');
			$srcLen = Binary::safeStrlen($encodedString);
		}

		$err = 0;
		$dest = '';

		for ($i = 0; $i + 4 <= $srcLen; $i += 4) {

			$chunk = \unpack('C*', Binary::safeSubstr($encodedString, $i, 4));
			$c0 = static::decode6Bits($chunk[1]);
			$c1 = static::decode6Bits($chunk[2]);
			$c2 = static::decode6Bits($chunk[3]);
			$c3 = static::decode6Bits($chunk[4]);

			$dest .= \pack(
				'CCC',
				((($c0 << 2) | ($c1 >> 4)) & 0xff),
				((($c1 << 4) | ($c2 >> 2)) & 0xff),
				((($c2 << 6) |	$c3		) & 0xff)
			);
			$err |= ($c0 | $c1 | $c2 | $c3) >> 8;
		}

		if ($i < $srcLen) {

			$chunk = \unpack('C*', Binary::safeSubstr($encodedString, $i, $srcLen - $i));
			$c0 = static::decode6Bits($chunk[1]);

			if ($i + 2 < $srcLen) {
				$c1 = static::decode6Bits($chunk[2]);
				$c2 = static::decode6Bits($chunk[3]);
				$dest .= \pack(
					'CC',
					((($c0 << 2) | ($c1 >> 4)) & 0xff),
					((($c1 << 4) | ($c2 >> 2)) & 0xff)
				);
				$err |= ($c0 | $c1 | $c2) >> 8;
				if ($strictPadding) {
					$err |= ($c2 << 6) & 0xff;
				}
			} elseif ($i + 1 < $srcLen) {
				$c1 = static::decode6Bits($chunk[2]);
				$dest .= \pack(
					'C',
					((($c0 << 2) | ($c1 >> 4)) & 0xff)
				);
				$err |= ($c0 | $c1) >> 8;
				if ($strictPadding) {
					$err |= ($c1 << 4) & 0xff;
				}
			} elseif ($strictPadding) {
				$err |= 1;
			}
		}
		$check = ($err === 0);
		if (!$check) {
			throw new RangeException(
				'Base64::decode() only expects characters in the correct base64 alphabet'
			);
		}
		return $dest;
	}

	public static function decodeNoPadding(
		#[\SensitiveParameter]
		string $encodedString
	): string {
		$srcLen = Binary::safeStrlen($encodedString);
		if ($srcLen === 0) {
			return '';
		}
		if (($srcLen & 3) === 0) {

			if ($encodedString[$srcLen - 1] === '=' || $encodedString[$srcLen - 2] === '=') {
				throw new InvalidArgumentException(
					"decodeNoPadding() doesn't tolerate padding"
				);
			}
		}
		return static::decode(
			$encodedString,
			true
		);
	}

	protected static function decode6Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x40 - $src) & ($src - 0x5b)) >> 8) & ($src - 64);

		$ret += (((0x60 - $src) & ($src - 0x7b)) >> 8) & ($src - 70);

		$ret += (((0x2f - $src) & ($src - 0x3a)) >> 8) & ($src + 5);

		$ret += (((0x2a - $src) & ($src - 0x2c)) >> 8) & 63;

		$ret += (((0x2e - $src) & ($src - 0x30)) >> 8) & 64;

		return $ret;
	}

	protected static function encode6Bits(int $src): string
	{
		$diff = 0x41;

		$diff += ((25 - $src) >> 8) & 6;

		$diff -= ((51 - $src) >> 8) & 75;

		$diff -= ((61 - $src) >> 8) & 15;

		$diff += ((62 - $src) >> 8) & 3;

		return \pack('C', $src + $diff);
	}
}
}

namespace ParagonIE\ConstantTime {

abstract class Base64DotSlash extends Base64
{

	protected static function decode6Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x2d - $src) & ($src - 0x30)) >> 8) & ($src - 45);

		$ret += (((0x40 - $src) & ($src - 0x5b)) >> 8) & ($src - 62);

		$ret += (((0x60 - $src) & ($src - 0x7b)) >> 8) & ($src - 68);

		$ret += (((0x2f - $src) & ($src - 0x3a)) >> 8) & ($src + 7);

		return $ret;
	}

	protected static function encode6Bits(int $src): string
	{
		$src += 0x2e;

		$src += ((0x2f - $src) >> 8) & 17;

		$src += ((0x5a - $src) >> 8) & 6;

		$src -= ((0x7a - $src) >> 8) & 75;

		return \pack('C', $src);
	}
}
}

namespace ParagonIE\ConstantTime {

abstract class Base64DotSlashOrdered extends Base64
{

	protected static function decode6Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x2d - $src) & ($src - 0x3a)) >> 8) & ($src - 45);

		$ret += (((0x40 - $src) & ($src - 0x5b)) >> 8) & ($src - 52);

		$ret += (((0x60 - $src) & ($src - 0x7b)) >> 8) & ($src - 58);

		return $ret;
	}

	protected static function encode6Bits(int $src): string
	{
		$src += 0x2e;

		$src += ((0x39 - $src) >> 8) & 7;

		$src += ((0x5a - $src) >> 8) & 6;

		return \pack('C', $src);
	}
}
}

namespace ParagonIE\ConstantTime {

abstract class Base64UrlSafe extends Base64
{

	protected static function decode6Bits(int $src): int
	{
		$ret = -1;

		$ret += (((0x40 - $src) & ($src - 0x5b)) >> 8) & ($src - 64);

		$ret += (((0x60 - $src) & ($src - 0x7b)) >> 8) & ($src - 70);

		$ret += (((0x2f - $src) & ($src - 0x3a)) >> 8) & ($src + 5);

		$ret += (((0x2c - $src) & ($src - 0x2e)) >> 8) & 63;

		$ret += (((0x5e - $src) & ($src - 0x60)) >> 8) & 64;

		return $ret;
	}

	protected static function encode6Bits(int $src): string
	{
		$diff = 0x41;

		$diff += ((25 - $src) >> 8) & 6;

		$diff -= ((51 - $src) >> 8) & 75;

		$diff -= ((61 - $src) >> 8) & 13;

		$diff += ((62 - $src) >> 8) & 49;

		return \pack('C', $src + $diff);
	}
}
}

namespace ParagonIE\ConstantTime {

use TypeError;

abstract class Binary
{

	public static function safeStrlen(
		#[\SensitiveParameter]
		string $str
	): int {
		if (\function_exists('mb_strlen')) {

			return (int) \mb_strlen($str, '8bit');
		} else {
			return \strlen($str);
		}
	}

	public static function safeSubstr(
		#[\SensitiveParameter]
		string $str,
		int $start = 0,
		?int $length = null
	): string {
		if ($length === 0) {
			return '';
		}
		if (\function_exists('mb_substr')) {
			return \mb_substr($str, $start, $length, '8bit');
		}

		if ($length !== null) {
			return \substr($str, $start, $length);
		} else {
			return \substr($str, $start);
		}
	}
}
}

namespace ParagonIE\ConstantTime {

use TypeError;

abstract class Encoding
{

	public static function base32Encode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::encode($str);
	}

	public static function base32EncodeUpper(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::encodeUpper($str);
	}

	public static function base32Decode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::decode($str);
	}

	public static function base32DecodeUpper(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::decodeUpper($str);
	}

	public static function base32HexEncode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32Hex::encode($str);
	}

	public static function base32HexEncodeUpper(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32Hex::encodeUpper($str);
	}

	public static function base32HexDecode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32Hex::decode($str);
	}

	public static function base32HexDecodeUpper(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32Hex::decodeUpper($str);
	}

	public static function base64Encode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64::encode($str);
	}

	public static function base64Decode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64::decode($str);
	}

	public static function base64EncodeDotSlash(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64DotSlash::encode($str);
	}

	public static function base64DecodeDotSlash(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64DotSlash::decode($str);
	}

	public static function base64EncodeDotSlashOrdered(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64DotSlashOrdered::encode($str);
	}

	public static function base64DecodeDotSlashOrdered(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64DotSlashOrdered::decode($str);
	}

	public static function hexEncode(
		#[\SensitiveParameter]
		string $bin_string
	): string {
		return Hex::encode($bin_string);
	}

	public static function hexDecode(
		#[\SensitiveParameter]
		string $hex_string
	): string {
		return Hex::decode($hex_string);
	}

	public static function hexEncodeUpper(
		#[\SensitiveParameter]
		string $bin_string
	): string {
		return Hex::encodeUpper($bin_string);
	}

	public static function hexDecodeUpper(
		#[\SensitiveParameter]
		string $bin_string
	): string {
		return Hex::decode($bin_string);
	}
}
}

namespace ParagonIE\ConstantTime {

use RangeException;
use TypeError;

abstract class Hex implements EncoderInterface
{

	public static function encode(
		#[\SensitiveParameter]
		string $binString
	): string {
		$hex = '';
		$len = Binary::safeStrlen($binString);
		for ($i = 0; $i < $len; ++$i) {

			$chunk = \unpack('C', $binString[$i]);
			$c = $chunk[1] & 0xf;
			$b = $chunk[1] >> 4;

			$hex .= \pack(
				'CC',
				(87 + $b + ((($b - 10) >> 8) & ~38)),
				(87 + $c + ((($c - 10) >> 8) & ~38))
			);
		}
		return $hex;
	}

	public static function encodeUpper(
		#[\SensitiveParameter]
		string $binString
	): string {
		$hex = '';
		$len = Binary::safeStrlen($binString);

		for ($i = 0; $i < $len; ++$i) {

			$chunk = \unpack('C', $binString[$i]);
			$c = $chunk[1] & 0xf;
			$b = $chunk[1] >> 4;

			$hex .= \pack(
				'CC',
				(55 + $b + ((($b - 10) >> 8) & ~6)),
				(55 + $c + ((($c - 10) >> 8) & ~6))
			);
		}
		return $hex;
	}

	public static function decode(
		#[\SensitiveParameter]
		string $encodedString,
		bool $strictPadding = false
	): string {
		$hex_pos = 0;
		$bin = '';
		$c_acc = 0;
		$hex_len = Binary::safeStrlen($encodedString);
		$state = 0;
		if (($hex_len & 1) !== 0) {
			if ($strictPadding) {
				throw new RangeException(
					'Expected an even number of hexadecimal characters'
				);
			} else {
				$encodedString = '0' . $encodedString;
				++$hex_len;
			}
		}

		$chunk = \unpack('C*', $encodedString);
		while ($hex_pos < $hex_len) {
			++$hex_pos;
			$c = $chunk[$hex_pos];
			$c_num = $c ^ 48;
			$c_num0 = ($c_num - 10) >> 8;
			$c_alpha = ($c & ~32) - 55;
			$c_alpha0 = (($c_alpha - 10) ^ ($c_alpha - 16)) >> 8;

			if (($c_num0 | $c_alpha0) === 0) {
				throw new RangeException(
					'Expected hexadecimal character'
				);
			}
			$c_val = ($c_num0 & $c_num) | ($c_alpha & $c_alpha0);
			if ($state === 0) {
				$c_acc = $c_val * 16;
			} else {
				$bin .= \pack('C', $c_acc | $c_val);
			}
			$state ^= 1;
		}
		return $bin;
	}
}
}

namespace ParagonIE\ConstantTime {

use TypeError;

abstract class RFC4648
{

	public static function base64Encode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64::encode($str);
	}

	public static function base64Decode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64::decode($str, true);
	}

	public static function base64UrlSafeEncode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64UrlSafe::encode($str);
	}

	public static function base64UrlSafeDecode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base64UrlSafe::decode($str, true);
	}

	public static function base32Encode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::encodeUpper($str);
	}

	public static function base32Decode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::decodeUpper($str, true);
	}

	public static function base32HexEncode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::encodeUpper($str);
	}

	public static function base32HexDecode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Base32::decodeUpper($str, true);
	}

	public static function base16Encode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Hex::encodeUpper($str);
	}

	public static function base16Decode(
		#[\SensitiveParameter]
		string $str
	): string {
		return Hex::decode($str, true);
	}
}
}

namespace phpseclib3\Common\Functions {

use ParagonIE\ConstantTime\Base64;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Hex;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\Common\FiniteField;

abstract class Strings
{

	public static function shift(&$string, $index = 1)
	{
		$substr = substr($string, 0, $index);
		$string = substr($string, $index);
		return $substr;
	}

	public static function pop(&$string, $index = 1)
	{
		$substr = substr($string, -$index);
		$string = substr($string, 0, -$index);
		return $substr;
	}

	public static function unpackSSH2($format, &$data)
	{
		$format = self::formatPack($format);
		$result = [];
		for ($i = 0; $i < strlen($format); $i++) {
			switch ($format[$i]) {
				case 'C':
				case 'b':
					if (!strlen($data)) {
						throw new \LengthException('At least one byte needs to be present for successful C / b decodes');
					}
					break;
				case 'N':
				case 'i':
				case 's':
				case 'L':
					if (strlen($data) < 4) {
						throw new \LengthException('At least four byte needs to be present for successful N / i / s / L decodes');
					}
					break;
				case 'Q':
					if (strlen($data) < 8) {
						throw new \LengthException('At least eight byte needs to be present for successful N / i / s / L decodes');
					}
					break;

				default:
					throw new \InvalidArgumentException('$format contains an invalid character');
			}
			switch ($format[$i]) {
				case 'C':
					$result[] = ord(self::shift($data));
					continue 2;
				case 'b':
					$result[] = ord(self::shift($data)) != 0;
					continue 2;
				case 'N':
					list(, $temp) = unpack('N', self::shift($data, 4));
					$result[] = $temp;
					continue 2;
				case 'Q':

					extract(unpack('Nupper/Nlower', self::shift($data, 8)));
					$temp = $upper ? 4294967296 * $upper : 0;
					$temp += $lower < 0 ? ($lower & 0x7FFFFFFFF) + 0x80000000 : $lower;

					$result[] = $temp;
					continue 2;
			}
			list(, $length) = unpack('N', self::shift($data, 4));
			if (strlen($data) < $length) {
				throw new \LengthException("$length bytes needed; " . strlen($data) . ' bytes available');
			}
			$temp = self::shift($data, $length);
			switch ($format[$i]) {
				case 'i':
					$result[] = new BigInteger($temp, -256);
					break;
				case 's':
					$result[] = $temp;
					break;
				case 'L':
					$result[] = explode(',', $temp);
			}
		}

		return $result;
	}

	public static function packSSH2($format, ...$elements)
	{
		$format = self::formatPack($format);
		if (strlen($format) != count($elements)) {
			throw new \InvalidArgumentException('There must be as many arguments as there are characters in the $format string');
		}
		$result = '';
		for ($i = 0; $i < strlen($format); $i++) {
			$element = $elements[$i];
			switch ($format[$i]) {
				case 'C':
					if (!is_int($element)) {
						throw new \InvalidArgumentException('Bytes must be represented as an integer between 0 and 255, inclusive.');
					}
					$result .= pack('C', $element);
					break;
				case 'b':
					if (!is_bool($element)) {
						throw new \InvalidArgumentException('A boolean parameter was expected.');
					}
					$result .= $element ? "\1" : "\0";
					break;
				case 'Q':
					if (!is_int($element) && !is_float($element)) {
						throw new \InvalidArgumentException('An integer was expected.');
					}

					$result .= pack('NN', $element / 4294967296, $element);
					break;
				case 'N':
					if (is_float($element)) {
						$element = (int) $element;
					}
					if (!is_int($element)) {
						throw new \InvalidArgumentException('An integer was expected.');
					}
					$result .= pack('N', $element);
					break;
				case 's':
					if (!self::is_stringable($element)) {
						throw new \InvalidArgumentException('A string was expected.');
					}
					$result .= pack('Na*', strlen($element), $element);
					break;
				case 'i':
					if (!$element instanceof BigInteger && !$element instanceof FiniteField\Integer) {
						throw new \InvalidArgumentException('A phpseclib3\Math\BigInteger or phpseclib3\Math\Common\FiniteField\Integer object was expected.');
					}
					$element = $element->toBytes(true);
					$result .= pack('Na*', strlen($element), $element);
					break;
				case 'L':
					if (!is_array($element)) {
						throw new \InvalidArgumentException('An array was expected.');
					}
					$element = implode(',', $element);
					$result .= pack('Na*', strlen($element), $element);
					break;
				default:
					throw new \InvalidArgumentException('$format contains an invalid character');
			}
		}
		return $result;
	}

	private static function formatPack($format)
	{
		$parts = preg_split('#(\d+)#', $format, -1, PREG_SPLIT_DELIM_CAPTURE);
		$format = '';
		for ($i = 1; $i < count($parts); $i += 2) {
			$format .= substr($parts[$i - 1], 0, -1) . str_repeat(substr($parts[$i - 1], -1), $parts[$i]);
		}
		$format .= $parts[$i - 1];

		return $format;
	}

	public static function bits2bin($x)
	{

		if (preg_match('#[^01]#', $x)) {
			throw new \RuntimeException('The only valid characters are 0 and 1');
		}

		if (!defined('PHP_INT_MIN')) {
			define('PHP_INT_MIN', ~PHP_INT_MAX);
		}

		$length = strlen($x);
		if (!$length) {
			return '';
		}
		$block_size = PHP_INT_SIZE << 3;
		$pad = $block_size - ($length % $block_size);
		if ($pad != $block_size) {
			$x = str_repeat('0', $pad) . $x;
		}

		$parts = str_split($x, $block_size);
		$str = '';
		foreach ($parts as $part) {
			$xor = $part[0] == '1' ? PHP_INT_MIN : 0;
			$part[0] = '0';
			$str .= pack(
				PHP_INT_SIZE == 4 ? 'N' : 'J',
				$xor ^ eval('return 0b' . $part . ';')
			);
		}
		return ltrim($str, "\0");
	}

	public static function bin2bits($x, $trim = true)
	{

		$len = strlen($x);
		$mod = $len % PHP_INT_SIZE;
		if ($mod) {
			$x = str_pad($x, $len + PHP_INT_SIZE - $mod, "\0", STR_PAD_LEFT);
		}

		$bits = '';
		if (PHP_INT_SIZE == 4) {
			$digits = unpack('N*', $x);
			foreach ($digits as $digit) {
				$bits .= sprintf('%032b', $digit);
			}
		} else {
			$digits = unpack('J*', $x);
			foreach ($digits as $digit) {
				$bits .= sprintf('%064b', $digit);
			}
		}

		return $trim ? ltrim($bits, '0') : $bits;
	}

	public static function switchEndianness($x)
	{
		$r = '';
		for ($i = strlen($x) - 1; $i >= 0; $i--) {
			$b = ord($x[$i]);
			if (PHP_INT_SIZE === 8) {

				$r .= chr((($b * 0x0202020202) & 0x010884422010) % 1023);
			} else {

				$p1 = ($b * 0x0802) & 0x22110;
				$p2 = ($b * 0x8020) & 0x88440;
				$r .= chr(
					(($p1 | $p2) * 0x10101) >> 16
				);
			}
		}
		return $r;
	}

	public static function increment_str(&$var)
	{
		if (function_exists('sodium_increment')) {
			$var = strrev($var);
			sodium_increment($var);
			$var = strrev($var);
			return $var;
		}

		for ($i = 4; $i <= strlen($var); $i += 4) {
			$temp = substr($var, -$i, 4);
			switch ($temp) {
				case "\xFF\xFF\xFF\xFF":
					$var = substr_replace($var, "\x00\x00\x00\x00", -$i, 4);
					break;
				case "\x7F\xFF\xFF\xFF":
					$var = substr_replace($var, "\x80\x00\x00\x00", -$i, 4);
					return $var;
				default:
					$temp = unpack('Nnum', $temp);
					$var = substr_replace($var, pack('N', $temp['num'] + 1), -$i, 4);
					return $var;
			}
		}

		$remainder = strlen($var) % 4;

		if ($remainder == 0) {
			return $var;
		}

		$temp = unpack('Nnum', str_pad(substr($var, 0, $remainder), 4, "\0", STR_PAD_LEFT));
		$temp = substr(pack('N', $temp['num'] + 1), -$remainder);
		$var = substr_replace($var, $temp, 0, $remainder);

		return $var;
	}

	public static function is_stringable($var)
	{
		return is_string($var) || (is_object($var) && method_exists($var, '__toString'));
	}

	public static function base64_decode($data)
	{
		return function_exists('sodium_base642bin') ?
			sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING, '=') :
			Base64::decode($data);
	}

	public static function base64url_decode($data)
	{

		return function_exists('sodium_base642bin') ?
			sodium_base642bin($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '=') :
			Base64UrlSafe::decode($data);
	}

	public static function base64_encode($data)
	{
		return function_exists('sodium_bin2base64') ?
			sodium_bin2base64($data, SODIUM_BASE64_VARIANT_ORIGINAL) :
			Base64::encode($data);
	}

	public static function base64url_encode($data)
	{

		return function_exists('sodium_bin2base64') ?
			sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) :
			Base64UrlSafe::encode($data);
	}

	public static function hex2bin($data)
	{
		return function_exists('sodium_hex2bin') ?
			sodium_hex2bin($data) :
			Hex::decode($data);
	}

	public static function bin2hex($data)
	{
		return function_exists('sodium_bin2hex') ?
			sodium_bin2hex($data) :
			Hex::encode($data);
	}
}
}

namespace phpseclib3\Crypt\Common {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Blowfish;
use phpseclib3\Crypt\Hash;
use phpseclib3\Exception\BadDecryptionException;
use phpseclib3\Exception\BadModeException;
use phpseclib3\Exception\InconsistentSetupException;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BinaryField;
use phpseclib3\Math\PrimeField;

abstract class SymmetricKey
{

	const MODE_CTR = -1;

	const MODE_ECB = 1;

	const MODE_CBC = 2;

	const MODE_CFB = 3;

	const MODE_CFB8 = 7;

	const MODE_OFB8 = 8;

	const MODE_OFB = 4;

	const MODE_GCM = 5;

	const MODE_STREAM = 6;

	const MODE_MAP = [
		'ctr'	=> self::MODE_CTR,
		'ecb'	=> self::MODE_ECB,
		'cbc'	=> self::MODE_CBC,
		'cfb'	=> self::MODE_CFB,
		'cfb8'	=> self::MODE_CFB8,
		'ofb'	=> self::MODE_OFB,
		'ofb8'	=> self::MODE_OFB8,
		'gcm'	=> self::MODE_GCM,
		'stream' => self::MODE_STREAM
	];

	const ENGINE_INTERNAL = 1;

	const ENGINE_EVAL = 2;

	const ENGINE_MCRYPT = 3;

	const ENGINE_OPENSSL = 4;

	const ENGINE_LIBSODIUM = 5;

	const ENGINE_OPENSSL_GCM = 6;

	const ENGINE_MAP = [
		self::ENGINE_INTERNAL	=> 'PHP',
		self::ENGINE_EVAL		=> 'Eval',
		self::ENGINE_MCRYPT		=> 'mcrypt',
		self::ENGINE_OPENSSL	 => 'OpenSSL',
		self::ENGINE_LIBSODIUM	=> 'libsodium',
		self::ENGINE_OPENSSL_GCM => 'OpenSSL (GCM)'
	];

	protected $mode;

	protected $block_size = 16;

	protected $key = false;

	protected $hKey = false;

	protected $iv = false;

	protected $encryptIV;

	protected $decryptIV;

	protected $continuousBuffer = false;

	protected $enbuffer;

	protected $debuffer;

	private $enmcrypt;

	private $demcrypt;

	private $enchanged = true;

	private $dechanged = true;

	private $ecb;

	protected $cfb_init_len = 600;

	protected $changed = true;

	protected $nonIVChanged = true;

	private $padding = true;

	private $paddable = false;

	protected $engine;

	private $preferredEngine;

	protected $cipher_name_mcrypt;

	protected $cipher_name_openssl;

	protected $cipher_name_openssl_ecb;

	private $password_default_salt = 'phpseclib/salt';

	protected $inline_crypt;

	private $openssl_emulate_ctr = false;

	private $skip_key_adjustment = false;

	protected $explicit_key_length = false;

	private $h;

	protected $aad = '';

	protected $newtag = false;

	protected $oldtag = false;

	private static $gcmField;

	private static $poly1305Field;

	protected static $use_reg_intval;

	protected $poly1305Key;

	protected $usePoly1305 = false;

	private $origIV = false;

	protected $nonce = false;

	public function __construct($mode)
	{
		$mode = strtolower($mode);

		$map = self::MODE_MAP;
		if (!isset($map[$mode])) {
			throw new BadModeException('No valid mode has been specified');
		}

		$mode = self::MODE_MAP[$mode];

		switch ($mode) {
			case self::MODE_ECB:
			case self::MODE_CBC:
				$this->paddable = true;
				break;
			case self::MODE_CTR:
			case self::MODE_CFB:
			case self::MODE_CFB8:
			case self::MODE_OFB:
			case self::MODE_OFB8:
			case self::MODE_STREAM:
				$this->paddable = false;
				break;
			case self::MODE_GCM:
				if ($this->block_size != 16) {
					throw new BadModeException('GCM is only valid for block ciphers with a block size of 128 bits');
				}
				if (!isset(self::$gcmField)) {
					self::$gcmField = new BinaryField(128, 7, 2, 1, 0);
				}
				$this->paddable = false;
				break;
			default:
				throw new BadModeException('No valid mode has been specified');
		}

		$this->mode = $mode;

		static::initialize_static_variables();
	}

	protected static function initialize_static_variables()
	{
		if (!isset(self::$use_reg_intval)) {
			switch (true) {

				case (PHP_OS & "\xDF\xDF\xDF") === 'WIN':
				case !function_exists('php_uname'):
				case !is_string(php_uname('m')):
				case (php_uname('m') & "\xDF\xDF\xDF") != 'ARM':
				case defined('PHP_INT_SIZE') && PHP_INT_SIZE == 8:
					self::$use_reg_intval = true;
					break;
				case (php_uname('m') & "\xDF\xDF\xDF") == 'ARM':
					switch (true) {

						case PHP_VERSION_ID >= 70000 && PHP_VERSION_ID <= 70123:
						case PHP_VERSION_ID >= 70200 && PHP_VERSION_ID <= 70211:
							self::$use_reg_intval = false;
							break;
						default:
							self::$use_reg_intval = true;
					}
			}
		}
	}

	public function setIV($iv)
	{
		if ($this->mode == self::MODE_ECB) {
			throw new \BadMethodCallException('This mode does not require an IV.');
		}

		if ($this->mode == self::MODE_GCM) {
			throw new \BadMethodCallException('Use setNonce instead');
		}

		if (!$this->usesIV()) {
			throw new \BadMethodCallException('This algorithm does not use an IV.');
		}

		if (strlen($iv) != $this->block_size) {
			throw new \LengthException('Received initialization vector of size ' . strlen($iv) . ', but size ' . $this->block_size . ' is required');
		}

		$this->iv = $this->origIV = $iv;
		$this->changed = true;
	}

	public function enablePoly1305()
	{
		if ($this->mode == self::MODE_GCM) {
			throw new \BadMethodCallException('Poly1305 cannot be used in GCM mode');
		}

		$this->usePoly1305 = true;
	}

	public function setPoly1305Key($key = null)
	{
		if ($this->mode == self::MODE_GCM) {
			throw new \BadMethodCallException('Poly1305 cannot be used in GCM mode');
		}

		if (!is_string($key) || strlen($key) != 32) {
			throw new \LengthException('The Poly1305 key must be 32 bytes long (256 bits)');
		}

		if (!isset(self::$poly1305Field)) {

			self::$poly1305Field = new PrimeField(new BigInteger('3fffffffffffffffffffffffffffffffb', 16));
		}

		$this->poly1305Key = $key;
		$this->usePoly1305 = true;
	}

	public function setNonce($nonce)
	{
		if ($this->mode != self::MODE_GCM) {
			throw new \BadMethodCallException('Nonces are only used in GCM mode.');
		}

		$this->nonce = $nonce;
		$this->setEngine();
	}

	public function setAAD($aad)
	{
		if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
			throw new \BadMethodCallException('Additional authenticated data is only utilized in GCM mode or with Poly1305');
		}

		$this->aad = $aad;
	}

	public function usesIV()
	{
		return $this->mode != self::MODE_GCM && $this->mode != self::MODE_ECB;
	}

	public function usesNonce()
	{
		return $this->mode == self::MODE_GCM;
	}

	public function getKeyLength()
	{
		return $this->key_length << 3;
	}

	public function getBlockLength()
	{
		return $this->block_size << 3;
	}

	public function getBlockLengthInBytes()
	{
		return $this->block_size;
	}

	public function setKeyLength($length)
	{
		$this->explicit_key_length = $length >> 3;

		if (is_string($this->key) && strlen($this->key) != $this->explicit_key_length) {
			$this->key = false;
			throw new InconsistentSetupException('Key has already been set and is not ' . $this->explicit_key_length . ' bytes long');
		}
	}

	public function setKey($key)
	{
		if ($this->explicit_key_length !== false && strlen($key) != $this->explicit_key_length) {
			throw new InconsistentSetupException('Key length has already been set to ' . $this->explicit_key_length . ' bytes and this key is ' . strlen($key) . ' bytes');
		}

		$this->key = $key;
		$this->key_length = strlen($key);
		$this->setEngine();
	}

	public function setPassword($password, $method = 'pbkdf2', ...$func_args)
	{
		$key = '';

		$method = strtolower($method);
		switch ($method) {
			case 'bcrypt':
				if (!isset($func_args[2])) {
					throw new \RuntimeException('A salt must be provided for bcrypt to work');
				}

				$salt = $func_args[0];

				$rounds = isset($func_args[1]) ? $func_args[1] : 16;
				$keylen = isset($func_args[2]) ? $func_args[2] : $this->key_length;

				$key = Blowfish::bcrypt_pbkdf($password, $salt, $keylen + $this->block_size, $rounds);

				$this->setKey(substr($key, 0, $keylen));
				$this->setIV(substr($key, $keylen));

				return true;
			case 'pkcs12':
			case 'pbkdf1':
			case 'pbkdf2':

				$hash = isset($func_args[0]) ? strtolower($func_args[0]) : 'sha1';
				$hashObj = new Hash();
				$hashObj->setHash($hash);

				$salt = isset($func_args[1]) ? $func_args[1] : $this->password_default_salt;

				$count = isset($func_args[2]) ? $func_args[2] : 1000;

				if (isset($func_args[3])) {
					if ($func_args[3] <= 0) {
						throw new \LengthException('Derived key length cannot be longer 0 or less');
					}
					$dkLen = $func_args[3];
				} else {
					$key_length = $this->explicit_key_length !== false ? $this->explicit_key_length : $this->key_length;
					$dkLen = $method == 'pbkdf1' ? 2 * $key_length : $key_length;
				}

				switch (true) {
					case $method == 'pkcs12':

						$password = "\0" . chunk_split($password, 1, "\0") . "\0";

						$blockLength = $hashObj->getBlockLengthInBytes();
						$d1 = str_repeat(chr(1), $blockLength);
						$d2 = str_repeat(chr(2), $blockLength);
						$s = '';
						if (strlen($salt)) {
							while (strlen($s) < $blockLength) {
								$s .= $salt;
							}
						}
						$s = substr($s, 0, $blockLength);

						$p = '';
						if (strlen($password)) {
							while (strlen($p) < $blockLength) {
								$p .= $password;
							}
						}
						$p = substr($p, 0, $blockLength);

						$i = $s . $p;

						$this->setKey(self::pkcs12helper($dkLen, $hashObj, $i, $d1, $count));
						if ($this->usesIV()) {
							$this->setIV(self::pkcs12helper($this->block_size, $hashObj, $i, $d2, $count));
						}

						return true;
					case $method == 'pbkdf1':
						if ($dkLen > $hashObj->getLengthInBytes()) {
							throw new \LengthException('Derived key length cannot be longer than the hash length');
						}
						$t = $password . $salt;
						for ($i = 0; $i < $count; ++$i) {
							$t = $hashObj->hash($t);
						}
						$key = substr($t, 0, $dkLen);

						$this->setKey(substr($key, 0, $dkLen >> 1));
						if ($this->usesIV()) {
							$this->setIV(substr($key, $dkLen >> 1));
						}

						return true;
					case !in_array($hash, hash_algos()):
						$i = 1;
						$hashObj->setKey($password);
						while (strlen($key) < $dkLen) {
							$f = $u = $hashObj->hash($salt . pack('N', $i++));
							for ($j = 2; $j <= $count; ++$j) {
								$u = $hashObj->hash($u);
								$f ^= $u;
							}
							$key .= $f;
						}
						$key = substr($key, 0, $dkLen);
						break;
					default:
						$key = hash_pbkdf2($hash, $password, $salt, $count, $dkLen, true);
				}
				break;
			default:
				throw new UnsupportedAlgorithmException($method . ' is not a supported password hashing method');
		}

		$this->setKey($key);

		return true;
	}

	private static function pkcs12helper($n, $hashObj, $i, $d, $count)
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		$blockLength = $hashObj->getBlockLength() >> 3;

		$c = ceil($n / $hashObj->getLengthInBytes());
		$a = '';
		for ($j = 1; $j <= $c; $j++) {
			$ai = $d . $i;
			for ($k = 0; $k < $count; $k++) {
				$ai = $hashObj->hash($ai);
			}
			$b = '';
			while (strlen($b) < $blockLength) {
				$b .= $ai;
			}
			$b = substr($b, 0, $blockLength);
			$b = new BigInteger($b, 256);
			$newi = '';
			for ($k = 0; $k < strlen($i); $k += $blockLength) {
				$temp = substr($i, $k, $blockLength);
				$temp = new BigInteger($temp, 256);
				$temp->setPrecision($blockLength << 3);
				$temp = $temp->add($b);
				$temp = $temp->add($one);
				$newi .= $temp->toBytes(false);
			}
			$i = $newi;
			$a .= $ai;
		}

		return substr($a, 0, $n);
	}

	public function encrypt($plaintext)
	{
		if ($this->paddable) {
			$plaintext = $this->pad($plaintext);
		}

		$this->setup();

		if ($this->mode == self::MODE_GCM) {
			$oldIV = $this->iv;
			Strings::increment_str($this->iv);
			$cipher = new static('ctr');
			$cipher->setKey($this->key);
			$cipher->setIV($this->iv);
			$ciphertext = $cipher->encrypt($plaintext);

			$s = $this->ghash(
				self::nullPad128($this->aad) .
				self::nullPad128($ciphertext) .
				self::len64($this->aad) .
				self::len64($ciphertext)
			);
			$cipher->encryptIV = $this->iv = $this->encryptIV = $this->decryptIV = $oldIV;
			$this->newtag = $cipher->encrypt($s);
			return $ciphertext;
		}

		if (isset($this->poly1305Key)) {
			$cipher = clone $this;
			unset($cipher->poly1305Key);
			$this->usePoly1305 = false;
			$ciphertext = $cipher->encrypt($plaintext);
			$this->newtag = $this->poly1305($ciphertext);
			return $ciphertext;
		}

		if ($this->engine === self::ENGINE_OPENSSL) {
			switch ($this->mode) {
				case self::MODE_STREAM:
					return openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
				case self::MODE_ECB:
					return openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
				case self::MODE_CBC:
					$result = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->encryptIV);
					if ($this->continuousBuffer) {
						$this->encryptIV = substr($result, -$this->block_size);
					}
					return $result;
				case self::MODE_CTR:
					return $this->openssl_ctr_process($plaintext, $this->encryptIV, $this->enbuffer);
				case self::MODE_CFB:

					$ciphertext = '';
					if ($this->continuousBuffer) {
						$iv = &$this->encryptIV;
						$pos = &$this->enbuffer['pos'];
					} else {
						$iv = $this->encryptIV;
						$pos = 0;
					}
					$len = strlen($plaintext);
					$i = 0;
					if ($pos) {
						$orig_pos = $pos;
						$max = $this->block_size - $pos;
						if ($len >= $max) {
							$i = $max;
							$len -= $max;
							$pos = 0;
						} else {
							$i = $len;
							$pos += $len;
							$len = 0;
						}

						$ciphertext = substr($iv, $orig_pos) ^ $plaintext;
						$iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
						$plaintext = substr($plaintext, $i);
					}

					$overflow = $len % $this->block_size;

					if ($overflow) {
						$ciphertext .= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
						$iv = Strings::pop($ciphertext, $this->block_size);

						$size = $len - $overflow;
						$block = $iv ^ substr($plaintext, -$overflow);
						$iv = substr_replace($iv, $block, 0, $overflow);
						$ciphertext .= $block;
						$pos = $overflow;
					} elseif ($len) {
						$ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
						$iv = substr($ciphertext, -$this->block_size);
					}

					return $ciphertext;
				case self::MODE_CFB8:
					$ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->encryptIV);
					if ($this->continuousBuffer) {
						if (($len = strlen($ciphertext)) >= $this->block_size) {
							$this->encryptIV = substr($ciphertext, -$this->block_size);
						} else {
							$this->encryptIV = substr($this->encryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
						}
					}
					return $ciphertext;
				case self::MODE_OFB8:
					$ciphertext = '';
					$len = strlen($plaintext);
					$iv = $this->encryptIV;

					for ($i = 0; $i < $len; ++$i) {
						$xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
						$ciphertext .= $plaintext[$i] ^ $xor;
						$iv = substr($iv, 1) . $xor[0];
					}

					if ($this->continuousBuffer) {
						$this->encryptIV = $iv;
					}
					break;
				case self::MODE_OFB:
					return $this->openssl_ofb_process($plaintext, $this->encryptIV, $this->enbuffer);
			}
		}

		if ($this->engine === self::ENGINE_MCRYPT) {
			set_error_handler(function () {
			});
			if ($this->enchanged) {
				mcrypt_generic_init($this->enmcrypt, $this->key, $this->getIV($this->encryptIV));
				$this->enchanged = false;
			}

			if ($this->mode == self::MODE_CFB && $this->continuousBuffer) {
				$block_size = $this->block_size;
				$iv = &$this->encryptIV;
				$pos = &$this->enbuffer['pos'];
				$len = strlen($plaintext);
				$ciphertext = '';
				$i = 0;
				if ($pos) {
					$orig_pos = $pos;
					$max = $block_size - $pos;
					if ($len >= $max) {
						$i = $max;
						$len -= $max;
						$pos = 0;
					} else {
						$i = $len;
						$pos += $len;
						$len = 0;
					}
					$ciphertext = substr($iv, $orig_pos) ^ $plaintext;
					$iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
					$this->enbuffer['enmcrypt_init'] = true;
				}
				if ($len >= $block_size) {
					if ($this->enbuffer['enmcrypt_init'] === false || $len > $this->cfb_init_len) {
						if ($this->enbuffer['enmcrypt_init'] === true) {
							mcrypt_generic_init($this->enmcrypt, $this->key, $iv);
							$this->enbuffer['enmcrypt_init'] = false;
						}
						$ciphertext .= mcrypt_generic($this->enmcrypt, substr($plaintext, $i, $len - $len % $block_size));
						$iv = substr($ciphertext, -$block_size);
						$len %= $block_size;
					} else {
						while ($len >= $block_size) {
							$iv = mcrypt_generic($this->ecb, $iv) ^ substr($plaintext, $i, $block_size);
							$ciphertext .= $iv;
							$len -= $block_size;
							$i += $block_size;
						}
					}
				}

				if ($len) {
					$iv = mcrypt_generic($this->ecb, $iv);
					$block = $iv ^ substr($plaintext, -$len);
					$iv = substr_replace($iv, $block, 0, $len);
					$ciphertext .= $block;
					$pos = $len;
				}

				restore_error_handler();

				return $ciphertext;
			}

			$ciphertext = mcrypt_generic($this->enmcrypt, $plaintext);

			if (!$this->continuousBuffer) {
				mcrypt_generic_init($this->enmcrypt, $this->key, $this->getIV($this->encryptIV));
			}

			restore_error_handler();

			return $ciphertext;
		}

		if ($this->engine === self::ENGINE_EVAL) {
			$inline = $this->inline_crypt;
			return $inline('encrypt', $plaintext);
		}

		$buffer = &$this->enbuffer;
		$block_size = $this->block_size;
		$ciphertext = '';
		switch ($this->mode) {
			case self::MODE_ECB:
				for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
					$ciphertext .= $this->encryptBlock(substr($plaintext, $i, $block_size));
				}
				break;
			case self::MODE_CBC:
				$xor = $this->encryptIV;
				for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
					$block = substr($plaintext, $i, $block_size);
					$block = $this->encryptBlock($block ^ $xor);
					$xor = $block;
					$ciphertext .= $block;
				}
				if ($this->continuousBuffer) {
					$this->encryptIV = $xor;
				}
				break;
			case self::MODE_CTR:
				$xor = $this->encryptIV;
				if (strlen($buffer['ciphertext'])) {
					for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
						$block = substr($plaintext, $i, $block_size);
						if (strlen($block) > strlen($buffer['ciphertext'])) {
							$buffer['ciphertext'] .= $this->encryptBlock($xor);
							Strings::increment_str($xor);
						}
						$key = Strings::shift($buffer['ciphertext'], $block_size);
						$ciphertext .= $block ^ $key;
					}
				} else {
					for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
						$block = substr($plaintext, $i, $block_size);
						$key = $this->encryptBlock($xor);
						Strings::increment_str($xor);
						$ciphertext .= $block ^ $key;
					}
				}
				if ($this->continuousBuffer) {
					$this->encryptIV = $xor;
					if ($start = strlen($plaintext) % $block_size) {
						$buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
					}
				}
				break;
			case self::MODE_CFB:

				if ($this->continuousBuffer) {
					$iv = &$this->encryptIV;
					$pos = &$buffer['pos'];
				} else {
					$iv = $this->encryptIV;
					$pos = 0;
				}
				$len = strlen($plaintext);
				$i = 0;
				if ($pos) {
					$orig_pos = $pos;
					$max = $block_size - $pos;
					if ($len >= $max) {
						$i = $max;
						$len -= $max;
						$pos = 0;
					} else {
						$i = $len;
						$pos += $len;
						$len = 0;
					}

					$ciphertext = substr($iv, $orig_pos) ^ $plaintext;
					$iv = substr_replace($iv, $ciphertext, $orig_pos, $i);
				}
				while ($len >= $block_size) {
					$iv = $this->encryptBlock($iv) ^ substr($plaintext, $i, $block_size);
					$ciphertext .= $iv;
					$len -= $block_size;
					$i += $block_size;
				}
				if ($len) {
					$iv = $this->encryptBlock($iv);
					$block = $iv ^ substr($plaintext, $i);
					$iv = substr_replace($iv, $block, 0, $len);
					$ciphertext .= $block;
					$pos = $len;
				}
				break;
			case self::MODE_CFB8:
				$ciphertext = '';
				$len = strlen($plaintext);
				$iv = $this->encryptIV;

				for ($i = 0; $i < $len; ++$i) {
					$ciphertext .= ($c = $plaintext[$i] ^ $this->encryptBlock($iv));
					$iv = substr($iv, 1) . $c;
				}

				if ($this->continuousBuffer) {
					if ($len >= $block_size) {
						$this->encryptIV = substr($ciphertext, -$block_size);
					} else {
						$this->encryptIV = substr($this->encryptIV, $len - $block_size) . substr($ciphertext, -$len);
					}
				}
				break;
			case self::MODE_OFB8:
				$ciphertext = '';
				$len = strlen($plaintext);
				$iv = $this->encryptIV;

				for ($i = 0; $i < $len; ++$i) {
					$xor = $this->encryptBlock($iv);
					$ciphertext .= $plaintext[$i] ^ $xor;
					$iv = substr($iv, 1) . $xor[0];
				}

				if ($this->continuousBuffer) {
					$this->encryptIV = $iv;
				}
				break;
			case self::MODE_OFB:
				$xor = $this->encryptIV;
				if (strlen($buffer['xor'])) {
					for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
						$block = substr($plaintext, $i, $block_size);
						if (strlen($block) > strlen($buffer['xor'])) {
							$xor = $this->encryptBlock($xor);
							$buffer['xor'] .= $xor;
						}
						$key = Strings::shift($buffer['xor'], $block_size);
						$ciphertext .= $block ^ $key;
					}
				} else {
					for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
						$xor = $this->encryptBlock($xor);
						$ciphertext .= substr($plaintext, $i, $block_size) ^ $xor;
					}
					$key = $xor;
				}
				if ($this->continuousBuffer) {
					$this->encryptIV = $xor;
					if ($start = strlen($plaintext) % $block_size) {
						$buffer['xor'] = substr($key, $start) . $buffer['xor'];
					}
				}
				break;
			case self::MODE_STREAM:
				$ciphertext = $this->encryptBlock($plaintext);
				break;
		}

		return $ciphertext;
	}

	public function decrypt($ciphertext)
	{
		if ($this->paddable && strlen($ciphertext) % $this->block_size) {
			throw new \LengthException('The ciphertext length (' . strlen($ciphertext) . ') needs to be a multiple of the block size (' . $this->block_size . ')');
		}
		$this->setup();

		if ($this->mode == self::MODE_GCM || isset($this->poly1305Key)) {
			if ($this->oldtag === false) {
				throw new InsufficientSetupException('Authentication Tag has not been set');
			}

			if (isset($this->poly1305Key)) {
				$newtag = $this->poly1305($ciphertext);
			} else {
				$oldIV = $this->iv;
				Strings::increment_str($this->iv);
				$cipher = new static('ctr');
				$cipher->setKey($this->key);
				$cipher->setIV($this->iv);
				$plaintext = $cipher->decrypt($ciphertext);

				$s = $this->ghash(
					self::nullPad128($this->aad) .
					self::nullPad128($ciphertext) .
					self::len64($this->aad) .
					self::len64($ciphertext)
				);
				$cipher->encryptIV = $this->iv = $this->encryptIV = $this->decryptIV = $oldIV;
				$newtag = $cipher->encrypt($s);
			}
			if ($this->oldtag != substr($newtag, 0, strlen($newtag))) {
				$cipher = clone $this;
				unset($cipher->poly1305Key);
				$this->usePoly1305 = false;
				$plaintext = $cipher->decrypt($ciphertext);
				$this->oldtag = false;
				throw new BadDecryptionException('Derived authentication tag and supplied authentication tag do not match');
			}
			$this->oldtag = false;
			return $plaintext;
		}

		if ($this->engine === self::ENGINE_OPENSSL) {
			switch ($this->mode) {
				case self::MODE_STREAM:
					$plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
					break;
				case self::MODE_ECB:
					$plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
					break;
				case self::MODE_CBC:
					$offset = $this->block_size;
					$plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->decryptIV);
					if ($this->continuousBuffer) {
						$this->decryptIV = substr($ciphertext, -$offset, $this->block_size);
					}
					break;
				case self::MODE_CTR:
					$plaintext = $this->openssl_ctr_process($ciphertext, $this->decryptIV, $this->debuffer);
					break;
				case self::MODE_CFB:

					$plaintext = '';
					if ($this->continuousBuffer) {
						$iv = &$this->decryptIV;
						$pos = &$this->debuffer['pos'];
					} else {
						$iv = $this->decryptIV;
						$pos = 0;
					}
					$len = strlen($ciphertext);
					$i = 0;
					if ($pos) {
						$orig_pos = $pos;
						$max = $this->block_size - $pos;
						if ($len >= $max) {
							$i = $max;
							$len -= $max;
							$pos = 0;
						} else {
							$i = $len;
							$pos += $len;
							$len = 0;
						}

						$plaintext = substr($iv, $orig_pos) ^ $ciphertext;
						$iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
						$ciphertext = substr($ciphertext, $i);
					}
					$overflow = $len % $this->block_size;
					if ($overflow) {
						$plaintext .= openssl_decrypt(substr($ciphertext, 0, -$overflow), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
						if ($len - $overflow) {
							$iv = substr($ciphertext, -$overflow - $this->block_size, -$overflow);
						}
						$iv = openssl_encrypt(str_repeat("\0", $this->block_size), $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
						$plaintext .= $iv ^ substr($ciphertext, -$overflow);
						$iv = substr_replace($iv, substr($ciphertext, -$overflow), 0, $overflow);
						$pos = $overflow;
					} elseif ($len) {
						$plaintext .= openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
						$iv = substr($ciphertext, -$this->block_size);
					}
					break;
				case self::MODE_CFB8:
					$plaintext = openssl_decrypt($ciphertext, $this->cipher_name_openssl, $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->decryptIV);
					if ($this->continuousBuffer) {
						if (($len = strlen($ciphertext)) >= $this->block_size) {
							$this->decryptIV = substr($ciphertext, -$this->block_size);
						} else {
							$this->decryptIV = substr($this->decryptIV, $len - $this->block_size) . substr($ciphertext, -$len);
						}
					}
					break;
				case self::MODE_OFB8:
					$plaintext = '';
					$len = strlen($ciphertext);
					$iv = $this->decryptIV;

					for ($i = 0; $i < $len; ++$i) {
						$xor = openssl_encrypt($iv, $this->cipher_name_openssl_ecb, $this->key, $this->openssl_options, $this->decryptIV);
						$plaintext .= $ciphertext[$i] ^ $xor;
						$iv = substr($iv, 1) . $xor[0];
					}

					if ($this->continuousBuffer) {
						$this->decryptIV = $iv;
					}
					break;
				case self::MODE_OFB:
					$plaintext = $this->openssl_ofb_process($ciphertext, $this->decryptIV, $this->debuffer);
			}

			return $this->paddable ? $this->unpad($plaintext) : $plaintext;
		}

		if ($this->engine === self::ENGINE_MCRYPT) {
			set_error_handler(function () {
			});
			$block_size = $this->block_size;
			if ($this->dechanged) {
				mcrypt_generic_init($this->demcrypt, $this->key, $this->getIV($this->decryptIV));
				$this->dechanged = false;
			}

			if ($this->mode == self::MODE_CFB && $this->continuousBuffer) {
				$iv = &$this->decryptIV;
				$pos = &$this->debuffer['pos'];
				$len = strlen($ciphertext);
				$plaintext = '';
				$i = 0;
				if ($pos) {
					$orig_pos = $pos;
					$max = $block_size - $pos;
					if ($len >= $max) {
						$i = $max;
						$len -= $max;
						$pos = 0;
					} else {
						$i = $len;
						$pos += $len;
						$len = 0;
					}

					$plaintext = substr($iv, $orig_pos) ^ $ciphertext;
					$iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
				}
				if ($len >= $block_size) {
					$cb = substr($ciphertext, $i, $len - $len % $block_size);
					$plaintext .= mcrypt_generic($this->ecb, $iv . $cb) ^ $cb;
					$iv = substr($cb, -$block_size);
					$len %= $block_size;
				}
				if ($len) {
					$iv = mcrypt_generic($this->ecb, $iv);
					$plaintext .= $iv ^ substr($ciphertext, -$len);
					$iv = substr_replace($iv, substr($ciphertext, -$len), 0, $len);
					$pos = $len;
				}

				restore_error_handler();

				return $plaintext;
			}

			$plaintext = mdecrypt_generic($this->demcrypt, $ciphertext);

			if (!$this->continuousBuffer) {
				mcrypt_generic_init($this->demcrypt, $this->key, $this->getIV($this->decryptIV));
			}

			restore_error_handler();

			return $this->paddable ? $this->unpad($plaintext) : $plaintext;
		}

		if ($this->engine === self::ENGINE_EVAL) {
			$inline = $this->inline_crypt;
			return $inline('decrypt', $ciphertext);
		}

		$block_size = $this->block_size;

		$buffer = &$this->debuffer;
		$plaintext = '';
		switch ($this->mode) {
			case self::MODE_ECB:
				for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
					$plaintext .= $this->decryptBlock(substr($ciphertext, $i, $block_size));
				}
				break;
			case self::MODE_CBC:
				$xor = $this->decryptIV;
				for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
					$block = substr($ciphertext, $i, $block_size);
					$plaintext .= $this->decryptBlock($block) ^ $xor;
					$xor = $block;
				}
				if ($this->continuousBuffer) {
					$this->decryptIV = $xor;
				}
				break;
			case self::MODE_CTR:
				$xor = $this->decryptIV;
				if (strlen($buffer['ciphertext'])) {
					for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
						$block = substr($ciphertext, $i, $block_size);
						if (strlen($block) > strlen($buffer['ciphertext'])) {
							$buffer['ciphertext'] .= $this->encryptBlock($xor);
							Strings::increment_str($xor);
						}
						$key = Strings::shift($buffer['ciphertext'], $block_size);
						$plaintext .= $block ^ $key;
					}
				} else {
					for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
						$block = substr($ciphertext, $i, $block_size);
						$key = $this->encryptBlock($xor);
						Strings::increment_str($xor);
						$plaintext .= $block ^ $key;
					}
				}
				if ($this->continuousBuffer) {
					$this->decryptIV = $xor;
					if ($start = strlen($ciphertext) % $block_size) {
						$buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
					}
				}
				break;
			case self::MODE_CFB:
				if ($this->continuousBuffer) {
					$iv = &$this->decryptIV;
					$pos = &$buffer['pos'];
				} else {
					$iv = $this->decryptIV;
					$pos = 0;
				}
				$len = strlen($ciphertext);
				$i = 0;
				if ($pos) {
					$orig_pos = $pos;
					$max = $block_size - $pos;
					if ($len >= $max) {
						$i = $max;
						$len -= $max;
						$pos = 0;
					} else {
						$i = $len;
						$pos += $len;
						$len = 0;
					}

					$plaintext = substr($iv, $orig_pos) ^ $ciphertext;
					$iv = substr_replace($iv, substr($ciphertext, 0, $i), $orig_pos, $i);
				}
				while ($len >= $block_size) {
					$iv = $this->encryptBlock($iv);
					$cb = substr($ciphertext, $i, $block_size);
					$plaintext .= $iv ^ $cb;
					$iv = $cb;
					$len -= $block_size;
					$i += $block_size;
				}
				if ($len) {
					$iv = $this->encryptBlock($iv);
					$plaintext .= $iv ^ substr($ciphertext, $i);
					$iv = substr_replace($iv, substr($ciphertext, $i), 0, $len);
					$pos = $len;
				}
				break;
			case self::MODE_CFB8:
				$plaintext = '';
				$len = strlen($ciphertext);
				$iv = $this->decryptIV;

				for ($i = 0; $i < $len; ++$i) {
					$plaintext .= $ciphertext[$i] ^ $this->encryptBlock($iv);
					$iv = substr($iv, 1) . $ciphertext[$i];
				}

				if ($this->continuousBuffer) {
					if ($len >= $block_size) {
						$this->decryptIV = substr($ciphertext, -$block_size);
					} else {
						$this->decryptIV = substr($this->decryptIV, $len - $block_size) . substr($ciphertext, -$len);
					}
				}
				break;
			case self::MODE_OFB8:
				$plaintext = '';
				$len = strlen($ciphertext);
				$iv = $this->decryptIV;

				for ($i = 0; $i < $len; ++$i) {
					$xor = $this->encryptBlock($iv);
					$plaintext .= $ciphertext[$i] ^ $xor;
					$iv = substr($iv, 1) . $xor[0];
				}

				if ($this->continuousBuffer) {
					$this->decryptIV = $iv;
				}
				break;
			case self::MODE_OFB:
				$xor = $this->decryptIV;
				if (strlen($buffer['xor'])) {
					for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
						$block = substr($ciphertext, $i, $block_size);
						if (strlen($block) > strlen($buffer['xor'])) {
							$xor = $this->encryptBlock($xor);
							$buffer['xor'] .= $xor;
						}
						$key = Strings::shift($buffer['xor'], $block_size);
						$plaintext .= $block ^ $key;
					}
				} else {
					for ($i = 0; $i < strlen($ciphertext); $i += $block_size) {
						$xor = $this->encryptBlock($xor);
						$plaintext .= substr($ciphertext, $i, $block_size) ^ $xor;
					}
					$key = $xor;
				}
				if ($this->continuousBuffer) {
					$this->decryptIV = $xor;
					if ($start = strlen($ciphertext) % $block_size) {
						$buffer['xor'] = substr($key, $start) . $buffer['xor'];
					}
				}
				break;
			case self::MODE_STREAM:
				$plaintext = $this->decryptBlock($ciphertext);
				break;
		}
		return $this->paddable ? $this->unpad($plaintext) : $plaintext;
	}

	public function getTag($length = 16)
	{
		if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
			throw new \BadMethodCallException('Authentication tags are only utilized in GCM mode or with Poly1305');
		}

		if ($this->newtag === false) {
			throw new \BadMethodCallException('A tag can only be returned after a round of encryption has been performed');
		}

		if ($length < 4 || $length > 16) {
			throw new \LengthException('The authentication tag must be between 4 and 16 bytes long');
		}

		return $length == 16 ?
			$this->newtag :
			substr($this->newtag, 0, $length);
	}

	public function setTag($tag)
	{
		if ($this->usePoly1305 && !isset($this->poly1305Key) && method_exists($this, 'createPoly1305Key')) {
			$this->createPoly1305Key();
		}

		if ($this->mode != self::MODE_GCM && !$this->usePoly1305) {
			throw new \BadMethodCallException('Authentication tags are only utilized in GCM mode or with Poly1305');
		}

		$length = strlen($tag);
		if ($length < 4 || $length > 16) {
			throw new \LengthException('The authentication tag must be between 4 and 16 bytes long');
		}
		$this->oldtag = $tag;
	}

	protected function getIV($iv)
	{
		return $this->mode == self::MODE_ECB ? str_repeat("\0", $this->block_size) : $iv;
	}

	private function openssl_ctr_process($plaintext, &$encryptIV, &$buffer)
	{
		$ciphertext = '';

		$block_size = $this->block_size;
		$key = $this->key;

		if ($this->openssl_emulate_ctr) {
			$xor = $encryptIV;
			if (strlen($buffer['ciphertext'])) {
				for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
					$block = substr($plaintext, $i, $block_size);
					if (strlen($block) > strlen($buffer['ciphertext'])) {
						$buffer['ciphertext'] .= openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
					}
					Strings::increment_str($xor);
					$otp = Strings::shift($buffer['ciphertext'], $block_size);
					$ciphertext .= $block ^ $otp;
				}
			} else {
				for ($i = 0; $i < strlen($plaintext); $i += $block_size) {
					$block = substr($plaintext, $i, $block_size);
					$otp = openssl_encrypt($xor, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
					Strings::increment_str($xor);
					$ciphertext .= $block ^ $otp;
				}
			}
			if ($this->continuousBuffer) {
				$encryptIV = $xor;
				if ($start = strlen($plaintext) % $block_size) {
					$buffer['ciphertext'] = substr($key, $start) . $buffer['ciphertext'];
				}
			}

			return $ciphertext;
		}

		if (strlen($buffer['ciphertext'])) {
			$ciphertext = $plaintext ^ Strings::shift($buffer['ciphertext'], strlen($plaintext));
			$plaintext = substr($plaintext, strlen($ciphertext));

			if (!strlen($plaintext)) {
				return $ciphertext;
			}
		}

		$overflow = strlen($plaintext) % $block_size;
		if ($overflow) {
			$plaintext2 = Strings::pop($plaintext, $overflow);
			$encrypted = openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
			$temp = Strings::pop($encrypted, $block_size);
			$ciphertext .= $encrypted . ($plaintext2 ^ $temp);
			if ($this->continuousBuffer) {
				$buffer['ciphertext'] = substr($temp, $overflow);
				$encryptIV = $temp;
			}
		} elseif (!strlen($buffer['ciphertext'])) {
			$ciphertext .= openssl_encrypt($plaintext . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
			$temp = Strings::pop($ciphertext, $block_size);
			if ($this->continuousBuffer) {
				$encryptIV = $temp;
			}
		}
		if ($this->continuousBuffer) {
			$encryptIV = openssl_decrypt($encryptIV, $this->cipher_name_openssl_ecb, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
			if ($overflow) {
				Strings::increment_str($encryptIV);
			}
		}

		return $ciphertext;
	}

	private function openssl_ofb_process($plaintext, &$encryptIV, &$buffer)
	{
		if (strlen($buffer['xor'])) {
			$ciphertext = $plaintext ^ $buffer['xor'];
			$buffer['xor'] = substr($buffer['xor'], strlen($ciphertext));
			$plaintext = substr($plaintext, strlen($ciphertext));
		} else {
			$ciphertext = '';
		}

		$block_size = $this->block_size;

		$len = strlen($plaintext);
		$key = $this->key;
		$overflow = $len % $block_size;

		if (strlen($plaintext)) {
			if ($overflow) {
				$ciphertext .= openssl_encrypt(substr($plaintext, 0, -$overflow) . str_repeat("\0", $block_size), $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
				$xor = Strings::pop($ciphertext, $block_size);
				if ($this->continuousBuffer) {
					$encryptIV = $xor;
				}
				$ciphertext .= Strings::shift($xor, $overflow) ^ substr($plaintext, -$overflow);
				if ($this->continuousBuffer) {
					$buffer['xor'] = $xor;
				}
			} else {
				$ciphertext = openssl_encrypt($plaintext, $this->cipher_name_openssl, $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $encryptIV);
				if ($this->continuousBuffer) {
					$encryptIV = substr($ciphertext, -$block_size) ^ substr($plaintext, -$block_size);
				}
			}
		}

		return $ciphertext;
	}

	protected function openssl_translate_mode()
	{
		switch ($this->mode) {
			case self::MODE_ECB:
				return 'ecb';
			case self::MODE_CBC:
				return 'cbc';
			case self::MODE_CTR:
			case self::MODE_GCM:
				return 'ctr';
			case self::MODE_CFB:
				return 'cfb';
			case self::MODE_CFB8:
				return 'cfb8';
			case self::MODE_OFB:
				return 'ofb';
		}
	}

	public function enablePadding()
	{
		$this->padding = true;
	}

	public function disablePadding()
	{
		$this->padding = false;
	}

	public function enableContinuousBuffer()
	{
		if ($this->mode == self::MODE_ECB) {
			return;
		}

		if ($this->mode == self::MODE_GCM) {
			throw new \BadMethodCallException('This mode does not run in continuous mode');
		}

		$this->continuousBuffer = true;

		$this->setEngine();
	}

	public function disableContinuousBuffer()
	{
		if ($this->mode == self::MODE_ECB) {
			return;
		}
		if (!$this->continuousBuffer) {
			return;
		}

		$this->continuousBuffer = false;

		$this->setEngine();
	}

	protected function isValidEngineHelper($engine)
	{
		switch ($engine) {
			case self::ENGINE_OPENSSL:
				$this->openssl_emulate_ctr = false;
				$result = $this->cipher_name_openssl &&
							extension_loaded('openssl');
				if (!$result) {
					return false;
				}

				$methods = openssl_get_cipher_methods();
				if (in_array($this->cipher_name_openssl, $methods)) {
					return true;
				}

				switch ($this->mode) {
					case self::MODE_CTR:
						if (in_array($this->cipher_name_openssl_ecb, $methods)) {
							$this->openssl_emulate_ctr = true;
							return true;
						}
				}
				return false;
			case self::ENGINE_MCRYPT:
				set_error_handler(function () {
				});
				$result = $this->cipher_name_mcrypt &&
							extension_loaded('mcrypt') &&
							in_array($this->cipher_name_mcrypt, mcrypt_list_algorithms());
				restore_error_handler();
				return $result;
			case self::ENGINE_EVAL:
				return method_exists($this, 'setupInlineCrypt');
			case self::ENGINE_INTERNAL:
				return true;
		}

		return false;
	}

	public function isValidEngine($engine)
	{
		static $reverseMap;
		if (!isset($reverseMap)) {
			$reverseMap = array_map('strtolower', self::ENGINE_MAP);
			$reverseMap = array_flip($reverseMap);
		}
		$engine = strtolower($engine);
		if (!isset($reverseMap[$engine])) {
			return false;
		}

		return $this->isValidEngineHelper($reverseMap[$engine]);
	}

	public function setPreferredEngine($engine)
	{
		static $reverseMap;
		if (!isset($reverseMap)) {
			$reverseMap = array_map('strtolower', self::ENGINE_MAP);
			$reverseMap = array_flip($reverseMap);
		}
		$engine = is_string($engine) ? strtolower($engine) : '';
		$this->preferredEngine = isset($reverseMap[$engine]) ? $reverseMap[$engine] : self::ENGINE_LIBSODIUM;

		$this->setEngine();
	}

	public function getEngine()
	{
		return self::ENGINE_MAP[$this->engine];
	}

	protected function setEngine()
	{
		$this->engine = null;

		$candidateEngines = [
			self::ENGINE_LIBSODIUM,
			self::ENGINE_OPENSSL_GCM,
			self::ENGINE_OPENSSL,
			self::ENGINE_MCRYPT,
			self::ENGINE_EVAL
		];
		if (isset($this->preferredEngine)) {
			$temp = [$this->preferredEngine];
			$candidateEngines = array_merge(
				$temp,
				array_diff($candidateEngines, $temp)
			);
		}
		foreach ($candidateEngines as $engine) {
			if ($this->isValidEngineHelper($engine)) {
				$this->engine = $engine;
				break;
			}
		}
		if (!$this->engine) {
			$this->engine = self::ENGINE_INTERNAL;
		}

		if ($this->engine != self::ENGINE_MCRYPT && $this->enmcrypt) {
			set_error_handler(function () {
			});

			mcrypt_module_close($this->enmcrypt);
			mcrypt_module_close($this->demcrypt);
			$this->enmcrypt = null;
			$this->demcrypt = null;

			if ($this->ecb) {
				mcrypt_module_close($this->ecb);
				$this->ecb = null;
			}
			restore_error_handler();
		}

		$this->changed = $this->nonIVChanged = true;
	}

	abstract protected function encryptBlock($in);

	abstract protected function decryptBlock($in);

	abstract protected function setupKey();

	protected function setup()
	{
		if (!$this->changed) {
			return;
		}

		$this->changed = false;

		if ($this->usePoly1305 && !isset($this->poly1305Key) && method_exists($this, 'createPoly1305Key')) {
			$this->createPoly1305Key();
		}

		$this->enbuffer = $this->debuffer = ['ciphertext' => '', 'xor' => '', 'pos' => 0, 'enmcrypt_init' => true];

		if ($this->usesNonce()) {
			if ($this->nonce === false) {
				throw new InsufficientSetupException('No nonce has been defined');
			}
			if ($this->mode == self::MODE_GCM && !in_array($this->engine, [self::ENGINE_LIBSODIUM, self::ENGINE_OPENSSL_GCM])) {
				$this->setupGCM();
			}
		} else {
			$this->iv = $this->origIV;
		}

		if ($this->iv === false && !in_array($this->mode, [self::MODE_STREAM, self::MODE_ECB])) {
			if ($this->mode != self::MODE_GCM || !in_array($this->engine, [self::ENGINE_LIBSODIUM, self::ENGINE_OPENSSL_GCM])) {
				throw new InsufficientSetupException('No IV has been defined');
			}
		}

		if ($this->key === false) {
			throw new InsufficientSetupException('No key has been defined');
		}

		$this->encryptIV = $this->decryptIV = $this->iv;

		switch ($this->engine) {
			case self::ENGINE_MCRYPT:
				$this->enchanged = $this->dechanged = true;

				set_error_handler(function () {
				});

				if (!isset($this->enmcrypt)) {
					static $mcrypt_modes = [
						self::MODE_CTR	=> 'ctr',
						self::MODE_ECB	=> MCRYPT_MODE_ECB,
						self::MODE_CBC	=> MCRYPT_MODE_CBC,
						self::MODE_CFB	=> 'ncfb',
						self::MODE_CFB8	=> MCRYPT_MODE_CFB,
						self::MODE_OFB	=> MCRYPT_MODE_NOFB,
						self::MODE_OFB8	=> MCRYPT_MODE_OFB,
						self::MODE_STREAM => MCRYPT_MODE_STREAM,
					];

					$this->demcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');
					$this->enmcrypt = mcrypt_module_open($this->cipher_name_mcrypt, '', $mcrypt_modes[$this->mode], '');

					if ($this->mode == self::MODE_CFB) {
						$this->ecb = mcrypt_module_open($this->cipher_name_mcrypt, '', MCRYPT_MODE_ECB, '');
					}
				}

				if ($this->mode == self::MODE_CFB) {
					mcrypt_generic_init($this->ecb, $this->key, str_repeat("\0", $this->block_size));
				}

				restore_error_handler();

				break;
			case self::ENGINE_INTERNAL:
				$this->setupKey();
				break;
			case self::ENGINE_EVAL:
				if ($this->nonIVChanged) {
					$this->setupKey();
					$this->setupInlineCrypt();
				}
		}

		$this->nonIVChanged = false;
	}

	protected function pad($text)
	{
		$length = strlen($text);

		if (!$this->padding) {
			if ($length % $this->block_size == 0) {
				return $text;
			} else {
				throw new \LengthException("The plaintext's length ($length) is not a multiple of the block size ({$this->block_size}). Try enabling padding.");
			}
		}

		$pad = $this->block_size - ($length % $this->block_size);

		return str_pad($text, $length + $pad, chr($pad));
	}

	protected function unpad($text)
	{
		if (!$this->padding) {
			return $text;
		}

		$length = ord($text[strlen($text) - 1]);

		if (!$length || $length > $this->block_size) {
			throw new BadDecryptionException("The ciphertext has an invalid padding length ($length) compared to the block size ({$this->block_size})");
		}

		return substr($text, 0, -$length);
	}

	protected function createInlineCryptFunction($cipher_code)
	{
		$block_size = $this->block_size;

		$init_crypt	= isset($cipher_code['init_crypt'])	? $cipher_code['init_crypt']	: '';
		$init_encrypt	= isset($cipher_code['init_encrypt'])	? $cipher_code['init_encrypt']	: '';
		$init_decrypt	= isset($cipher_code['init_decrypt'])	? $cipher_code['init_decrypt']	: '';

		$encrypt_block = $cipher_code['encrypt_block'];
		$decrypt_block = $cipher_code['decrypt_block'];

		switch ($this->mode) {
			case self::MODE_ECB:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ');
                        ' . $encrypt_block . '
                        $_ciphertext.= $in;
                    }

                    return $_ciphertext;
                    ';

				$decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + (' . $block_size . ' - strlen($_text) % ' . $block_size . ') % ' . $block_size . ', chr(0));
                    $_ciphertext_len = strlen($_text);

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ');
                        ' . $decrypt_block . '
                        $_plaintext.= $in;
                    }

                    return $this->unpad($_plaintext);
                    ';
				break;
			case self::MODE_CTR:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $this->encryptIV;
                    $_buffer = &$this->enbuffer;
                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                \phpseclib3\Common\Functions\Strings::increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = \phpseclib3\Common\Functions\Strings::shift($_buffer["ciphertext"], ' . $block_size . ');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            $in = $_xor;
                            ' . $encrypt_block . '
                            \phpseclib3\Common\Functions\Strings::increment_str($_xor);
                            $_key = $in;
                            $_ciphertext.= $_block ^ $_key;
                        }
                    }
                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % ' . $block_size . ') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_ciphertext;
                ';

				$decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $this->decryptIV;
                    $_buffer = &$this->debuffer;

                    if (strlen($_buffer["ciphertext"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["ciphertext"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                \phpseclib3\Common\Functions\Strings::increment_str($_xor);
                                $_buffer["ciphertext"].= $in;
                            }
                            $_key = \phpseclib3\Common\Functions\Strings::shift($_buffer["ciphertext"], ' . $block_size . ');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            $in = $_xor;
                            ' . $encrypt_block . '
                            \phpseclib3\Common\Functions\Strings::increment_str($_xor);
                            $_key = $in;
                            $_plaintext.= $_block ^ $_key;
                        }
                    }
                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % ' . $block_size . ') {
                            $_buffer["ciphertext"] = substr($_key, $_start) . $_buffer["ciphertext"];
                        }
                    }

                    return $_plaintext;
                    ';
				break;
			case self::MODE_CFB:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_buffer = &$this->enbuffer;

                    if ($this->continuousBuffer) {
                        $_iv = &$this->encryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $this->encryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = ' . $block_size . ' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_ciphertext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, $_ciphertext, $_orig_pos, $_i);
                    }
                    while ($_len >= ' . $block_size . ') {
                        $in = $_iv;
                        ' . $encrypt_block . ';
                        $_iv = $in ^ substr($_text, $_i, ' . $block_size . ');
                        $_ciphertext.= $_iv;
                        $_len-= ' . $block_size . ';
                        $_i+= ' . $block_size . ';
                    }
                    if ($_len) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $_block = $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, $_block, 0, $_len);
                        $_ciphertext.= $_block;
                        $_pos = $_len;
                    }
                    return $_ciphertext;
                ';

				$decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_buffer = &$this->debuffer;

                    if ($this->continuousBuffer) {
                        $_iv = &$this->decryptIV;
                        $_pos = &$_buffer["pos"];
                    } else {
                        $_iv = $this->decryptIV;
                        $_pos = 0;
                    }
                    $_len = strlen($_text);
                    $_i = 0;
                    if ($_pos) {
                        $_orig_pos = $_pos;
                        $_max = ' . $block_size . ' - $_pos;
                        if ($_len >= $_max) {
                            $_i = $_max;
                            $_len-= $_max;
                            $_pos = 0;
                        } else {
                            $_i = $_len;
                            $_pos+= $_len;
                            $_len = 0;
                        }
                        $_plaintext = substr($_iv, $_orig_pos) ^ $_text;
                        $_iv = substr_replace($_iv, substr($_text, 0, $_i), $_orig_pos, $_i);
                    }
                    while ($_len >= ' . $block_size . ') {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $cb = substr($_text, $_i, ' . $block_size . ');
                        $_plaintext.= $_iv ^ $cb;
                        $_iv = $cb;
                        $_len-= ' . $block_size . ';
                        $_i+= ' . $block_size . ';
                    }
                    if ($_len) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_iv = $in;
                        $_plaintext.= $_iv ^ substr($_text, $_i);
                        $_iv = substr_replace($_iv, substr($_text, $_i), 0, $_len);
                        $_pos = $_len;
                    }

                    return $_plaintext;
                    ';
				break;
			case self::MODE_CFB8:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $this->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_ciphertext .= ($_c = $_text[$_i] ^ $in);
                        $_iv = substr($_iv, 1) . $_c;
                    }

                    if ($this->continuousBuffer) {
                        if ($_len >= ' . $block_size . ') {
                            $this->encryptIV = substr($_ciphertext, -' . $block_size . ');
                        } else {
                            $this->encryptIV = substr($this->encryptIV, $_len - ' . $block_size . ') . substr($_ciphertext, -$_len);
                        }
                    }

                    return $_ciphertext;
                    ';
				$decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_plaintext .= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $_text[$_i];
                    }

                    if ($this->continuousBuffer) {
                        if ($_len >= ' . $block_size . ') {
                            $this->decryptIV = substr($_text, -' . $block_size . ');
                        } else {
                            $this->decryptIV = substr($this->decryptIV, $_len - ' . $block_size . ') . substr($_text, -$_len);
                        }
                    }

                    return $_plaintext;
                    ';
				break;
			case self::MODE_OFB8:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_len = strlen($_text);
                    $_iv = $this->encryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_ciphertext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_iv;
                    }

                    return $_ciphertext;
                    ';
				$decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_len = strlen($_text);
                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_len; ++$_i) {
                        $in = $_iv;
                        ' . $encrypt_block . '
                        $_plaintext.= $_text[$_i] ^ $in;
                        $_iv = substr($_iv, 1) . $in[0];
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_iv;
                    }

                    return $_plaintext;
                    ';
				break;
			case self::MODE_OFB:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);
                    $_xor = $this->encryptIV;
                    $_buffer = &$this->enbuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = \phpseclib3\Common\Functions\Strings::shift($_buffer["xor"], ' . $block_size . ');
                            $_ciphertext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                            $in = $_xor;
                            ' . $encrypt_block . '
                            $_xor = $in;
                            $_ciphertext.= substr($_text, $_i, ' . $block_size . ') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($this->continuousBuffer) {
                        $this->encryptIV = $_xor;
                        if ($_start = $_plaintext_len % ' . $block_size . ') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_ciphertext;
                    ';

				$decrypt = $init_encrypt . '
                    $_plaintext = "";
                    $_ciphertext_len = strlen($_text);
                    $_xor = $this->decryptIV;
                    $_buffer = &$this->debuffer;

                    if (strlen($_buffer["xor"])) {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $_block = substr($_text, $_i, ' . $block_size . ');
                            if (strlen($_block) > strlen($_buffer["xor"])) {
                                $in = $_xor;
                                ' . $encrypt_block . '
                                $_xor = $in;
                                $_buffer["xor"].= $_xor;
                            }
                            $_key = \phpseclib3\Common\Functions\Strings::shift($_buffer["xor"], ' . $block_size . ');
                            $_plaintext.= $_block ^ $_key;
                        }
                    } else {
                        for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                            $in = $_xor;
                            ' . $encrypt_block . '
                            $_xor = $in;
                            $_plaintext.= substr($_text, $_i, ' . $block_size . ') ^ $_xor;
                        }
                        $_key = $_xor;
                    }
                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_xor;
                        if ($_start = $_ciphertext_len % ' . $block_size . ') {
                             $_buffer["xor"] = substr($_key, $_start) . $_buffer["xor"];
                        }
                    }
                    return $_plaintext;
                    ';
				break;
			case self::MODE_STREAM:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    ' . $encrypt_block . '
                    return $_ciphertext;
                    ';
				$decrypt = $init_decrypt . '
                    $_plaintext = "";
                    ' . $decrypt_block . '
                    return $_plaintext;
                    ';
				break;

			default:
				$encrypt = $init_encrypt . '
                    $_ciphertext = "";
                    $_plaintext_len = strlen($_text);

                    $in = $this->encryptIV;

                    for ($_i = 0; $_i < $_plaintext_len; $_i+= ' . $block_size . ') {
                        $in = substr($_text, $_i, ' . $block_size . ') ^ $in;
                        ' . $encrypt_block . '
                        $_ciphertext.= $in;
                    }

                    if ($this->continuousBuffer) {
                        $this->encryptIV = $in;
                    }

                    return $_ciphertext;
                    ';

				$decrypt = $init_decrypt . '
                    $_plaintext = "";
                    $_text = str_pad($_text, strlen($_text) + (' . $block_size . ' - strlen($_text) % ' . $block_size . ') % ' . $block_size . ', chr(0));
                    $_ciphertext_len = strlen($_text);

                    $_iv = $this->decryptIV;

                    for ($_i = 0; $_i < $_ciphertext_len; $_i+= ' . $block_size . ') {
                        $in = $_block = substr($_text, $_i, ' . $block_size . ');
                        ' . $decrypt_block . '
                        $_plaintext.= $in ^ $_iv;
                        $_iv = $_block;
                    }

                    if ($this->continuousBuffer) {
                        $this->decryptIV = $_iv;
                    }

                    return $this->unpad($_plaintext);
                    ';
				break;
		}

		eval('$func = function ($_action, $_text) { ' . $init_crypt . 'if ($_action == "encrypt") { ' . $encrypt . ' } else { ' . $decrypt . ' }};');

		return \Closure::bind($func, $this, static::class);
	}

	protected static function safe_intval($x)
	{
		if (is_int($x)) {
			return $x;
		}

		if (self::$use_reg_intval) {
			return PHP_INT_SIZE == 4 && PHP_VERSION_ID >= 80100 ? intval($x) : $x;
		}

		return (fmod($x, 0x80000000) & 0x7FFFFFFF) |
			((fmod(floor($x / 0x80000000), 2) & 1) << 31);
	}

	protected static function safe_intval_inline()
	{
		if (self::$use_reg_intval) {
			return PHP_INT_SIZE == 4 && PHP_VERSION_ID >= 80100 ? 'intval(%s)' : '%s';
		}

		$safeint = '(is_int($temp = %s) ? $temp : (fmod($temp, 0x80000000) & 0x7FFFFFFF) | ';
		return $safeint . '((fmod(floor($temp / 0x80000000), 2) & 1) << 31))';
	}

	private function setupGCM()
	{

		if (!$this->h || $this->hKey != $this->key) {
			$cipher = new static('ecb');
			$cipher->setKey($this->key);
			$cipher->disablePadding();

			$this->h = self::$gcmField->newInteger(
				Strings::switchEndianness($cipher->encrypt("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"))
			);
			$this->hKey = $this->key;
		}

		if (strlen($this->nonce) == 12) {
			$this->iv = $this->nonce . "\0\0\0\1";
		} else {
			$this->iv = $this->ghash(
				self::nullPad128($this->nonce) . str_repeat("\0", 8) . self::len64($this->nonce)
			);
		}
	}

	private function ghash($x)
	{
		$h = $this->h;
		$y = ["\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"];
		$x = str_split($x, 16);
		$n = 0;

		foreach ($x as $xn) {
			$xn = Strings::switchEndianness($xn);
			$t = $y[$n] ^ $xn;
			$temp = self::$gcmField->newInteger($t);
			$y[++$n] = $temp->multiply($h)->toBytes();
			$y[$n] = substr($y[$n], 1);
		}
		$y[$n] = Strings::switchEndianness($y[$n]);
		return $y[$n];
	}

	private static function len64($str)
	{
		return "\0\0\0\0" . pack('N', 8 * strlen($str));
	}

	protected static function nullPad128($str)
	{
		$len = strlen($str);
		return $str . str_repeat("\0", 16 * ceil($len / 16) - $len);
	}

	protected function poly1305($text)
	{
		$s = $this->poly1305Key;
		$r = Strings::shift($s, 16);
		$r = strrev($r);
		$r &= "\x0f\xff\xff\xfc\x0f\xff\xff\xfc\x0f\xff\xff\xfc\x0f\xff\xff\xff";
		$s = strrev($s);

		$r = self::$poly1305Field->newInteger(new BigInteger($r, 256));
		$s = self::$poly1305Field->newInteger(new BigInteger($s, 256));
		$a = self::$poly1305Field->newInteger(new BigInteger());

		$blocks = str_split($text, 16);
		foreach ($blocks as $block) {
			$n = strrev($block . chr(1));
			$n = self::$poly1305Field->newInteger(new BigInteger($n, 256));
			$a = $a->add($n);
			$a = $a->multiply($r);
		}
		$r = $a->toBigInteger()->add($s->toBigInteger());
		$mask = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
		return strrev($r->toBytes()) & $mask;
	}

	public function getMode()
	{
		return array_flip(self::MODE_MAP)[$this->mode];
	}

	public function continuousBufferEnabled()
	{
		return $this->continuousBuffer;
	}
}
}

namespace phpseclib3\Crypt\Common {

abstract class BlockCipher extends SymmetricKey
{
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadDecryptionException;
use phpseclib3\Exception\BadModeException;
use phpseclib3\Exception\InconsistentSetupException;
use phpseclib3\Exception\InsufficientSetupException;

class Rijndael extends BlockCipher
{

	protected $cipher_name_mcrypt = 'rijndael-128';

	private $w;

	private $dw;

	private $Nb = 4;

	protected $key_length = 16;

	private $Nk = 4;

	private $Nr;

	private $c;

	private $kl;

	public function __construct($mode)
	{
		parent::__construct($mode);

		if ($this->mode == self::MODE_STREAM) {
			throw new BadModeException('Block ciphers cannot be ran in stream mode');
		}
	}

	public function setKeyLength($length)
	{
		switch ($length) {
			case 128:
			case 160:
			case 192:
			case 224:
			case 256:
				$this->key_length = $length >> 3;
				break;
			default:
				throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys of sizes 128, 160, 192, 224 or 256 bits are supported');
		}

		parent::setKeyLength($length);
	}

	public function setKey($key)
	{
		switch (strlen($key)) {
			case 16:
			case 20:
			case 24:
			case 28:
			case 32:
				break;
			default:
				throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16, 20, 24, 28 or 32 are supported');
		}

		parent::setKey($key);
	}

	public function setBlockLength($length)
	{
		switch ($length) {
			case 128:
			case 160:
			case 192:
			case 224:
			case 256:
				break;
			default:
				throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys of sizes 128, 160, 192, 224 or 256 bits are supported');
		}

		$this->Nb = $length >> 5;
		$this->block_size = $length >> 3;
		$this->changed = $this->nonIVChanged = true;
		$this->setEngine();
	}

	protected function isValidEngineHelper($engine)
	{
		switch ($engine) {
			case self::ENGINE_LIBSODIUM:
				return function_exists('sodium_crypto_aead_aes256gcm_is_available') &&
						sodium_crypto_aead_aes256gcm_is_available() &&
						$this->mode == self::MODE_GCM &&
						$this->key_length == 32 &&
						$this->nonce && strlen($this->nonce) == 12 &&
						$this->block_size == 16;
			case self::ENGINE_OPENSSL_GCM:
				if (!extension_loaded('openssl')) {
					return false;
				}
				$methods = openssl_get_cipher_methods();
				return $this->mode == self::MODE_GCM &&
						version_compare(PHP_VERSION, '7.1.0', '>=') &&
						in_array('aes-' . $this->getKeyLength() . '-gcm', $methods) &&
						$this->block_size == 16;
			case self::ENGINE_OPENSSL:
				if ($this->block_size != 16) {
					return false;
				}
				$this->cipher_name_openssl_ecb = 'aes-' . ($this->key_length << 3) . '-ecb';
				$this->cipher_name_openssl = 'aes-' . ($this->key_length << 3) . '-' . $this->openssl_translate_mode();
				break;
			case self::ENGINE_MCRYPT:
				$this->cipher_name_mcrypt = 'rijndael-' . ($this->block_size << 3);
				if ($this->key_length % 8) {

					return false;
				}
		}

		return parent::isValidEngineHelper($engine);
	}

	protected function encryptBlock($in)
	{
		static $tables;
		if (empty($tables)) {
			$tables = &$this->getTables();
		}
		$t0	= $tables[0];
		$t1	= $tables[1];
		$t2	= $tables[2];
		$t3	= $tables[3];
		$sbox = $tables[4];

		$state = [];
		$words = unpack('N*', $in);

		$c = $this->c;
		$w = $this->w;
		$Nb = $this->Nb;
		$Nr = $this->Nr;

		$wc = $Nb - 1;
		foreach ($words as $word) {
			$state[] = $word ^ $w[++$wc];
		}

		$temp = [];
		for ($round = 1; $round < $Nr; ++$round) {
			$i = 0;
			$j = $c[1];
			$k = $c[2];
			$l = $c[3];

			while ($i < $Nb) {
				$temp[$i] = $t0[$state[$i] >> 24 & 0x000000FF] ^
							$t1[$state[$j] >> 16 & 0x000000FF] ^
							$t2[$state[$k] >>	8 & 0x000000FF] ^
							$t3[$state[$l]		& 0x000000FF] ^
							$w[++$wc];
				++$i;
				$j = ($j + 1) % $Nb;
				$k = ($k + 1) % $Nb;
				$l = ($l + 1) % $Nb;
			}
			$state = $temp;
		}

		for ($i = 0; $i < $Nb; ++$i) {
			$state[$i] =	$sbox[$state[$i]		& 0x000000FF]		|
							($sbox[$state[$i] >>	8 & 0x000000FF] <<	8) |
							($sbox[$state[$i] >> 16 & 0x000000FF] << 16) |
							($sbox[$state[$i] >> 24 & 0x000000FF] << 24);
		}

		$i = 0;
		$j = $c[1];
		$k = $c[2];
		$l = $c[3];
		while ($i < $Nb) {
			$temp[$i] = ($state[$i] & intval(0xFF000000)) ^
						($state[$j] & 0x00FF0000) ^
						($state[$k] & 0x0000FF00) ^
						($state[$l] & 0x000000FF) ^
						 $w[$i];
			++$i;
			$j = ($j + 1) % $Nb;
			$k = ($k + 1) % $Nb;
			$l = ($l + 1) % $Nb;
		}

		return pack('N*', ...$temp);
	}

	protected function decryptBlock($in)
	{
		static $invtables;
		if (empty($invtables)) {
			$invtables = &$this->getInvTables();
		}
		$dt0	= $invtables[0];
		$dt1	= $invtables[1];
		$dt2	= $invtables[2];
		$dt3	= $invtables[3];
		$isbox = $invtables[4];

		$state = [];
		$words = unpack('N*', $in);

		$c	= $this->c;
		$dw = $this->dw;
		$Nb = $this->Nb;
		$Nr = $this->Nr;

		$wc = $Nb - 1;
		foreach ($words as $word) {
			$state[] = $word ^ $dw[++$wc];
		}

		$temp = [];
		for ($round = $Nr - 1; $round > 0; --$round) {
			$i = 0;
			$j = $Nb - $c[1];
			$k = $Nb - $c[2];
			$l = $Nb - $c[3];

			while ($i < $Nb) {
				$temp[$i] = $dt0[$state[$i] >> 24 & 0x000000FF] ^
							$dt1[$state[$j] >> 16 & 0x000000FF] ^
							$dt2[$state[$k] >>	8 & 0x000000FF] ^
							$dt3[$state[$l]		& 0x000000FF] ^
							$dw[++$wc];
				++$i;
				$j = ($j + 1) % $Nb;
				$k = ($k + 1) % $Nb;
				$l = ($l + 1) % $Nb;
			}
			$state = $temp;
		}

		$i = 0;
		$j = $Nb - $c[1];
		$k = $Nb - $c[2];
		$l = $Nb - $c[3];

		while ($i < $Nb) {
			$word = ($state[$i] & intval(0xFF000000)) |
					($state[$j] & 0x00FF0000) |
					($state[$k] & 0x0000FF00) |
					($state[$l] & 0x000000FF);

			$temp[$i] = $dw[$i] ^ ($isbox[$word		& 0x000000FF]		|
									($isbox[$word >>	8 & 0x000000FF] <<	8) |
									($isbox[$word >> 16 & 0x000000FF] << 16) |
									($isbox[$word >> 24 & 0x000000FF] << 24));
			++$i;
			$j = ($j + 1) % $Nb;
			$k = ($k + 1) % $Nb;
			$l = ($l + 1) % $Nb;
		}

		return pack('N*', ...$temp);
	}

	protected function setup()
	{
		if (!$this->changed) {
			return;
		}

		parent::setup();

		if (is_string($this->iv) && strlen($this->iv) != $this->block_size) {
			throw new InconsistentSetupException('The IV length (' . strlen($this->iv) . ') does not match the block size (' . $this->block_size . ')');
		}
	}

	protected function setupKey()
	{

		static $rcon;

		if (!isset($rcon)) {
			$rcon = [0,
				0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
				0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000,
				0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
				0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000,
				0x97000000, 0x35000000, 0x6A000000, 0xD4000000, 0xB3000000,
				0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000, 0x91000000
			];
			$rcon = array_map('intval', $rcon);
		}

		if (isset($this->kl['key']) && $this->key === $this->kl['key'] && $this->key_length === $this->kl['key_length'] && $this->block_size === $this->kl['block_size']) {

			return;
		}
		$this->kl = ['key' => $this->key, 'key_length' => $this->key_length, 'block_size' => $this->block_size];

		$this->Nk = $this->key_length >> 2;

		$this->Nr = max($this->Nk, $this->Nb) + 6;

		switch ($this->Nb) {
			case 4:
			case 5:
			case 6:
				$this->c = [0, 1, 2, 3];
				break;
			case 7:
				$this->c = [0, 1, 2, 4];
				break;
			case 8:
				$this->c = [0, 1, 3, 4];
		}

		$w = array_values(unpack('N*words', $this->key));

		$length = $this->Nb * ($this->Nr + 1);
		for ($i = $this->Nk; $i < $length; $i++) {
			$temp = $w[$i - 1];
			if ($i % $this->Nk == 0) {

				$temp = (($temp << 8) & intval(0xFFFFFF00)) | (($temp >> 24) & 0x000000FF);
				$temp = $this->subWord($temp) ^ $rcon[$i / $this->Nk];
			} elseif ($this->Nk > 6 && $i % $this->Nk == 4) {
				$temp = $this->subWord($temp);
			}
			$w[$i] = $w[$i - $this->Nk] ^ $temp;
		}

		list($dt0, $dt1, $dt2, $dt3) = $this->getInvTables();
		$temp = $this->w = $this->dw = [];
		for ($i = $row = $col = 0; $i < $length; $i++, $col++) {
			if ($col == $this->Nb) {
				if ($row == 0) {
					$this->dw[0] = $this->w[0];
				} else {

					$j = 0;
					while ($j < $this->Nb) {
						$dw = $this->subWord($this->w[$row][$j]);
						$temp[$j] = $dt0[$dw >> 24 & 0x000000FF] ^
									$dt1[$dw >> 16 & 0x000000FF] ^
									$dt2[$dw >>	8 & 0x000000FF] ^
									$dt3[$dw		& 0x000000FF];
						$j++;
					}
					$this->dw[$row] = $temp;
				}

				$col = 0;
				$row++;
			}
			$this->w[$row][$col] = $w[$i];
		}

		$this->dw[$row] = $this->w[$row];

		$this->dw = array_reverse($this->dw);
		$w	= array_pop($this->w);
		$dw = array_pop($this->dw);
		foreach ($this->w as $r => $wr) {
			foreach ($wr as $c => $wc) {
				$w[]	= $wc;
				$dw[] = $this->dw[$r][$c];
			}
		}
		$this->w	= $w;
		$this->dw = $dw;
	}

	private function subWord($word)
	{
		static $sbox;
		if (empty($sbox)) {
			list(, , , , $sbox) = self::getTables();
		}

		return	$sbox[$word		& 0x000000FF]		|
				($sbox[$word >>	8 & 0x000000FF] <<	8) |
				($sbox[$word >> 16 & 0x000000FF] << 16) |
				($sbox[$word >> 24 & 0x000000FF] << 24);
	}

	protected function &getTables()
	{
		static $tables;
		if (empty($tables)) {

			$t3 = array_map('intval', [

				0x6363A5C6, 0x7C7C84F8, 0x777799EE, 0x7B7B8DF6, 0xF2F20DFF, 0x6B6BBDD6, 0x6F6FB1DE, 0xC5C55491,
				0x30305060, 0x01010302, 0x6767A9CE, 0x2B2B7D56, 0xFEFE19E7, 0xD7D762B5, 0xABABE64D, 0x76769AEC,
				0xCACA458F, 0x82829D1F, 0xC9C94089, 0x7D7D87FA, 0xFAFA15EF, 0x5959EBB2, 0x4747C98E, 0xF0F00BFB,
				0xADADEC41, 0xD4D467B3, 0xA2A2FD5F, 0xAFAFEA45, 0x9C9CBF23, 0xA4A4F753, 0x727296E4, 0xC0C05B9B,
				0xB7B7C275, 0xFDFD1CE1, 0x9393AE3D, 0x26266A4C, 0x36365A6C, 0x3F3F417E, 0xF7F702F5, 0xCCCC4F83,
				0x34345C68, 0xA5A5F451, 0xE5E534D1, 0xF1F108F9, 0x717193E2, 0xD8D873AB, 0x31315362, 0x15153F2A,
				0x04040C08, 0xC7C75295, 0x23236546, 0xC3C35E9D, 0x18182830, 0x9696A137, 0x05050F0A, 0x9A9AB52F,
				0x0707090E, 0x12123624, 0x80809B1B, 0xE2E23DDF, 0xEBEB26CD, 0x2727694E, 0xB2B2CD7F, 0x75759FEA,
				0x09091B12, 0x83839E1D, 0x2C2C7458, 0x1A1A2E34, 0x1B1B2D36, 0x6E6EB2DC, 0x5A5AEEB4, 0xA0A0FB5B,
				0x5252F6A4, 0x3B3B4D76, 0xD6D661B7, 0xB3B3CE7D, 0x29297B52, 0xE3E33EDD, 0x2F2F715E, 0x84849713,
				0x5353F5A6, 0xD1D168B9, 0x00000000, 0xEDED2CC1, 0x20206040, 0xFCFC1FE3, 0xB1B1C879, 0x5B5BEDB6,
				0x6A6ABED4, 0xCBCB468D, 0xBEBED967, 0x39394B72, 0x4A4ADE94, 0x4C4CD498, 0x5858E8B0, 0xCFCF4A85,
				0xD0D06BBB, 0xEFEF2AC5, 0xAAAAE54F, 0xFBFB16ED, 0x4343C586, 0x4D4DD79A, 0x33335566, 0x85859411,
				0x4545CF8A, 0xF9F910E9, 0x02020604, 0x7F7F81FE, 0x5050F0A0, 0x3C3C4478, 0x9F9FBA25, 0xA8A8E34B,
				0x5151F3A2, 0xA3A3FE5D, 0x4040C080, 0x8F8F8A05, 0x9292AD3F, 0x9D9DBC21, 0x38384870, 0xF5F504F1,
				0xBCBCDF63, 0xB6B6C177, 0xDADA75AF, 0x21216342, 0x10103020, 0xFFFF1AE5, 0xF3F30EFD, 0xD2D26DBF,
				0xCDCD4C81, 0x0C0C1418, 0x13133526, 0xECEC2FC3, 0x5F5FE1BE, 0x9797A235, 0x4444CC88, 0x1717392E,
				0xC4C45793, 0xA7A7F255, 0x7E7E82FC, 0x3D3D477A, 0x6464ACC8, 0x5D5DE7BA, 0x19192B32, 0x737395E6,
				0x6060A0C0, 0x81819819, 0x4F4FD19E, 0xDCDC7FA3, 0x22226644, 0x2A2A7E54, 0x9090AB3B, 0x8888830B,
				0x4646CA8C, 0xEEEE29C7, 0xB8B8D36B, 0x14143C28, 0xDEDE79A7, 0x5E5EE2BC, 0x0B0B1D16, 0xDBDB76AD,
				0xE0E03BDB, 0x32325664, 0x3A3A4E74, 0x0A0A1E14, 0x4949DB92, 0x06060A0C, 0x24246C48, 0x5C5CE4B8,
				0xC2C25D9F, 0xD3D36EBD, 0xACACEF43, 0x6262A6C4, 0x9191A839, 0x9595A431, 0xE4E437D3, 0x79798BF2,
				0xE7E732D5, 0xC8C8438B, 0x3737596E, 0x6D6DB7DA, 0x8D8D8C01, 0xD5D564B1, 0x4E4ED29C, 0xA9A9E049,
				0x6C6CB4D8, 0x5656FAAC, 0xF4F407F3, 0xEAEA25CF, 0x6565AFCA, 0x7A7A8EF4, 0xAEAEE947, 0x08081810,
				0xBABAD56F, 0x787888F0, 0x25256F4A, 0x2E2E725C, 0x1C1C2438, 0xA6A6F157, 0xB4B4C773, 0xC6C65197,
				0xE8E823CB, 0xDDDD7CA1, 0x74749CE8, 0x1F1F213E, 0x4B4BDD96, 0xBDBDDC61, 0x8B8B860D, 0x8A8A850F,
				0x707090E0, 0x3E3E427C, 0xB5B5C471, 0x6666AACC, 0x4848D890, 0x03030506, 0xF6F601F7, 0x0E0E121C,
				0x6161A3C2, 0x35355F6A, 0x5757F9AE, 0xB9B9D069, 0x86869117, 0xC1C15899, 0x1D1D273A, 0x9E9EB927,
				0xE1E138D9, 0xF8F813EB, 0x9898B32B, 0x11113322, 0x6969BBD2, 0xD9D970A9, 0x8E8E8907, 0x9494A733,
				0x9B9BB62D, 0x1E1E223C, 0x87879215, 0xE9E920C9, 0xCECE4987, 0x5555FFAA, 0x28287850, 0xDFDF7AA5,
				0x8C8C8F03, 0xA1A1F859, 0x89898009, 0x0D0D171A, 0xBFBFDA65, 0xE6E631D7, 0x4242C684, 0x6868B8D0,
				0x4141C382, 0x9999B029, 0x2D2D775A, 0x0F0F111E, 0xB0B0CB7B, 0x5454FCA8, 0xBBBBD66D, 0x16163A2C
			]);

			foreach ($t3 as $t3i) {
				$t0[] = (($t3i << 24) & intval(0xFF000000)) | (($t3i >>	8) & 0x00FFFFFF);
				$t1[] = (($t3i << 16) & intval(0xFFFF0000)) | (($t3i >> 16) & 0x0000FFFF);
				$t2[] = (($t3i <<	8) & intval(0xFFFFFF00)) | (($t3i >> 24) & 0x000000FF);
			}

			$tables = [

				$t0,
				$t1,
				$t2,
				$t3,

				[
					0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
					0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
					0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
					0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
					0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
					0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
					0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
					0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
					0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
					0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
					0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
					0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
					0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
					0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
					0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
					0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
				]
			];
		}
		return $tables;
	}

	protected function &getInvTables()
	{
		static $tables;
		if (empty($tables)) {
			$dt3 = array_map('intval', [
				0xF4A75051, 0x4165537E, 0x17A4C31A, 0x275E963A, 0xAB6BCB3B, 0x9D45F11F, 0xFA58ABAC, 0xE303934B,
				0x30FA5520, 0x766DF6AD, 0xCC769188, 0x024C25F5, 0xE5D7FC4F, 0x2ACBD7C5, 0x35448026, 0x62A38FB5,
				0xB15A49DE, 0xBA1B6725, 0xEA0E9845, 0xFEC0E15D, 0x2F7502C3, 0x4CF01281, 0x4697A38D, 0xD3F9C66B,
				0x8F5FE703, 0x929C9515, 0x6D7AEBBF, 0x5259DA95, 0xBE832DD4, 0x7421D358, 0xE0692949, 0xC9C8448E,
				0xC2896A75, 0x8E7978F4, 0x583E6B99, 0xB971DD27, 0xE14FB6BE, 0x88AD17F0, 0x20AC66C9, 0xCE3AB47D,
				0xDF4A1863, 0x1A3182E5, 0x51336097, 0x537F4562, 0x6477E0B1, 0x6BAE84BB, 0x81A01CFE, 0x082B94F9,
				0x48685870, 0x45FD198F, 0xDE6C8794, 0x7BF8B752, 0x73D323AB, 0x4B02E272, 0x1F8F57E3, 0x55AB2A66,
				0xEB2807B2, 0xB5C2032F, 0xC57B9A86, 0x3708A5D3, 0x2887F230, 0xBFA5B223, 0x036ABA02, 0x16825CED,
				0xCF1C2B8A, 0x79B492A7, 0x07F2F0F3, 0x69E2A14E, 0xDAF4CD65, 0x05BED506, 0x34621FD1, 0xA6FE8AC4,
				0x2E539D34, 0xF355A0A2, 0x8AE13205, 0xF6EB75A4, 0x83EC390B, 0x60EFAA40, 0x719F065E, 0x6E1051BD,
				0x218AF93E, 0xDD063D96, 0x3E05AEDD, 0xE6BD464D, 0x548DB591, 0xC45D0571, 0x06D46F04, 0x5015FF60,
				0x98FB2419, 0xBDE997D6, 0x4043CC89, 0xD99E7767, 0xE842BDB0, 0x898B8807, 0x195B38E7, 0xC8EEDB79,
				0x7C0A47A1, 0x420FE97C, 0x841EC9F8, 0x00000000, 0x80868309, 0x2BED4832, 0x1170AC1E, 0x5A724E6C,
				0x0EFFFBFD, 0x8538560F, 0xAED51E3D, 0x2D392736, 0x0FD9640A, 0x5CA62168, 0x5B54D19B, 0x362E3A24,
				0x0A67B10C, 0x57E70F93, 0xEE96D2B4, 0x9B919E1B, 0xC0C54F80, 0xDC20A261, 0x774B695A, 0x121A161C,
				0x93BA0AE2, 0xA02AE5C0, 0x22E0433C, 0x1B171D12, 0x090D0B0E, 0x8BC7ADF2, 0xB6A8B92D, 0x1EA9C814,
				0xF1198557, 0x75074CAF, 0x99DDBBEE, 0x7F60FDA3, 0x01269FF7, 0x72F5BC5C, 0x663BC544, 0xFB7E345B,
				0x4329768B, 0x23C6DCCB, 0xEDFC68B6, 0xE4F163B8, 0x31DCCAD7, 0x63851042, 0x97224013, 0xC6112084,
				0x4A247D85, 0xBB3DF8D2, 0xF93211AE, 0x29A16DC7, 0x9E2F4B1D, 0xB230F3DC, 0x8652EC0D, 0xC1E3D077,
				0xB3166C2B, 0x70B999A9, 0x9448FA11, 0xE9642247, 0xFC8CC4A8, 0xF03F1AA0, 0x7D2CD856, 0x3390EF22,
				0x494EC787, 0x38D1C1D9, 0xCAA2FE8C, 0xD40B3698, 0xF581CFA6, 0x7ADE28A5, 0xB78E26DA, 0xADBFA43F,
				0x3A9DE42C, 0x78920D50, 0x5FCC9B6A, 0x7E466254, 0x8D13C2F6, 0xD8B8E890, 0x39F75E2E, 0xC3AFF582,
				0x5D80BE9F, 0xD0937C69, 0xD52DA96F, 0x2512B3CF, 0xAC993BC8, 0x187DA710, 0x9C636EE8, 0x3BBB7BDB,
				0x267809CD, 0x5918F46E, 0x9AB701EC, 0x4F9AA883, 0x956E65E6, 0xFFE67EAA, 0xBCCF0821, 0x15E8E6EF,
				0xE79BD9BA, 0x6F36CE4A, 0x9F09D4EA, 0xB07CD629, 0xA4B2AF31, 0x3F23312A, 0xA59430C6, 0xA266C035,
				0x4EBC3774, 0x82CAA6FC, 0x90D0B0E0, 0xA7D81533, 0x04984AF1, 0xECDAF741, 0xCD500E7F, 0x91F62F17,
				0x4DD68D76, 0xEFB04D43, 0xAA4D54CC, 0x9604DFE4, 0xD1B5E39E, 0x6A881B4C, 0x2C1FB8C1, 0x65517F46,
				0x5EEA049D, 0x8C355D01, 0x877473FA, 0x0B412EFB, 0x671D5AB3, 0xDBD25292, 0x105633E9, 0xD647136D,
				0xD7618C9A, 0xA10C7A37, 0xF8148E59, 0x133C89EB, 0xA927EECE, 0x61C935B7, 0x1CE5EDE1, 0x47B13C7A,
				0xD2DF599C, 0xF2733F55, 0x14CE7918, 0xC737BF73, 0xF7CDEA53, 0xFDAA5B5F, 0x3D6F14DF, 0x44DB8678,
				0xAFF381CA, 0x68C43EB9, 0x24342C38, 0xA3405FC2, 0x1DC37216, 0xE2250CBC, 0x3C498B28, 0x0D9541FF,
				0xA8017139, 0x0CB3DE08, 0xB4E49CD8, 0x56C19064, 0xCB84617B, 0x32B670D5, 0x6C5C7448, 0xB85742D0
			]);

			foreach ($dt3 as $dt3i) {
				$dt0[] = (($dt3i << 24) & intval(0xFF000000)) | (($dt3i >>	8) & 0x00FFFFFF);
				$dt1[] = (($dt3i << 16) & intval(0xFFFF0000)) | (($dt3i >> 16) & 0x0000FFFF);
				$dt2[] = (($dt3i <<	8) & intval(0xFFFFFF00)) | (($dt3i >> 24) & 0x000000FF);
			};

			$tables = [

				$dt0,
				$dt1,
				$dt2,
				$dt3,

				[
					0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
					0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
					0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
					0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
					0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
					0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
					0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
					0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
					0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
					0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
					0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
					0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
					0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
					0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
					0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
					0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
				]
			];
		}
		return $tables;
	}

	protected function setupInlineCrypt()
	{
		$w	= $this->w;
		$dw = $this->dw;
		$init_encrypt = '';
		$init_decrypt = '';

		$Nr = $this->Nr;
		$Nb = $this->Nb;
		$c	= $this->c;

		$init_encrypt .= '
            if (empty($tables)) {
                $tables = &$this->getTables();
            }
            $t0   = $tables[0];
            $t1   = $tables[1];
            $t2   = $tables[2];
            $t3   = $tables[3];
            $sbox = $tables[4];
        ';

		$s	= 'e';
		$e	= 's';
		$wc = $Nb - 1;

		$encrypt_block = '$in = unpack("N*", $in);' . "\n";
		for ($i = 0; $i < $Nb; ++$i) {
			$encrypt_block .= '$s' . $i . ' = $in[' . ($i + 1) . '] ^ ' . $w[++$wc] . ";\n";
		}

		for ($round = 1; $round < $Nr; ++$round) {
			list($s, $e) = [$e, $s];
			for ($i = 0; $i < $Nb; ++$i) {
				$encrypt_block .=
					'$' . $e . $i . ' =
                    $t0[($' . $s . $i					. ' >> 24) & 0xff] ^
                    $t1[($' . $s . (($i + $c[1]) % $Nb) . ' >> 16) & 0xff] ^
                    $t2[($' . $s . (($i + $c[2]) % $Nb) . ' >>  8) & 0xff] ^
                    $t3[ $' . $s . (($i + $c[3]) % $Nb) . '        & 0xff] ^
                    ' . $w[++$wc] . ";\n";
			}
		}

		for ($i = 0; $i < $Nb; ++$i) {
			$encrypt_block .=
				'$' . $e . $i . ' =
                 $sbox[ $' . $e . $i . '        & 0xff]        |
                ($sbox[($' . $e . $i . ' >>  8) & 0xff] <<  8) |
                ($sbox[($' . $e . $i . ' >> 16) & 0xff] << 16) |
                ($sbox[($' . $e . $i . ' >> 24) & 0xff] << 24);' . "\n";
		}
		$encrypt_block .= '$in = pack("N*"' . "\n";
		for ($i = 0; $i < $Nb; ++$i) {
			$encrypt_block .= ',
                ($' . $e . $i					. ' & ' . ((int)0xFF000000) . ') ^
                ($' . $e . (($i + $c[1]) % $Nb) . ' &         0x00FF0000   ) ^
                ($' . $e . (($i + $c[2]) % $Nb) . ' &         0x0000FF00   ) ^
                ($' . $e . (($i + $c[3]) % $Nb) . ' &         0x000000FF   ) ^
                ' . $w[$i] . "\n";
		}
		$encrypt_block .= ');';

		$init_decrypt .= '
            if (empty($invtables)) {
                $invtables = &$this->getInvTables();
            }
            $dt0   = $invtables[0];
            $dt1   = $invtables[1];
            $dt2   = $invtables[2];
            $dt3   = $invtables[3];
            $isbox = $invtables[4];
        ';

		$s	= 'e';
		$e	= 's';
		$wc = $Nb - 1;

		$decrypt_block = '$in = unpack("N*", $in);' . "\n";
		for ($i = 0; $i < $Nb; ++$i) {
			$decrypt_block .= '$s' . $i . ' = $in[' . ($i + 1) . '] ^ ' . $dw[++$wc] . ';' . "\n";
		}

		for ($round = 1; $round < $Nr; ++$round) {
			list($s, $e) = [$e, $s];
			for ($i = 0; $i < $Nb; ++$i) {
				$decrypt_block .=
					'$' . $e . $i . ' =
                    $dt0[($' . $s . $i						. ' >> 24) & 0xff] ^
                    $dt1[($' . $s . (($Nb + $i - $c[1]) % $Nb) . ' >> 16) & 0xff] ^
                    $dt2[($' . $s . (($Nb + $i - $c[2]) % $Nb) . ' >>  8) & 0xff] ^
                    $dt3[ $' . $s . (($Nb + $i - $c[3]) % $Nb) . '        & 0xff] ^
                    ' . $dw[++$wc] . ";\n";
			}
		}

		for ($i = 0; $i < $Nb; ++$i) {
			$decrypt_block .=
				'$' . $e . $i . ' =
                 $isbox[ $' . $e . $i . '        & 0xff]        |
                ($isbox[($' . $e . $i . ' >>  8) & 0xff] <<  8) |
                ($isbox[($' . $e . $i . ' >> 16) & 0xff] << 16) |
                ($isbox[($' . $e . $i . ' >> 24) & 0xff] << 24);' . "\n";
		}
		$decrypt_block .= '$in = pack("N*"' . "\n";
		for ($i = 0; $i < $Nb; ++$i) {
			$decrypt_block .= ',
                ($' . $e . $i .						' & ' . ((int)0xFF000000) . ') ^
                ($' . $e . (($Nb + $i - $c[1]) % $Nb) . ' &         0x00FF0000   ) ^
                ($' . $e . (($Nb + $i - $c[2]) % $Nb) . ' &         0x0000FF00   ) ^
                ($' . $e . (($Nb + $i - $c[3]) % $Nb) . ' &         0x000000FF   ) ^
                ' . $dw[$i] . "\n";
		}
		$decrypt_block .= ');';

		$this->inline_crypt = $this->createInlineCryptFunction(
			[
				'init_crypt'	=> 'static $tables; static $invtables;',
				'init_encrypt'	=> $init_encrypt,
				'init_decrypt'	=> $init_decrypt,
				'encrypt_block' => $encrypt_block,
				'decrypt_block' => $decrypt_block
			]
		);
	}

	public function encrypt($plaintext)
	{
		$this->setup();

		switch ($this->engine) {
			case self::ENGINE_LIBSODIUM:
				$this->newtag = sodium_crypto_aead_aes256gcm_encrypt($plaintext, $this->aad, $this->nonce, $this->key);
				return Strings::shift($this->newtag, strlen($plaintext));
			case self::ENGINE_OPENSSL_GCM:
				return openssl_encrypt(
					$plaintext,
					'aes-' . $this->getKeyLength() . '-gcm',
					$this->key,
					OPENSSL_RAW_DATA,
					$this->nonce,
					$this->newtag,
					$this->aad
				);
		}

		return parent::encrypt($plaintext);
	}

	public function decrypt($ciphertext)
	{
		$this->setup();

		switch ($this->engine) {
			case self::ENGINE_LIBSODIUM:
				if ($this->oldtag === false) {
					throw new InsufficientSetupException('Authentication Tag has not been set');
				}
				if (strlen($this->oldtag) != 16) {
					break;
				}
				$plaintext = sodium_crypto_aead_aes256gcm_decrypt($ciphertext . $this->oldtag, $this->aad, $this->nonce, $this->key);
				if ($plaintext === false) {
					$this->oldtag = false;
					throw new BadDecryptionException('Error decrypting ciphertext with libsodium');
				}
				return $plaintext;
			case self::ENGINE_OPENSSL_GCM:
				if ($this->oldtag === false) {
					throw new InsufficientSetupException('Authentication Tag has not been set');
				}
				$plaintext = openssl_decrypt(
					$ciphertext,
					'aes-' . $this->getKeyLength() . '-gcm',
					$this->key,
					OPENSSL_RAW_DATA,
					$this->nonce,
					$this->oldtag,
					$this->aad
				);
				if ($plaintext === false) {
					$this->oldtag = false;
					throw new BadDecryptionException('Error decrypting ciphertext with OpenSSL');
				}
				return $plaintext;
		}

		return parent::decrypt($ciphertext);
	}
}
}

namespace phpseclib3\Crypt {

class AES extends Rijndael
{

	public function setBlockLength($length)
	{
		throw new \BadMethodCallException('The block length cannot be set for AES.');
	}

	public function setKeyLength($length)
	{
		switch ($length) {
			case 128:
			case 192:
			case 256:
				break;
			default:
				throw new \LengthException('Key of size ' . $length . ' not supported by this algorithm. Only keys of sizes 128, 192 or 256 supported');
		}
		parent::setKeyLength($length);
	}

	public function setKey($key)
	{
		switch (strlen($key)) {
			case 16:
			case 24:
			case 32:
				break;
			default:
				throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16, 24 or 32 supported');
		}

		parent::setKey($key);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\BlockCipher;

class Blowfish extends BlockCipher
{

	protected $block_size = 8;

	protected $cipher_name_mcrypt = 'blowfish';

	protected $cfb_init_len = 500;

	private static $sbox = [
		0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96, 0xba7c9045, 0xf12c7f99,
		0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e,
		0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
		0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e, 0x6c9e0e8b, 0xb01e8a3e,
		0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
		0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
		0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381, 0x28958677,
		0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032,
		0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
		0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
		0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98,
		0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
		0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d,
		0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7,
		0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
		0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c, 0xcc814544, 0xaf5ebd09,
		0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb,
		0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
		0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760, 0x53317b48, 0x3e00df82,
		0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
		0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
		0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341, 0xcee4c6e8,
		0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4, 0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0,
		0xd08ed1d0, 0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
		0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
		0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9,
		0x165fa266, 0x80957705, 0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
		0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af,
		0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5,
		0x83260376, 0x6295cfa9, 0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
		0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f, 0xf296ec6b, 0x2a0dd915,
		0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a,

		0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
		0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29, 0xa0591340, 0xe4183a3e,
		0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
		0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
		0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec, 0x5716f2b8,
		0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff, 0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd,
		0xd19113f9, 0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
		0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
		0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af,
		0xde9a771f, 0xd9930810, 0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
		0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2,
		0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd,
		0x71dff89e, 0x10314e55, 0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
		0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3,
		0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a,
		0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
		0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883, 0xb17f37d1, 0x018cff28,
		0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
		0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
		0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab, 0xb2f3846e,
		0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50, 0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7,
		0x9b540b19, 0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
		0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
		0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73,
		0x5d4a14d9, 0xe864b7e3, 0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
		0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250,
		0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285,
		0x095bbf00, 0xad19489d, 0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
		0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460, 0x4085f2a7, 0xce77326e,
		0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc,
		0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
		0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a, 0xe6e39f2b, 0xdb83adf7,

		0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
		0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
		0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0, 0x31cb8504,
		0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a, 0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb,
		0x68dc1462, 0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
		0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
		0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb,
		0xfb0af54e, 0xd8feb397, 0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
		0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c,
		0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc,
		0x07f9c9ee, 0x41041f0f, 0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
		0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e, 0xaf664fd1, 0xcad18115,
		0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728,
		0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
		0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8, 0x991be14c, 0xdb6e6b0d,
		0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
		0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
		0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc, 0x782ef11c,
		0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350, 0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9,
		0x44421659, 0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
		0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
		0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61,
		0x4e58f48f, 0xf2ddfda2, 0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
		0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c,
		0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633,
		0xe85a1f02, 0x09f0be8c, 0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
		0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa, 0xa002b5c4, 0x0de6d027,
		0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62,
		0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
		0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9, 0x1ac15bb4, 0xd39eb8fc,
		0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
		0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,

		0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740, 0x99bc9bbe,
		0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b, 0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4,
		0x5748ab2f, 0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
		0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
		0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6,
		0x2826a2f9, 0xa73a3ae1, 0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
		0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51,
		0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c,
		0xe029ac71, 0xe019a5e6, 0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
		0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba, 0x03a16125, 0x0564f0bd,
		0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319,
		0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
		0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce, 0x5121ce64, 0x774fbe32,
		0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
		0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
		0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae, 0xbf3c6f47,
		0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370, 0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d,
		0x4040cb08, 0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
		0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
		0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7,
		0x1a908749, 0xd44fbd9a, 0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
		0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525,
		0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442,
		0xe0ec6e0e, 0x1698db3b, 0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
		0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e, 0xe60b6f47, 0x0fe3f11d,
		0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299,
		0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
		0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a, 0x45e1d006, 0xc3f27b9a,
		0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
		0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
		0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4, 0xd6ebe1f9,
		0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f, 0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
	];

	private static $parray = [
		0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
		0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
		0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
	];

	private $bctx;

	private $kl;

	protected $key_length = 16;

	public function __construct($mode)
	{
		parent::__construct($mode);

		if ($this->mode == self::MODE_STREAM) {
			throw new \InvalidArgumentException('Block ciphers cannot be ran in stream mode');
		}
	}

	public function setKeyLength($length)
	{
		if ($length < 32 || $length > 448) {
				throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys of sizes between 32 and 448 bits are supported');
		}

		$this->key_length = $length >> 3;

		parent::setKeyLength($length);
	}

	protected function isValidEngineHelper($engine)
	{
		if ($engine == self::ENGINE_OPENSSL) {
			if ($this->key_length < 16) {
				return false;
			}

			if (defined('OPENSSL_VERSION_TEXT') && version_compare(preg_replace('#OpenSSL (\d+\.\d+\.\d+) .*#', '$1', OPENSSL_VERSION_TEXT), '3.0.1', '>=')) {
				return false;
			}
			$this->cipher_name_openssl_ecb = 'bf-ecb';
			$this->cipher_name_openssl = 'bf-' . $this->openssl_translate_mode();
		}

		return parent::isValidEngineHelper($engine);
	}

	protected function setupKey()
	{
		if (isset($this->kl['key']) && $this->key === $this->kl['key']) {

			return;
		}
		$this->kl = ['key' => $this->key];

		$this->bctx = [
			'p'	=> [],
			'sb' => self::$sbox
		];

		$key	= array_values(unpack('C*', $this->key));
		$keyl = count($key);

		for ($j = 0, $i = 0; $i < 18; ++$i) {

			for ($data = 0, $k = 0; $k < 4; ++$k) {
				$data = ($data << 8) | $key[$j];
				if (++$j >= $keyl) {
					$j = 0;
				}
			}
			$this->bctx['p'][] = self::$parray[$i] ^ intval($data);
		}

		$data = "\0\0\0\0\0\0\0\0";
		for ($i = 0; $i < 18; $i += 2) {
			list($l, $r) = array_values(unpack('N*', $data = $this->encryptBlock($data)));
			$this->bctx['p'][$i	] = $l;
			$this->bctx['p'][$i + 1] = $r;
		}
		for ($i = 0; $i < 0x400; $i += 0x100) {
			for ($j = 0; $j < 256; $j += 2) {
				list($l, $r) = array_values(unpack('N*', $data = $this->encryptBlock($data)));
				$this->bctx['sb'][$i | $j] = $l;
				$this->bctx['sb'][$i | ($j + 1)] = $r;
			}
		}
	}

	protected static function initialize_static_variables()
	{
		if (is_float(self::$sbox[0x200])) {
			self::$sbox = array_map('intval', self::$sbox);
			self::$parray = array_map('intval', self::$parray);
		}

		parent::initialize_static_variables();
	}

	private static function bcrypt_hash($sha2pass, $sha2salt)
	{
		$p = self::$parray;
		$sbox = self::$sbox;

		$cdata = array_values(unpack('N*', 'OxychromaticBlowfishSwatDynamite'));
		$sha2pass = array_values(unpack('N*', $sha2pass));
		$sha2salt = array_values(unpack('N*', $sha2salt));

		self::expandstate($sha2salt, $sha2pass, $sbox, $p);
		for ($i = 0; $i < 64; $i++) {
			self::expand0state($sha2salt, $sbox, $p);
			self::expand0state($sha2pass, $sbox, $p);
		}

		for ($i = 0; $i < 64; $i++) {
			for ($j = 0; $j < 8; $j += 2) {
				list($cdata[$j], $cdata[$j + 1]) = self::encryptBlockHelperFast($cdata[$j], $cdata[$j + 1], $sbox, $p);
			}
		}

		return pack('V*', ...$cdata);
	}

	public static function bcrypt_pbkdf($pass, $salt, $keylen, $rounds)
	{
		self::initialize_static_variables();

		if (PHP_INT_SIZE == 4) {
			throw new \RuntimeException('bcrypt is far too slow to be practical on 32-bit versions of PHP');
		}

		$sha2pass = hash('sha512', $pass, true);
		$results = [];
		$count = 1;
		while (32 * count($results) < $keylen) {
			$countsalt = $salt . pack('N', $count++);
			$sha2salt = hash('sha512', $countsalt, true);
			$out = $tmpout = self::bcrypt_hash($sha2pass, $sha2salt);
			for ($i = 1; $i < $rounds; $i++) {
				$sha2salt = hash('sha512', $tmpout, true);
				$tmpout = self::bcrypt_hash($sha2pass, $sha2salt);
				$out ^= $tmpout;
			}
			$results[] = $out;
		}
		$output = '';
		for ($i = 0; $i < 32; $i++) {
			foreach ($results as $result) {
				$output .= $result[$i];
			}
		}
		return substr($output, 0, $keylen);
	}

	private static function expand0state(array $key, array &$sbox, array &$p)
	{

		$p = [
			$p[0] ^ $key[0],
			$p[1] ^ $key[1],
			$p[2] ^ $key[2],
			$p[3] ^ $key[3],
			$p[4] ^ $key[4],
			$p[5] ^ $key[5],
			$p[6] ^ $key[6],
			$p[7] ^ $key[7],
			$p[8] ^ $key[8],
			$p[9] ^ $key[9],
			$p[10] ^ $key[10],
			$p[11] ^ $key[11],
			$p[12] ^ $key[12],
			$p[13] ^ $key[13],
			$p[14] ^ $key[14],
			$p[15] ^ $key[15],
			$p[16] ^ $key[0],
			$p[17] ^ $key[1]
		];

		list( $p[0],	$p[1]) = self::encryptBlockHelperFast(	 0,		0, $sbox, $p);
		list( $p[2],	$p[3]) = self::encryptBlockHelperFast($p[ 0], $p[ 1], $sbox, $p);
		list( $p[4],	$p[5]) = self::encryptBlockHelperFast($p[ 2], $p[ 3], $sbox, $p);
		list( $p[6],	$p[7]) = self::encryptBlockHelperFast($p[ 4], $p[ 5], $sbox, $p);
		list( $p[8],	$p[9]) = self::encryptBlockHelperFast($p[ 6], $p[ 7], $sbox, $p);
		list($p[10], $p[11]) = self::encryptBlockHelperFast($p[ 8], $p[ 9], $sbox, $p);
		list($p[12], $p[13]) = self::encryptBlockHelperFast($p[10], $p[11], $sbox, $p);
		list($p[14], $p[15]) = self::encryptBlockHelperFast($p[12], $p[13], $sbox, $p);
		list($p[16], $p[17]) = self::encryptBlockHelperFast($p[14], $p[15], $sbox, $p);

		list($sbox[0], $sbox[1]) = self::encryptBlockHelperFast($p[16], $p[17], $sbox, $p);
		for ($i = 2; $i < 1024; $i += 2) {
			list($sbox[$i], $sbox[$i + 1]) = self::encryptBlockHelperFast($sbox[$i - 2], $sbox[$i - 1], $sbox, $p);
		}
	}

	private static function expandstate(array $data, array $key, array &$sbox, array &$p)
	{
		$p = [
			$p[0] ^ $key[0],
			$p[1] ^ $key[1],
			$p[2] ^ $key[2],
			$p[3] ^ $key[3],
			$p[4] ^ $key[4],
			$p[5] ^ $key[5],
			$p[6] ^ $key[6],
			$p[7] ^ $key[7],
			$p[8] ^ $key[8],
			$p[9] ^ $key[9],
			$p[10] ^ $key[10],
			$p[11] ^ $key[11],
			$p[12] ^ $key[12],
			$p[13] ^ $key[13],
			$p[14] ^ $key[14],
			$p[15] ^ $key[15],
			$p[16] ^ $key[0],
			$p[17] ^ $key[1]
		];

		list( $p[0],	$p[1]) = self::encryptBlockHelperFast($data[ 0]		 , $data[ 1]		 , $sbox, $p);
		list( $p[2],	$p[3]) = self::encryptBlockHelperFast($data[ 2] ^ $p[ 0], $data[ 3] ^ $p[ 1], $sbox, $p);
		list( $p[4],	$p[5]) = self::encryptBlockHelperFast($data[ 4] ^ $p[ 2], $data[ 5] ^ $p[ 3], $sbox, $p);
		list( $p[6],	$p[7]) = self::encryptBlockHelperFast($data[ 6] ^ $p[ 4], $data[ 7] ^ $p[ 5], $sbox, $p);
		list( $p[8],	$p[9]) = self::encryptBlockHelperFast($data[ 8] ^ $p[ 6], $data[ 9] ^ $p[ 7], $sbox, $p);
		list($p[10], $p[11]) = self::encryptBlockHelperFast($data[10] ^ $p[ 8], $data[11] ^ $p[ 9], $sbox, $p);
		list($p[12], $p[13]) = self::encryptBlockHelperFast($data[12] ^ $p[10], $data[13] ^ $p[11], $sbox, $p);
		list($p[14], $p[15]) = self::encryptBlockHelperFast($data[14] ^ $p[12], $data[15] ^ $p[13], $sbox, $p);
		list($p[16], $p[17]) = self::encryptBlockHelperFast($data[ 0] ^ $p[14], $data[ 1] ^ $p[15], $sbox, $p);

		list($sbox[0], $sbox[1]) = self::encryptBlockHelperFast($data[2] ^ $p[16], $data[3] ^ $p[17], $sbox, $p);
		for ($i = 2, $j = 4; $i < 1024; $i += 2, $j = ($j + 2) % 16) {
			list($sbox[$i], $sbox[$i + 1]) = self::encryptBlockHelperFast($data[$j] ^ $sbox[$i - 2], $data[$j + 1] ^ $sbox[$i - 1], $sbox, $p);
		}
	}

	protected function encryptBlock($in)
	{
		$p = $this->bctx['p'];

		$sb = $this->bctx['sb'];

		$in = unpack('N*', $in);
		$l = $in[1];
		$r = $in[2];

		list($r, $l) = PHP_INT_SIZE == 4 ?
			self::encryptBlockHelperSlow($l, $r, $sb, $p) :
			self::encryptBlockHelperFast($l, $r, $sb, $p);

		return pack("N*", $r, $l);
	}

	private static function encryptBlockHelperFast($x0, $x1, array $sbox, array $p)
	{
		$x0 ^= $p[0];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[1];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[2];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[3];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[4];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[5];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[6];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[7];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[8];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[9];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[10];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[11];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[12];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[13];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[14];
		$x1 ^= ((($sbox[($x0 & 0xFF000000) >> 24] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[15];
		$x0 ^= ((($sbox[($x1 & 0xFF000000) >> 24] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[16];

		return [$x1 & 0xFFFFFFFF ^ $p[17], $x0 & 0xFFFFFFFF];
	}

	private static function encryptBlockHelperSlow($x0, $x1, array $sbox, array $p)
	{

		$x0 ^= $p[0];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[1];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[2];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[3];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[4];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[5];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[6];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[7];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[8];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[9];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[10];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[11];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[12];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[13];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[14];
		$x1 ^= self::safe_intval((self::safe_intval($sbox[(($x0 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x0 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x0 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x0 & 0xFF)]) ^ $p[15];
		$x0 ^= self::safe_intval((self::safe_intval($sbox[(($x1 & -16777216) >> 24) & 0xFF] + $sbox[0x100 | (($x1 & 0xFF0000) >> 16)]) ^ $sbox[0x200 | (($x1 & 0xFF00) >> 8)]) + $sbox[0x300 | ($x1 & 0xFF)]) ^ $p[16];

		return [$x1 ^ $p[17], $x0];
	}

	protected function decryptBlock($in)
	{
		$p = $this->bctx['p'];
		$sb = $this->bctx['sb'];

		$in = unpack('N*', $in);
		$l = $in[1];
		$r = $in[2];

		for ($i = 17; $i > 2; $i -= 2) {
			$l ^= $p[$i];
			$r ^= self::safe_intval((self::safe_intval($sb[$l >> 24 & 0xff] + $sb[0x100 + ($l >> 16 & 0xff)]) ^
					$sb[0x200 + ($l >>	8 & 0xff)]) +
					$sb[0x300 + ($l		& 0xff)]);

			$r ^= $p[$i - 1];
			$l ^= self::safe_intval((self::safe_intval($sb[$r >> 24 & 0xff] + $sb[0x100 + ($r >> 16 & 0xff)]) ^
					$sb[0x200 + ($r >>	8 & 0xff)]) +
					$sb[0x300 + ($r		& 0xff)]);
		}
		return pack('N*', $r ^ $p[0], $l ^ $p[1]);
	}

	protected function setupInlineCrypt()
	{
		$p = $this->bctx['p'];
		$init_crypt = '
            static $sb;
            if (!$sb) {
                $sb = $this->bctx["sb"];
            }
        ';

		$safeint = self::safe_intval_inline();

		$encrypt_block = '
            $in = unpack("N*", $in);
            $l = $in[1];
            $r = $in[2];
        ';
		for ($i = 0; $i < 16; $i += 2) {
			$encrypt_block .= '
                $l^= ' . $p[$i] . ';
                $r^= ' . sprintf($safeint, '(' . sprintf($safeint, '$sb[$l >> 24 & 0xff] + $sb[0x100 + ($l >> 16 & 0xff)]') . ' ^
                      $sb[0x200 + ($l >>  8 & 0xff)]) +
                      $sb[0x300 + ($l       & 0xff)]') . ';

                $r^= ' . $p[$i + 1] . ';
                $l^= ' . sprintf($safeint, '(' . sprintf($safeint, '$sb[$r >> 24 & 0xff] + $sb[0x100 + ($r >> 16 & 0xff)]') . '  ^
                      $sb[0x200 + ($r >>  8 & 0xff)]) +
                      $sb[0x300 + ($r       & 0xff)]') . ';
            ';
		}
		$encrypt_block .= '
            $in = pack("N*",
                $r ^ ' . $p[17] . ',
                $l ^ ' . $p[16] . '
            );
        ';

		$decrypt_block = '
            $in = unpack("N*", $in);
            $l = $in[1];
            $r = $in[2];
        ';

		for ($i = 17; $i > 2; $i -= 2) {
			$decrypt_block .= '
                $l^= ' . $p[$i] . ';
                $r^= ' . sprintf($safeint, '(' . sprintf($safeint, '$sb[$l >> 24 & 0xff] + $sb[0x100 + ($l >> 16 & 0xff)]') . ' ^
                      $sb[0x200 + ($l >>  8 & 0xff)]) +
                      $sb[0x300 + ($l       & 0xff)]') . ';

                $r^= ' . $p[$i - 1] . ';
                $l^= ' . sprintf($safeint, '(' . sprintf($safeint, '$sb[$r >> 24 & 0xff] + $sb[0x100 + ($r >> 16 & 0xff)]') . ' ^
                      $sb[0x200 + ($r >>  8 & 0xff)]) +
                      $sb[0x300 + ($r       & 0xff)]') . ';
            ';
		}

		$decrypt_block .= '
            $in = pack("N*",
                $r ^ ' . $p[0] . ',
                $l ^ ' . $p[1] . '
            );
        ';

		$this->inline_crypt = $this->createInlineCryptFunction(
			[
				'init_crypt'	=> $init_crypt,
				'init_encrypt'	=> '',
				'init_decrypt'	=> '',
				'encrypt_block' => $encrypt_block,
				'decrypt_block' => $decrypt_block
			]
		);
	}
}
}

namespace phpseclib3\Crypt\Common {

abstract class StreamCipher extends SymmetricKey
{

	protected $block_size = 0;

	public function __construct()
	{
		parent::__construct('stream');
	}

	public function usesIV()
	{
		return false;
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\StreamCipher;
use phpseclib3\Exception\BadDecryptionException;
use phpseclib3\Exception\InsufficientSetupException;

class Salsa20 extends StreamCipher
{

	protected $p1 = false;

	protected $p2 = false;

	protected $key_length = 32;

	const ENCRYPT = 0;

	const DECRYPT = 1;

	protected $enbuffer;

	protected $debuffer;

	protected $counter = 0;

	protected $usingGeneratedPoly1305Key = false;

	public function usesNonce()
	{
		return true;
	}

	public function setKey($key)
	{
		switch (strlen($key)) {
			case 16:
			case 32:
				break;
			default:
				throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16 or 32 are supported');
		}

		parent::setKey($key);
	}

	public function setNonce($nonce)
	{
		if (strlen($nonce) != 8) {
			throw new \LengthException('Nonce of size ' . strlen($key) . ' not supported by this algorithm. Only an 64-bit nonce is supported');
		}

		$this->nonce = $nonce;
		$this->changed = true;
		$this->setEngine();
	}

	public function setCounter($counter)
	{
		$this->counter = $counter;
		$this->setEngine();
	}

	protected function createPoly1305Key()
	{
		if ($this->nonce === false) {
			throw new InsufficientSetupException('No nonce has been defined');
		}

		if ($this->key === false) {
			throw new InsufficientSetupException('No key has been defined');
		}

		$c = clone $this;
		$c->setCounter(0);
		$c->usePoly1305 = false;
		$block = $c->encrypt(str_repeat("\0", 256));
		$this->setPoly1305Key(substr($block, 0, 32));

		if ($this->counter == 0) {
			$this->counter++;
		}
	}

	protected function setup()
	{
		if (!$this->changed) {
			return;
		}

		$this->enbuffer = $this->debuffer = ['ciphertext' => '', 'counter' => $this->counter];

		$this->changed = $this->nonIVChanged = false;

		if ($this->nonce === false) {
			throw new InsufficientSetupException('No nonce has been defined');
		}

		if ($this->key === false) {
			throw new InsufficientSetupException('No key has been defined');
		}

		if ($this->usePoly1305 && !isset($this->poly1305Key)) {
			$this->usingGeneratedPoly1305Key = true;
			$this->createPoly1305Key();
		}

		$key = $this->key;
		if (strlen($key) == 16) {
			$constant = 'expand 16-byte k';
			$key .= $key;
		} else {
			$constant = 'expand 32-byte k';
		}

		$this->p1 = substr($constant, 0, 4) .
					substr($key, 0, 16) .
					substr($constant, 4, 4) .
					$this->nonce .
					"\0\0\0\0";
		$this->p2 = substr($constant, 8, 4) .
					substr($key, 16, 16) .
					substr($constant, 12, 4);
	}

	protected function setupKey()
	{

	}

	public function encrypt($plaintext)
	{
		$ciphertext = $this->crypt($plaintext, self::ENCRYPT);
		if (isset($this->poly1305Key)) {
			$this->newtag = $this->poly1305($ciphertext);
		}
		return $ciphertext;
	}

	public function decrypt($ciphertext)
	{
		if (isset($this->poly1305Key)) {
			if ($this->oldtag === false) {
				throw new InsufficientSetupException('Authentication Tag has not been set');
			}
			$newtag = $this->poly1305($ciphertext);
			if ($this->oldtag != substr($newtag, 0, strlen($this->oldtag))) {
				$this->oldtag = false;
				throw new BadDecryptionException('Derived authentication tag and supplied authentication tag do not match');
			}
			$this->oldtag = false;
		}

		return $this->crypt($ciphertext, self::DECRYPT);
	}

	protected function encryptBlock($in)
	{

	}

	protected function decryptBlock($in)
	{

	}

	private function crypt($text, $mode)
	{
		$this->setup();
		if (!$this->continuousBuffer) {
			if ($this->engine == self::ENGINE_OPENSSL) {
				$iv = pack('V', $this->counter) . $this->p2;
				return openssl_encrypt(
					$text,
					$this->cipher_name_openssl,
					$this->key,
					OPENSSL_RAW_DATA,
					$iv
				);
			}
			$i = $this->counter;
			$blocks = str_split($text, 64);
			foreach ($blocks as &$block) {
				$block ^= static::salsa20($this->p1 . pack('V', $i++) . $this->p2);
			}
			unset($block);
			return implode('', $blocks);
		}

		if ($mode == self::ENCRYPT) {
			$buffer = &$this->enbuffer;
		} else {
			$buffer = &$this->debuffer;
		}
		if (!strlen($buffer['ciphertext'])) {
			$ciphertext = '';
		} else {
			$ciphertext = $text ^ Strings::shift($buffer['ciphertext'], strlen($text));
			$text = substr($text, strlen($ciphertext));
			if (!strlen($text)) {
				return $ciphertext;
			}
		}

		$overflow = strlen($text) % 64;
		if ($overflow) {
			$text2 = Strings::pop($text, $overflow);
			if ($this->engine == self::ENGINE_OPENSSL) {
				$iv = pack('V', $buffer['counter']) . $this->p2;

				$buffer['counter'] += (strlen($text) >> 6) + 1;
				$encrypted = openssl_encrypt(
					$text . str_repeat("\0", 64),
					$this->cipher_name_openssl,
					$this->key,
					OPENSSL_RAW_DATA,
					$iv
				);
				$temp = Strings::pop($encrypted, 64);
			} else {
				$blocks = str_split($text, 64);
				if (strlen($text)) {
					foreach ($blocks as &$block) {
						$block ^= static::salsa20($this->p1 . pack('V', $buffer['counter']++) . $this->p2);
					}
					unset($block);
				}
				$encrypted = implode('', $blocks);
				$temp = static::salsa20($this->p1 . pack('V', $buffer['counter']++) . $this->p2);
			}
			$ciphertext .= $encrypted . ($text2 ^ $temp);
			$buffer['ciphertext'] = substr($temp, $overflow);
		} elseif (!strlen($buffer['ciphertext'])) {
			if ($this->engine == self::ENGINE_OPENSSL) {
				$iv = pack('V', $buffer['counter']) . $this->p2;
				$buffer['counter'] += (strlen($text) >> 6);
				$ciphertext .= openssl_encrypt(
					$text,
					$this->cipher_name_openssl,
					$this->key,
					OPENSSL_RAW_DATA,
					$iv
				);
			} else {
				$blocks = str_split($text, 64);
				foreach ($blocks as &$block) {
					$block ^= static::salsa20($this->p1 . pack('V', $buffer['counter']++) . $this->p2);
				}
				unset($block);
				$ciphertext .= implode('', $blocks);
			}
		}

		return $ciphertext;
	}

	protected static function leftRotate($x, $n)
	{
		if (PHP_INT_SIZE == 8) {
			$r1 = $x << $n;
			$r1 &= 0xFFFFFFFF;
			$r2 = ($x & 0xFFFFFFFF) >> (32 - $n);
		} else {
			$x = (int) $x;
			$r1 = $x << $n;
			$r2 = $x >> (32 - $n);
			$r2 &= (1 << $n) - 1;
		}
		return $r1 | $r2;
	}

	protected static function quarterRound(&$a, &$b, &$c, &$d)
	{
		$b ^= self::leftRotate($a + $d, 7);
		$c ^= self::leftRotate($b + $a, 9);
		$d ^= self::leftRotate($c + $b, 13);
		$a ^= self::leftRotate($d + $c, 18);
	}

	protected static function doubleRound(&$x0, &$x1, &$x2, &$x3, &$x4, &$x5, &$x6, &$x7, &$x8, &$x9, &$x10, &$x11, &$x12, &$x13, &$x14, &$x15)
	{

		static::quarterRound($x0, $x4, $x8, $x12);
		static::quarterRound($x5, $x9, $x13, $x1);
		static::quarterRound($x10, $x14, $x2, $x6);
		static::quarterRound($x15, $x3, $x7, $x11);

		static::quarterRound($x0, $x1, $x2, $x3);
		static::quarterRound($x5, $x6, $x7, $x4);
		static::quarterRound($x10, $x11, $x8, $x9);
		static::quarterRound($x15, $x12, $x13, $x14);
	}

	protected static function salsa20($x)
	{
		$z = $x = unpack('V*', $x);
		for ($i = 0; $i < 10; $i++) {
			static::doubleRound($z[1], $z[2], $z[3], $z[4], $z[5], $z[6], $z[7], $z[8], $z[9], $z[10], $z[11], $z[12], $z[13], $z[14], $z[15], $z[16]);
		}

		for ($i = 1; $i <= 16; $i++) {
			$x[$i] += $z[$i];
		}

		return pack('V*', ...$x);
	}

	protected function poly1305($ciphertext)
	{
		if (!$this->usingGeneratedPoly1305Key) {
			return parent::poly1305($this->aad . $ciphertext);
		} else {

			return parent::poly1305(
				self::nullPad128($this->aad) .
				self::nullPad128($ciphertext) .
				pack('V', strlen($this->aad)) . "\0\0\0\0" .
				pack('V', strlen($ciphertext)) . "\0\0\0\0"
			);
		}
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Exception\BadDecryptionException;
use phpseclib3\Exception\InsufficientSetupException;

class ChaCha20 extends Salsa20
{

	protected $cipher_name_openssl = 'chacha20';

	protected function isValidEngineHelper($engine)
	{
		switch ($engine) {
			case self::ENGINE_LIBSODIUM:

				return function_exists('sodium_crypto_aead_chacha20poly1305_ietf_encrypt') &&
						$this->key_length == 32 &&
						(($this->usePoly1305 && !isset($this->poly1305Key) && $this->counter == 0) || $this->counter == 1) &&
						!$this->continuousBuffer;
			case self::ENGINE_OPENSSL:

				if ($this->key_length != 32) {
					return false;
				}
		}

		return parent::isValidEngineHelper($engine);
	}

	public function encrypt($plaintext)
	{
		$this->setup();

		if ($this->engine == self::ENGINE_LIBSODIUM) {
			return $this->encrypt_with_libsodium($plaintext);
		}

		return parent::encrypt($plaintext);
	}

	public function decrypt($ciphertext)
	{
		$this->setup();

		if ($this->engine == self::ENGINE_LIBSODIUM) {
			return $this->decrypt_with_libsodium($ciphertext);
		}

		return parent::decrypt($ciphertext);
	}

	private function encrypt_with_libsodium($plaintext)
	{
		$params = [$plaintext, $this->aad, $this->nonce, $this->key];
		$ciphertext = strlen($this->nonce) == 8 ?
			sodium_crypto_aead_chacha20poly1305_encrypt(...$params) :
			sodium_crypto_aead_chacha20poly1305_ietf_encrypt(...$params);
		if (!$this->usePoly1305) {
			return substr($ciphertext, 0, strlen($plaintext));
		}

		$newciphertext = substr($ciphertext, 0, strlen($plaintext));

		$this->newtag = $this->usingGeneratedPoly1305Key && strlen($this->nonce) == 12 ?
			substr($ciphertext, strlen($plaintext)) :
			$this->poly1305($newciphertext);

		return $newciphertext;
	}

	private function decrypt_with_libsodium($ciphertext)
	{
		$params = [$ciphertext, $this->aad, $this->nonce, $this->key];

		if (isset($this->poly1305Key)) {
			if ($this->oldtag === false) {
				throw new InsufficientSetupException('Authentication Tag has not been set');
			}
			if ($this->usingGeneratedPoly1305Key && strlen($this->nonce) == 12) {
				$plaintext = sodium_crypto_aead_chacha20poly1305_ietf_decrypt(...$params);
				$this->oldtag = false;
				if ($plaintext === false) {
					throw new BadDecryptionException('Derived authentication tag and supplied authentication tag do not match');
				}
				return $plaintext;
			}
			$newtag = $this->poly1305($ciphertext);
			if ($this->oldtag != substr($newtag, 0, strlen($this->oldtag))) {
				$this->oldtag = false;
				throw new BadDecryptionException('Derived authentication tag and supplied authentication tag do not match');
			}
			$this->oldtag = false;
		}

		$plaintext = strlen($this->nonce) == 8 ?
			sodium_crypto_aead_chacha20poly1305_encrypt(...$params) :
			sodium_crypto_aead_chacha20poly1305_ietf_encrypt(...$params);

		return substr($plaintext, 0, strlen($ciphertext));
	}

	public function setNonce($nonce)
	{
		if (!is_string($nonce)) {
			throw new \UnexpectedValueException('The nonce should be a string');
		}

		switch (strlen($nonce)) {
			case 8:
			case 12:
				break;
			default:
				throw new \LengthException('Nonce of size ' . strlen($nonce) . ' not supported by this algorithm. Only 64-bit nonces or 96-bit nonces are supported');
		}

		$this->nonce = $nonce;
		$this->changed = true;
		$this->setEngine();
	}

	protected function setup()
	{
		if (!$this->changed) {
			return;
		}

		$this->enbuffer = $this->debuffer = ['ciphertext' => '', 'counter' => $this->counter];

		$this->changed = $this->nonIVChanged = false;

		if ($this->nonce === false) {
			throw new InsufficientSetupException('No nonce has been defined');
		}

		if ($this->key === false) {
			throw new InsufficientSetupException('No key has been defined');
		}

		if ($this->usePoly1305 && !isset($this->poly1305Key)) {
			$this->usingGeneratedPoly1305Key = true;
			if ($this->engine == self::ENGINE_LIBSODIUM) {
				return;
			}
			$this->createPoly1305Key();
		}

		$key = $this->key;
		if (strlen($key) == 16) {
			$constant = 'expand 16-byte k';
			$key .= $key;
		} else {
			$constant = 'expand 32-byte k';
		}

		$this->p1 = $constant . $key;
		$this->p2 = $this->nonce;
		if (strlen($this->nonce) == 8) {
			$this->p2 = "\0\0\0\0" . $this->p2;
		}
	}

	protected static function quarterRound(&$a, &$b, &$c, &$d)
	{

		$a+= $b; $d = self::leftRotate(intval($d) ^ intval($a), 16);
		$c+= $d; $b = self::leftRotate(intval($b) ^ intval($c), 12);
		$a+= $b; $d = self::leftRotate(intval($d) ^ intval($a), 8);
		$c+= $d; $b = self::leftRotate(intval($b) ^ intval($c), 7);

	}

	protected static function doubleRound(&$x0, &$x1, &$x2, &$x3, &$x4, &$x5, &$x6, &$x7, &$x8, &$x9, &$x10, &$x11, &$x12, &$x13, &$x14, &$x15)
	{

		static::quarterRound($x0, $x4, $x8, $x12);
		static::quarterRound($x1, $x5, $x9, $x13);
		static::quarterRound($x2, $x6, $x10, $x14);
		static::quarterRound($x3, $x7, $x11, $x15);

		static::quarterRound($x0, $x5, $x10, $x15);
		static::quarterRound($x1, $x6, $x11, $x12);
		static::quarterRound($x2, $x7, $x8, $x13);
		static::quarterRound($x3, $x4, $x9, $x14);
	}

	protected static function salsa20($x)
	{
		list(, $x0, $x1, $x2, $x3, $x4, $x5, $x6, $x7, $x8, $x9, $x10, $x11, $x12, $x13, $x14, $x15) = unpack('V*', $x);
		$z0 = $x0;
		$z1 = $x1;
		$z2 = $x2;
		$z3 = $x3;
		$z4 = $x4;
		$z5 = $x5;
		$z6 = $x6;
		$z7 = $x7;
		$z8 = $x8;
		$z9 = $x9;
		$z10 = $x10;
		$z11 = $x11;
		$z12 = $x12;
		$z13 = $x13;
		$z14 = $x14;
		$z15 = $x15;

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 16);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 12);
		$x0+= $x4; $x12 = self::leftRotate(intval($x12) ^ intval($x0), 8);
		$x8+= $x12; $x4 = self::leftRotate(intval($x4) ^ intval($x8), 7);

		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 16);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 12);
		$x1+= $x5; $x13 = self::leftRotate(intval($x13) ^ intval($x1), 8);
		$x9+= $x13; $x5 = self::leftRotate(intval($x5) ^ intval($x9), 7);

		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 16);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 12);
		$x2+= $x6; $x14 = self::leftRotate(intval($x14) ^ intval($x2), 8);
		$x10+= $x14; $x6 = self::leftRotate(intval($x6) ^ intval($x10), 7);

		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 16);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 12);
		$x3+= $x7; $x15 = self::leftRotate(intval($x15) ^ intval($x3), 8);
		$x11+= $x15; $x7 = self::leftRotate(intval($x7) ^ intval($x11), 7);

		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 16);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 12);
		$x0+= $x5; $x15 = self::leftRotate(intval($x15) ^ intval($x0), 8);
		$x10+= $x15; $x5 = self::leftRotate(intval($x5) ^ intval($x10), 7);

		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 16);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 12);
		$x1+= $x6; $x12 = self::leftRotate(intval($x12) ^ intval($x1), 8);
		$x11+= $x12; $x6 = self::leftRotate(intval($x6) ^ intval($x11), 7);

		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 16);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 12);
		$x2+= $x7; $x13 = self::leftRotate(intval($x13) ^ intval($x2), 8);
		$x8+= $x13; $x7 = self::leftRotate(intval($x7) ^ intval($x8), 7);

		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 16);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 12);
		$x3+= $x4; $x14 = self::leftRotate(intval($x14) ^ intval($x3), 8);
		$x9+= $x14; $x4 = self::leftRotate(intval($x4) ^ intval($x9), 7);

		$x0 += $z0;
		$x1 += $z1;
		$x2 += $z2;
		$x3 += $z3;
		$x4 += $z4;
		$x5 += $z5;
		$x6 += $z6;
		$x7 += $z7;
		$x8 += $z8;
		$x9 += $z9;
		$x10 += $z10;
		$x11 += $z11;
		$x12 += $z12;
		$x13 += $z13;
		$x14 += $z14;
		$x15 += $z15;

		return pack('V*', $x0, $x1, $x2, $x3, $x4, $x5, $x6, $x7, $x8, $x9, $x10, $x11, $x12, $x13, $x14, $x15);
	}
}
}

namespace phpseclib3\Crypt\Common {

use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\RSA;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

abstract class AsymmetricKey
{

	protected static $zero;

	protected static $one;

	protected $format;

	protected $hash;

	private $hmac;

	private static $plugins = [];

	private static $invisiblePlugins = [];

	protected static $engines = [];

	private $comment;

	abstract public function toString($type, array $options = []);

	protected function __construct()
	{
		self::initialize_static_variables();

		$this->hash = new Hash('sha256');
		$this->hmac = new Hash('sha256');
	}

	protected static function initialize_static_variables()
	{
		if (!isset(self::$zero)) {
			self::$zero = new BigInteger(0);
			self::$one = new BigInteger(1);
		}

		self::loadPlugins('Keys');
		if (static::ALGORITHM != 'RSA' && static::ALGORITHM != 'DH') {
			self::loadPlugins('Signature');
		}
	}

	public static function load($key, $password = false)
	{
		self::initialize_static_variables();

		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('load() should not be called from final classes (' . static::class . ')');
		}

		$components = false;
		foreach (self::$plugins[static::ALGORITHM]['Keys'] as $format) {
			if (isset(self::$invisiblePlugins[static::ALGORITHM]) && in_array($format, self::$invisiblePlugins[static::ALGORITHM])) {
				continue;
			}
			try {
				$components = $format::load($key, $password);
			} catch (\Exception $e) {
				$components = false;
			}
			if ($components !== false) {
				break;
			}
		}

		if ($components === false) {
			throw new NoKeyLoadedException('Unable to read key');
		}

		$components['format'] = $format;
		$components['secret'] = isset($components['secret']) ? $components['secret'] : '';
		$comment = isset($components['comment']) ? $components['comment'] : null;
		$new = static::onLoad($components);
		$new->format = $format;
		$new->comment = $comment;
		return $new instanceof PrivateKey ?
			$new->withPassword($password) :
			$new;
	}

	public static function loadPrivateKey($key, $password = '')
	{
		$key = self::load($key, $password);
		if (!$key instanceof PrivateKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a private key');
		}
		return $key;
	}

	public static function loadPublicKey($key)
	{
		$key = self::load($key);
		if (!$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a public key');
		}
		return $key;
	}

	public static function loadParameters($key)
	{
		$key = self::load($key);
		if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a parameter');
		}
		return $key;
	}

	public static function loadFormat($type, $key, $password = false)
	{
		self::initialize_static_variables();

		$components = false;
		$format = strtolower($type);
		if (isset(self::$plugins[static::ALGORITHM]['Keys'][$format])) {
			$format = self::$plugins[static::ALGORITHM]['Keys'][$format];
			$components = $format::load($key, $password);
		}

		if ($components === false) {
			throw new NoKeyLoadedException('Unable to read key');
		}

		$components['format'] = $format;
		$components['secret'] = isset($components['secret']) ? $components['secret'] : '';

		$new = static::onLoad($components);
		$new->format = $format;
		return $new instanceof PrivateKey ?
			$new->withPassword($password) :
			$new;
	}

	public static function loadPrivateKeyFormat($type, $key, $password = false)
	{
		$key = self::loadFormat($type, $key, $password);
		if (!$key instanceof PrivateKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a private key');
		}
		return $key;
	}

	public static function loadPublicKeyFormat($type, $key)
	{
		$key = self::loadFormat($type, $key);
		if (!$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a public key');
		}
		return $key;
	}

	public static function loadParametersFormat($type, $key)
	{
		$key = self::loadFormat($type, $key);
		if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a parameter');
		}
		return $key;
	}

	protected static function validatePlugin($format, $type, $method = null)
	{
		$type = strtolower($type);
		if (!isset(self::$plugins[static::ALGORITHM][$format][$type])) {
			throw new UnsupportedFormatException("$type is not a supported format");
		}
		$type = self::$plugins[static::ALGORITHM][$format][$type];
		if (isset($method) && !method_exists($type, $method)) {
			throw new UnsupportedFormatException("$type does not implement $method");
		}

		return $type;
	}

	private static function loadPlugins($format)
	{
		if (!isset(self::$plugins[static::ALGORITHM][$format])) {
			self::$plugins = array (
	'DH' =>
	array (
	'Keys' =>
	array (
		'pkcs1' => 'phpseclib3\\Crypt\\DH\\Formats\\Keys\\PKCS1',
		'pkcs8' => 'phpseclib3\\Crypt\\DH\\Formats\\Keys\\PKCS8',
	),
	),
	'DSA' =>
	array (
	'Keys' =>
	array (
		'openssh' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\OpenSSH',
		'pkcs1' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\PKCS1',
		'pkcs8' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\PKCS8',
		'putty' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\PuTTY',
		'raw' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\Raw',
		'xml' => 'phpseclib3\\Crypt\\DSA\\Formats\\Keys\\XML',
	),
	'Signature' =>
	array (
		'asn1' => 'phpseclib3\\Crypt\\DSA\\Formats\\Signature\\ASN1',
		'raw' => 'phpseclib3\\Crypt\\DSA\\Formats\\Signature\\Raw',
		'ssh2' => 'phpseclib3\\Crypt\\DSA\\Formats\\Signature\\SSH2',
	),
	),
	'EC' =>
	array (
	'Keys' =>
	array (
		'jwk' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\JWK',
		'libsodium' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\libsodium',
		'montgomeryprivate' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\MontgomeryPrivate',
		'montgomerypublic' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\MontgomeryPublic',
		'openssh' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\OpenSSH',
		'pkcs1' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\PKCS1',
		'pkcs8' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\PKCS8',
		'putty' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\PuTTY',
		'xml' => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\XML',
	),
	'Signature' =>
	array (
		'asn1' => 'phpseclib3\\Crypt\\EC\\Formats\\Signature\\ASN1',
		'ieee' => 'phpseclib3\\Crypt\\EC\\Formats\\Signature\\IEEE',
		'raw' => 'phpseclib3\\Crypt\\EC\\Formats\\Signature\\Raw',
		'ssh2' => 'phpseclib3\\Crypt\\EC\\Formats\\Signature\\SSH2',
	),
	),
	'RSA' =>
	array (
	'Keys' =>
	array (
		'jwk' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\JWK',
		'msblob' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\MSBLOB',
		'openssh' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\OpenSSH',
		'pkcs1' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\PKCS1',
		'pkcs8' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\PKCS8',
		'pss' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\PSS',
		'putty' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\PuTTY',
		'raw' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\Raw',
		'xml' => 'phpseclib3\\Crypt\\RSA\\Formats\\Keys\\XML',
	),
	),
);
			self::$invisiblePlugins = array (
	'EC' =>
	array (
	0 => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\libsodium',
	1 => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\MontgomeryPrivate',
	2 => 'phpseclib3\\Crypt\\EC\\Formats\\Keys\\MontgomeryPublic',
	),
);
		}
	}

private static function __ORIG__loadPlugins($format)
	{
		if (!isset(self::$plugins[static::ALGORITHM][$format])) {
			self::$plugins[static::ALGORITHM][$format] = [];
			foreach (new \DirectoryIterator(__DIR__ . '/../' . static::ALGORITHM . '/Formats/' . $format . '/') as $file) {
				if ($file->getExtension() != 'php') {
					continue;
				}
				$name = $file->getBasename('.php');
				if ($name[0] == '.') {
					continue;
				}
				$type = 'phpseclib3\Crypt\\' . static::ALGORITHM . '\\Formats\\' . $format . '\\' . $name;
				$reflect = new \ReflectionClass($type);
				if ($reflect->isTrait()) {
					continue;
				}
				self::$plugins[static::ALGORITHM][$format][strtolower($name)] = $type;
				if ($reflect->hasConstant('IS_INVISIBLE')) {
					self::$invisiblePlugins[static::ALGORITHM][] = $type;
				}
			}
		}
	}

	public static function getSupportedKeyFormats()
	{
		self::initialize_static_variables();

		return self::$plugins[static::ALGORITHM]['Keys'];
	}

	public static function addFileFormat($fullname)
	{
		self::initialize_static_variables();

		if (class_exists($fullname)) {
			$meta = new \ReflectionClass($fullname);
			$shortname = $meta->getShortName();
			self::$plugins[static::ALGORITHM]['Keys'][strtolower($shortname)] = $fullname;
			if ($meta->hasConstant('IS_INVISIBLE')) {
				self::$invisiblePlugins[static::ALGORITHM][] = strtolower($shortname);
			}
		}
	}

	public function getLoadedFormat()
	{
		if (empty($this->format)) {
			throw new NoKeyLoadedException('This key was created with createKey - it was not loaded with load. Therefore there is no "loaded format"');
		}

		$meta = new \ReflectionClass($this->format);
		return $meta->getShortName();
	}

	public function getComment()
	{
		return $this->comment;
	}

	public static function useBestEngine()
	{
		static::$engines = [
			'PHP' => true,
			'OpenSSL' => extension_loaded('openssl'),

			'libsodium' => function_exists('sodium_crypto_sign_keypair')
		];

		return static::$engines;
	}

	public static function useInternalEngine()
	{
		static::$engines = [
			'PHP' => true,
			'OpenSSL' => false,
			'libsodium' => false
		];
	}

	public function __toString()
	{
		return $this->toString('PKCS8');
	}

	public function withHash($hash)
	{
		$new = clone $this;

		$new->hash = new Hash($hash);
		$new->hmac = new Hash($hash);

		return $new;
	}

	public function getHash()
	{
		return clone $this->hash;
	}

	protected function computek($h1)
	{
		$v = str_repeat("\1", strlen($h1));

		$k = str_repeat("\0", strlen($h1));

		$x = $this->int2octets($this->x);
		$h1 = $this->bits2octets($h1);

		$this->hmac->setKey($k);
		$k = $this->hmac->hash($v . "\0" . $x . $h1);
		$this->hmac->setKey($k);
		$v = $this->hmac->hash($v);
		$k = $this->hmac->hash($v . "\1" . $x . $h1);
		$this->hmac->setKey($k);
		$v = $this->hmac->hash($v);

		$qlen = $this->q->getLengthInBytes();

		while (true) {
			$t = '';
			while (strlen($t) < $qlen) {
				$v = $this->hmac->hash($v);
				$t = $t . $v;
			}
			$k = $this->bits2int($t);

			if (!$k->equals(self::$zero) && $k->compare($this->q) < 0) {
				break;
			}
			$k = $this->hmac->hash($v . "\0");
			$this->hmac->setKey($k);
			$v = $this->hmac->hash($v);
		}

		return $k;
	}

	private function int2octets($v)
	{
		$out = $v->toBytes();
		$rolen = $this->q->getLengthInBytes();
		if (strlen($out) < $rolen) {
			return str_pad($out, $rolen, "\0", STR_PAD_LEFT);
		} elseif (strlen($out) > $rolen) {
			return substr($out, -$rolen);
		} else {
			return $out;
		}
	}

	protected function bits2int($in)
	{
		$v = new BigInteger($in, 256);
		$vlen = strlen($in) << 3;
		$qlen = $this->q->getLength();
		if ($vlen > $qlen) {
			return $v->bitwise_rightShift($vlen - $qlen);
		}
		return $v;
	}

	private function bits2octets($in)
	{
		$z1 = $this->bits2int($in);
		$z2 = $z1->subtract($this->q);
		return $z2->compare(self::$zero) < 0 ?
			$this->int2octets($z1) :
			$this->int2octets($z2);
	}
}
}

namespace phpseclib3\Crypt\Common {

interface PrivateKey
{
	public function sign($message);

	public function getPublicKey();
	public function toString($type, array $options = []);

	public function withPassword($password = false);
}
}

namespace phpseclib3\Crypt\Common {

interface PublicKey
{
	public function verify($message, $signature);

	public function toString($type, array $options = []);
	public function getFingerprint($algorithm);
}
}

namespace phpseclib3\Crypt\Common\Traits {

use phpseclib3\Crypt\Hash;

trait Fingerprint
{

	public function getFingerprint($algorithm = 'md5')
	{
		$type = self::validatePlugin('Keys', 'OpenSSH', 'savePublicKey');
		if ($type === false) {
			return false;
		}
		$key = $this->toString('OpenSSH', ['binary' => true]);
		if ($key === false) {
			return false;
		}
		switch ($algorithm) {
			case 'sha256':
				$hash = new Hash('sha256');
				$base = base64_encode($hash->hash($key));
				return substr($base, 0, strlen($base) - 1);
			case 'md5':
				return substr(chunk_split(md5($key), 2, ':'), 0, -1);
			default:
				return false;
		}
	}
}
}

namespace phpseclib3\Crypt\Common\Traits {

trait PasswordProtected
{

	private $password = false;

	public function withPassword($password = false)
	{
		$new = clone $this;
		$new->password = $password;
		return $new;
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadModeException;

class DES extends BlockCipher
{

	const ENCRYPT = 0;

	const DECRYPT = 1;

	protected $block_size = 8;

	protected $key_length = 8;

	protected $cipher_name_mcrypt = 'des';

	protected $openssl_mode_names = [
		self::MODE_ECB => 'des-ecb',
		self::MODE_CBC => 'des-cbc',
		self::MODE_CFB => 'des-cfb',
		self::MODE_OFB => 'des-ofb'

	];

	protected $cfb_init_len = 500;

	protected $des_rounds = 1;

	protected $key_length_max = 8;

	private $keys;

	private $kl;

	protected static $shuffle = [
		"\x00\x00\x00\x00\x00\x00\x00\x00", "\x00\x00\x00\x00\x00\x00\x00\xFF",
		"\x00\x00\x00\x00\x00\x00\xFF\x00", "\x00\x00\x00\x00\x00\x00\xFF\xFF",
		"\x00\x00\x00\x00\x00\xFF\x00\x00", "\x00\x00\x00\x00\x00\xFF\x00\xFF",
		"\x00\x00\x00\x00\x00\xFF\xFF\x00", "\x00\x00\x00\x00\x00\xFF\xFF\xFF",
		"\x00\x00\x00\x00\xFF\x00\x00\x00", "\x00\x00\x00\x00\xFF\x00\x00\xFF",
		"\x00\x00\x00\x00\xFF\x00\xFF\x00", "\x00\x00\x00\x00\xFF\x00\xFF\xFF",
		"\x00\x00\x00\x00\xFF\xFF\x00\x00", "\x00\x00\x00\x00\xFF\xFF\x00\xFF",
		"\x00\x00\x00\x00\xFF\xFF\xFF\x00", "\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
		"\x00\x00\x00\xFF\x00\x00\x00\x00", "\x00\x00\x00\xFF\x00\x00\x00\xFF",
		"\x00\x00\x00\xFF\x00\x00\xFF\x00", "\x00\x00\x00\xFF\x00\x00\xFF\xFF",
		"\x00\x00\x00\xFF\x00\xFF\x00\x00", "\x00\x00\x00\xFF\x00\xFF\x00\xFF",
		"\x00\x00\x00\xFF\x00\xFF\xFF\x00", "\x00\x00\x00\xFF\x00\xFF\xFF\xFF",
		"\x00\x00\x00\xFF\xFF\x00\x00\x00", "\x00\x00\x00\xFF\xFF\x00\x00\xFF",
		"\x00\x00\x00\xFF\xFF\x00\xFF\x00", "\x00\x00\x00\xFF\xFF\x00\xFF\xFF",
		"\x00\x00\x00\xFF\xFF\xFF\x00\x00", "\x00\x00\x00\xFF\xFF\xFF\x00\xFF",
		"\x00\x00\x00\xFF\xFF\xFF\xFF\x00", "\x00\x00\x00\xFF\xFF\xFF\xFF\xFF",
		"\x00\x00\xFF\x00\x00\x00\x00\x00", "\x00\x00\xFF\x00\x00\x00\x00\xFF",
		"\x00\x00\xFF\x00\x00\x00\xFF\x00", "\x00\x00\xFF\x00\x00\x00\xFF\xFF",
		"\x00\x00\xFF\x00\x00\xFF\x00\x00", "\x00\x00\xFF\x00\x00\xFF\x00\xFF",
		"\x00\x00\xFF\x00\x00\xFF\xFF\x00", "\x00\x00\xFF\x00\x00\xFF\xFF\xFF",
		"\x00\x00\xFF\x00\xFF\x00\x00\x00", "\x00\x00\xFF\x00\xFF\x00\x00\xFF",
		"\x00\x00\xFF\x00\xFF\x00\xFF\x00", "\x00\x00\xFF\x00\xFF\x00\xFF\xFF",
		"\x00\x00\xFF\x00\xFF\xFF\x00\x00", "\x00\x00\xFF\x00\xFF\xFF\x00\xFF",
		"\x00\x00\xFF\x00\xFF\xFF\xFF\x00", "\x00\x00\xFF\x00\xFF\xFF\xFF\xFF",
		"\x00\x00\xFF\xFF\x00\x00\x00\x00", "\x00\x00\xFF\xFF\x00\x00\x00\xFF",
		"\x00\x00\xFF\xFF\x00\x00\xFF\x00", "\x00\x00\xFF\xFF\x00\x00\xFF\xFF",
		"\x00\x00\xFF\xFF\x00\xFF\x00\x00", "\x00\x00\xFF\xFF\x00\xFF\x00\xFF",
		"\x00\x00\xFF\xFF\x00\xFF\xFF\x00", "\x00\x00\xFF\xFF\x00\xFF\xFF\xFF",
		"\x00\x00\xFF\xFF\xFF\x00\x00\x00", "\x00\x00\xFF\xFF\xFF\x00\x00\xFF",
		"\x00\x00\xFF\xFF\xFF\x00\xFF\x00", "\x00\x00\xFF\xFF\xFF\x00\xFF\xFF",
		"\x00\x00\xFF\xFF\xFF\xFF\x00\x00", "\x00\x00\xFF\xFF\xFF\xFF\x00\xFF",
		"\x00\x00\xFF\xFF\xFF\xFF\xFF\x00", "\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
		"\x00\xFF\x00\x00\x00\x00\x00\x00", "\x00\xFF\x00\x00\x00\x00\x00\xFF",
		"\x00\xFF\x00\x00\x00\x00\xFF\x00", "\x00\xFF\x00\x00\x00\x00\xFF\xFF",
		"\x00\xFF\x00\x00\x00\xFF\x00\x00", "\x00\xFF\x00\x00\x00\xFF\x00\xFF",
		"\x00\xFF\x00\x00\x00\xFF\xFF\x00", "\x00\xFF\x00\x00\x00\xFF\xFF\xFF",
		"\x00\xFF\x00\x00\xFF\x00\x00\x00", "\x00\xFF\x00\x00\xFF\x00\x00\xFF",
		"\x00\xFF\x00\x00\xFF\x00\xFF\x00", "\x00\xFF\x00\x00\xFF\x00\xFF\xFF",
		"\x00\xFF\x00\x00\xFF\xFF\x00\x00", "\x00\xFF\x00\x00\xFF\xFF\x00\xFF",
		"\x00\xFF\x00\x00\xFF\xFF\xFF\x00", "\x00\xFF\x00\x00\xFF\xFF\xFF\xFF",
		"\x00\xFF\x00\xFF\x00\x00\x00\x00", "\x00\xFF\x00\xFF\x00\x00\x00\xFF",
		"\x00\xFF\x00\xFF\x00\x00\xFF\x00", "\x00\xFF\x00\xFF\x00\x00\xFF\xFF",
		"\x00\xFF\x00\xFF\x00\xFF\x00\x00", "\x00\xFF\x00\xFF\x00\xFF\x00\xFF",
		"\x00\xFF\x00\xFF\x00\xFF\xFF\x00", "\x00\xFF\x00\xFF\x00\xFF\xFF\xFF",
		"\x00\xFF\x00\xFF\xFF\x00\x00\x00", "\x00\xFF\x00\xFF\xFF\x00\x00\xFF",
		"\x00\xFF\x00\xFF\xFF\x00\xFF\x00", "\x00\xFF\x00\xFF\xFF\x00\xFF\xFF",
		"\x00\xFF\x00\xFF\xFF\xFF\x00\x00", "\x00\xFF\x00\xFF\xFF\xFF\x00\xFF",
		"\x00\xFF\x00\xFF\xFF\xFF\xFF\x00", "\x00\xFF\x00\xFF\xFF\xFF\xFF\xFF",
		"\x00\xFF\xFF\x00\x00\x00\x00\x00", "\x00\xFF\xFF\x00\x00\x00\x00\xFF",
		"\x00\xFF\xFF\x00\x00\x00\xFF\x00", "\x00\xFF\xFF\x00\x00\x00\xFF\xFF",
		"\x00\xFF\xFF\x00\x00\xFF\x00\x00", "\x00\xFF\xFF\x00\x00\xFF\x00\xFF",
		"\x00\xFF\xFF\x00\x00\xFF\xFF\x00", "\x00\xFF\xFF\x00\x00\xFF\xFF\xFF",
		"\x00\xFF\xFF\x00\xFF\x00\x00\x00", "\x00\xFF\xFF\x00\xFF\x00\x00\xFF",
		"\x00\xFF\xFF\x00\xFF\x00\xFF\x00", "\x00\xFF\xFF\x00\xFF\x00\xFF\xFF",
		"\x00\xFF\xFF\x00\xFF\xFF\x00\x00", "\x00\xFF\xFF\x00\xFF\xFF\x00\xFF",
		"\x00\xFF\xFF\x00\xFF\xFF\xFF\x00", "\x00\xFF\xFF\x00\xFF\xFF\xFF\xFF",
		"\x00\xFF\xFF\xFF\x00\x00\x00\x00", "\x00\xFF\xFF\xFF\x00\x00\x00\xFF",
		"\x00\xFF\xFF\xFF\x00\x00\xFF\x00", "\x00\xFF\xFF\xFF\x00\x00\xFF\xFF",
		"\x00\xFF\xFF\xFF\x00\xFF\x00\x00", "\x00\xFF\xFF\xFF\x00\xFF\x00\xFF",
		"\x00\xFF\xFF\xFF\x00\xFF\xFF\x00", "\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF",
		"\x00\xFF\xFF\xFF\xFF\x00\x00\x00", "\x00\xFF\xFF\xFF\xFF\x00\x00\xFF",
		"\x00\xFF\xFF\xFF\xFF\x00\xFF\x00", "\x00\xFF\xFF\xFF\xFF\x00\xFF\xFF",
		"\x00\xFF\xFF\xFF\xFF\xFF\x00\x00", "\x00\xFF\xFF\xFF\xFF\xFF\x00\xFF",
		"\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00", "\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
		"\xFF\x00\x00\x00\x00\x00\x00\x00", "\xFF\x00\x00\x00\x00\x00\x00\xFF",
		"\xFF\x00\x00\x00\x00\x00\xFF\x00", "\xFF\x00\x00\x00\x00\x00\xFF\xFF",
		"\xFF\x00\x00\x00\x00\xFF\x00\x00", "\xFF\x00\x00\x00\x00\xFF\x00\xFF",
		"\xFF\x00\x00\x00\x00\xFF\xFF\x00", "\xFF\x00\x00\x00\x00\xFF\xFF\xFF",
		"\xFF\x00\x00\x00\xFF\x00\x00\x00", "\xFF\x00\x00\x00\xFF\x00\x00\xFF",
		"\xFF\x00\x00\x00\xFF\x00\xFF\x00", "\xFF\x00\x00\x00\xFF\x00\xFF\xFF",
		"\xFF\x00\x00\x00\xFF\xFF\x00\x00", "\xFF\x00\x00\x00\xFF\xFF\x00\xFF",
		"\xFF\x00\x00\x00\xFF\xFF\xFF\x00", "\xFF\x00\x00\x00\xFF\xFF\xFF\xFF",
		"\xFF\x00\x00\xFF\x00\x00\x00\x00", "\xFF\x00\x00\xFF\x00\x00\x00\xFF",
		"\xFF\x00\x00\xFF\x00\x00\xFF\x00", "\xFF\x00\x00\xFF\x00\x00\xFF\xFF",
		"\xFF\x00\x00\xFF\x00\xFF\x00\x00", "\xFF\x00\x00\xFF\x00\xFF\x00\xFF",
		"\xFF\x00\x00\xFF\x00\xFF\xFF\x00", "\xFF\x00\x00\xFF\x00\xFF\xFF\xFF",
		"\xFF\x00\x00\xFF\xFF\x00\x00\x00", "\xFF\x00\x00\xFF\xFF\x00\x00\xFF",
		"\xFF\x00\x00\xFF\xFF\x00\xFF\x00", "\xFF\x00\x00\xFF\xFF\x00\xFF\xFF",
		"\xFF\x00\x00\xFF\xFF\xFF\x00\x00", "\xFF\x00\x00\xFF\xFF\xFF\x00\xFF",
		"\xFF\x00\x00\xFF\xFF\xFF\xFF\x00", "\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF",
		"\xFF\x00\xFF\x00\x00\x00\x00\x00", "\xFF\x00\xFF\x00\x00\x00\x00\xFF",
		"\xFF\x00\xFF\x00\x00\x00\xFF\x00", "\xFF\x00\xFF\x00\x00\x00\xFF\xFF",
		"\xFF\x00\xFF\x00\x00\xFF\x00\x00", "\xFF\x00\xFF\x00\x00\xFF\x00\xFF",
		"\xFF\x00\xFF\x00\x00\xFF\xFF\x00", "\xFF\x00\xFF\x00\x00\xFF\xFF\xFF",
		"\xFF\x00\xFF\x00\xFF\x00\x00\x00", "\xFF\x00\xFF\x00\xFF\x00\x00\xFF",
		"\xFF\x00\xFF\x00\xFF\x00\xFF\x00", "\xFF\x00\xFF\x00\xFF\x00\xFF\xFF",
		"\xFF\x00\xFF\x00\xFF\xFF\x00\x00", "\xFF\x00\xFF\x00\xFF\xFF\x00\xFF",
		"\xFF\x00\xFF\x00\xFF\xFF\xFF\x00", "\xFF\x00\xFF\x00\xFF\xFF\xFF\xFF",
		"\xFF\x00\xFF\xFF\x00\x00\x00\x00", "\xFF\x00\xFF\xFF\x00\x00\x00\xFF",
		"\xFF\x00\xFF\xFF\x00\x00\xFF\x00", "\xFF\x00\xFF\xFF\x00\x00\xFF\xFF",
		"\xFF\x00\xFF\xFF\x00\xFF\x00\x00", "\xFF\x00\xFF\xFF\x00\xFF\x00\xFF",
		"\xFF\x00\xFF\xFF\x00\xFF\xFF\x00", "\xFF\x00\xFF\xFF\x00\xFF\xFF\xFF",
		"\xFF\x00\xFF\xFF\xFF\x00\x00\x00", "\xFF\x00\xFF\xFF\xFF\x00\x00\xFF",
		"\xFF\x00\xFF\xFF\xFF\x00\xFF\x00", "\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF",
		"\xFF\x00\xFF\xFF\xFF\xFF\x00\x00", "\xFF\x00\xFF\xFF\xFF\xFF\x00\xFF",
		"\xFF\x00\xFF\xFF\xFF\xFF\xFF\x00", "\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF",
		"\xFF\xFF\x00\x00\x00\x00\x00\x00", "\xFF\xFF\x00\x00\x00\x00\x00\xFF",
		"\xFF\xFF\x00\x00\x00\x00\xFF\x00", "\xFF\xFF\x00\x00\x00\x00\xFF\xFF",
		"\xFF\xFF\x00\x00\x00\xFF\x00\x00", "\xFF\xFF\x00\x00\x00\xFF\x00\xFF",
		"\xFF\xFF\x00\x00\x00\xFF\xFF\x00", "\xFF\xFF\x00\x00\x00\xFF\xFF\xFF",
		"\xFF\xFF\x00\x00\xFF\x00\x00\x00", "\xFF\xFF\x00\x00\xFF\x00\x00\xFF",
		"\xFF\xFF\x00\x00\xFF\x00\xFF\x00", "\xFF\xFF\x00\x00\xFF\x00\xFF\xFF",
		"\xFF\xFF\x00\x00\xFF\xFF\x00\x00", "\xFF\xFF\x00\x00\xFF\xFF\x00\xFF",
		"\xFF\xFF\x00\x00\xFF\xFF\xFF\x00", "\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF",
		"\xFF\xFF\x00\xFF\x00\x00\x00\x00", "\xFF\xFF\x00\xFF\x00\x00\x00\xFF",
		"\xFF\xFF\x00\xFF\x00\x00\xFF\x00", "\xFF\xFF\x00\xFF\x00\x00\xFF\xFF",
		"\xFF\xFF\x00\xFF\x00\xFF\x00\x00", "\xFF\xFF\x00\xFF\x00\xFF\x00\xFF",
		"\xFF\xFF\x00\xFF\x00\xFF\xFF\x00", "\xFF\xFF\x00\xFF\x00\xFF\xFF\xFF",
		"\xFF\xFF\x00\xFF\xFF\x00\x00\x00", "\xFF\xFF\x00\xFF\xFF\x00\x00\xFF",
		"\xFF\xFF\x00\xFF\xFF\x00\xFF\x00", "\xFF\xFF\x00\xFF\xFF\x00\xFF\xFF",
		"\xFF\xFF\x00\xFF\xFF\xFF\x00\x00", "\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF",
		"\xFF\xFF\x00\xFF\xFF\xFF\xFF\x00", "\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF",
		"\xFF\xFF\xFF\x00\x00\x00\x00\x00", "\xFF\xFF\xFF\x00\x00\x00\x00\xFF",
		"\xFF\xFF\xFF\x00\x00\x00\xFF\x00", "\xFF\xFF\xFF\x00\x00\x00\xFF\xFF",
		"\xFF\xFF\xFF\x00\x00\xFF\x00\x00", "\xFF\xFF\xFF\x00\x00\xFF\x00\xFF",
		"\xFF\xFF\xFF\x00\x00\xFF\xFF\x00", "\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF",
		"\xFF\xFF\xFF\x00\xFF\x00\x00\x00", "\xFF\xFF\xFF\x00\xFF\x00\x00\xFF",
		"\xFF\xFF\xFF\x00\xFF\x00\xFF\x00", "\xFF\xFF\xFF\x00\xFF\x00\xFF\xFF",
		"\xFF\xFF\xFF\x00\xFF\xFF\x00\x00", "\xFF\xFF\xFF\x00\xFF\xFF\x00\xFF",
		"\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00", "\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF",
		"\xFF\xFF\xFF\xFF\x00\x00\x00\x00", "\xFF\xFF\xFF\xFF\x00\x00\x00\xFF",
		"\xFF\xFF\xFF\xFF\x00\x00\xFF\x00", "\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF",
		"\xFF\xFF\xFF\xFF\x00\xFF\x00\x00", "\xFF\xFF\xFF\xFF\x00\xFF\x00\xFF",
		"\xFF\xFF\xFF\xFF\x00\xFF\xFF\x00", "\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF",
		"\xFF\xFF\xFF\xFF\xFF\x00\x00\x00", "\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF",
		"\xFF\xFF\xFF\xFF\xFF\x00\xFF\x00", "\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF",
		"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00", "\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF",
		"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00", "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	];

	protected static $ipmap = [
		0x00, 0x10, 0x01, 0x11, 0x20, 0x30, 0x21, 0x31,
		0x02, 0x12, 0x03, 0x13, 0x22, 0x32, 0x23, 0x33,
		0x40, 0x50, 0x41, 0x51, 0x60, 0x70, 0x61, 0x71,
		0x42, 0x52, 0x43, 0x53, 0x62, 0x72, 0x63, 0x73,
		0x04, 0x14, 0x05, 0x15, 0x24, 0x34, 0x25, 0x35,
		0x06, 0x16, 0x07, 0x17, 0x26, 0x36, 0x27, 0x37,
		0x44, 0x54, 0x45, 0x55, 0x64, 0x74, 0x65, 0x75,
		0x46, 0x56, 0x47, 0x57, 0x66, 0x76, 0x67, 0x77,
		0x80, 0x90, 0x81, 0x91, 0xA0, 0xB0, 0xA1, 0xB1,
		0x82, 0x92, 0x83, 0x93, 0xA2, 0xB2, 0xA3, 0xB3,
		0xC0, 0xD0, 0xC1, 0xD1, 0xE0, 0xF0, 0xE1, 0xF1,
		0xC2, 0xD2, 0xC3, 0xD3, 0xE2, 0xF2, 0xE3, 0xF3,
		0x84, 0x94, 0x85, 0x95, 0xA4, 0xB4, 0xA5, 0xB5,
		0x86, 0x96, 0x87, 0x97, 0xA6, 0xB6, 0xA7, 0xB7,
		0xC4, 0xD4, 0xC5, 0xD5, 0xE4, 0xF4, 0xE5, 0xF5,
		0xC6, 0xD6, 0xC7, 0xD7, 0xE6, 0xF6, 0xE7, 0xF7,
		0x08, 0x18, 0x09, 0x19, 0x28, 0x38, 0x29, 0x39,
		0x0A, 0x1A, 0x0B, 0x1B, 0x2A, 0x3A, 0x2B, 0x3B,
		0x48, 0x58, 0x49, 0x59, 0x68, 0x78, 0x69, 0x79,
		0x4A, 0x5A, 0x4B, 0x5B, 0x6A, 0x7A, 0x6B, 0x7B,
		0x0C, 0x1C, 0x0D, 0x1D, 0x2C, 0x3C, 0x2D, 0x3D,
		0x0E, 0x1E, 0x0F, 0x1F, 0x2E, 0x3E, 0x2F, 0x3F,
		0x4C, 0x5C, 0x4D, 0x5D, 0x6C, 0x7C, 0x6D, 0x7D,
		0x4E, 0x5E, 0x4F, 0x5F, 0x6E, 0x7E, 0x6F, 0x7F,
		0x88, 0x98, 0x89, 0x99, 0xA8, 0xB8, 0xA9, 0xB9,
		0x8A, 0x9A, 0x8B, 0x9B, 0xAA, 0xBA, 0xAB, 0xBB,
		0xC8, 0xD8, 0xC9, 0xD9, 0xE8, 0xF8, 0xE9, 0xF9,
		0xCA, 0xDA, 0xCB, 0xDB, 0xEA, 0xFA, 0xEB, 0xFB,
		0x8C, 0x9C, 0x8D, 0x9D, 0xAC, 0xBC, 0xAD, 0xBD,
		0x8E, 0x9E, 0x8F, 0x9F, 0xAE, 0xBE, 0xAF, 0xBF,
		0xCC, 0xDC, 0xCD, 0xDD, 0xEC, 0xFC, 0xED, 0xFD,
		0xCE, 0xDE, 0xCF, 0xDF, 0xEE, 0xFE, 0xEF, 0xFF
	];

	protected static $invipmap = [
		0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0,
		0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
		0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8,
		0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
		0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4,
		0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
		0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC,
		0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
		0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2,
		0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
		0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA,
		0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
		0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6,
		0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
		0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE,
		0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
		0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1,
		0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
		0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9,
		0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
		0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5,
		0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
		0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED,
		0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
		0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3,
		0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
		0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB,
		0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
		0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7,
		0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
		0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF,
		0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF
	];

	protected static $sbox1 = [
		0x00808200, 0x00000000, 0x00008000, 0x00808202,
		0x00808002, 0x00008202, 0x00000002, 0x00008000,
		0x00000200, 0x00808200, 0x00808202, 0x00000200,
		0x00800202, 0x00808002, 0x00800000, 0x00000002,
		0x00000202, 0x00800200, 0x00800200, 0x00008200,
		0x00008200, 0x00808000, 0x00808000, 0x00800202,
		0x00008002, 0x00800002, 0x00800002, 0x00008002,
		0x00000000, 0x00000202, 0x00008202, 0x00800000,
		0x00008000, 0x00808202, 0x00000002, 0x00808000,
		0x00808200, 0x00800000, 0x00800000, 0x00000200,
		0x00808002, 0x00008000, 0x00008200, 0x00800002,
		0x00000200, 0x00000002, 0x00800202, 0x00008202,
		0x00808202, 0x00008002, 0x00808000, 0x00800202,
		0x00800002, 0x00000202, 0x00008202, 0x00808200,
		0x00000202, 0x00800200, 0x00800200, 0x00000000,
		0x00008002, 0x00008200, 0x00000000, 0x00808002
	];

	protected static $sbox2 = [
		0x40084010, 0x40004000, 0x00004000, 0x00084010,
		0x00080000, 0x00000010, 0x40080010, 0x40004010,
		0x40000010, 0x40084010, 0x40084000, 0x40000000,
		0x40004000, 0x00080000, 0x00000010, 0x40080010,
		0x00084000, 0x00080010, 0x40004010, 0x00000000,
		0x40000000, 0x00004000, 0x00084010, 0x40080000,
		0x00080010, 0x40000010, 0x00000000, 0x00084000,
		0x00004010, 0x40084000, 0x40080000, 0x00004010,
		0x00000000, 0x00084010, 0x40080010, 0x00080000,
		0x40004010, 0x40080000, 0x40084000, 0x00004000,
		0x40080000, 0x40004000, 0x00000010, 0x40084010,
		0x00084010, 0x00000010, 0x00004000, 0x40000000,
		0x00004010, 0x40084000, 0x00080000, 0x40000010,
		0x00080010, 0x40004010, 0x40000010, 0x00080010,
		0x00084000, 0x00000000, 0x40004000, 0x00004010,
		0x40000000, 0x40080010, 0x40084010, 0x00084000
	];

	protected static $sbox3 = [
		0x00000104, 0x04010100, 0x00000000, 0x04010004,
		0x04000100, 0x00000000, 0x00010104, 0x04000100,
		0x00010004, 0x04000004, 0x04000004, 0x00010000,
		0x04010104, 0x00010004, 0x04010000, 0x00000104,
		0x04000000, 0x00000004, 0x04010100, 0x00000100,
		0x00010100, 0x04010000, 0x04010004, 0x00010104,
		0x04000104, 0x00010100, 0x00010000, 0x04000104,
		0x00000004, 0x04010104, 0x00000100, 0x04000000,
		0x04010100, 0x04000000, 0x00010004, 0x00000104,
		0x00010000, 0x04010100, 0x04000100, 0x00000000,
		0x00000100, 0x00010004, 0x04010104, 0x04000100,
		0x04000004, 0x00000100, 0x00000000, 0x04010004,
		0x04000104, 0x00010000, 0x04000000, 0x04010104,
		0x00000004, 0x00010104, 0x00010100, 0x04000004,
		0x04010000, 0x04000104, 0x00000104, 0x04010000,
		0x00010104, 0x00000004, 0x04010004, 0x00010100
	];

	protected static $sbox4 = [
		0x80401000, 0x80001040, 0x80001040, 0x00000040,
		0x00401040, 0x80400040, 0x80400000, 0x80001000,
		0x00000000, 0x00401000, 0x00401000, 0x80401040,
		0x80000040, 0x00000000, 0x00400040, 0x80400000,
		0x80000000, 0x00001000, 0x00400000, 0x80401000,
		0x00000040, 0x00400000, 0x80001000, 0x00001040,
		0x80400040, 0x80000000, 0x00001040, 0x00400040,
		0x00001000, 0x00401040, 0x80401040, 0x80000040,
		0x00400040, 0x80400000, 0x00401000, 0x80401040,
		0x80000040, 0x00000000, 0x00000000, 0x00401000,
		0x00001040, 0x00400040, 0x80400040, 0x80000000,
		0x80401000, 0x80001040, 0x80001040, 0x00000040,
		0x80401040, 0x80000040, 0x80000000, 0x00001000,
		0x80400000, 0x80001000, 0x00401040, 0x80400040,
		0x80001000, 0x00001040, 0x00400000, 0x80401000,
		0x00000040, 0x00400000, 0x00001000, 0x00401040
	];

	protected static $sbox5 = [
		0x00000080, 0x01040080, 0x01040000, 0x21000080,
		0x00040000, 0x00000080, 0x20000000, 0x01040000,
		0x20040080, 0x00040000, 0x01000080, 0x20040080,
		0x21000080, 0x21040000, 0x00040080, 0x20000000,
		0x01000000, 0x20040000, 0x20040000, 0x00000000,
		0x20000080, 0x21040080, 0x21040080, 0x01000080,
		0x21040000, 0x20000080, 0x00000000, 0x21000000,
		0x01040080, 0x01000000, 0x21000000, 0x00040080,
		0x00040000, 0x21000080, 0x00000080, 0x01000000,
		0x20000000, 0x01040000, 0x21000080, 0x20040080,
		0x01000080, 0x20000000, 0x21040000, 0x01040080,
		0x20040080, 0x00000080, 0x01000000, 0x21040000,
		0x21040080, 0x00040080, 0x21000000, 0x21040080,
		0x01040000, 0x00000000, 0x20040000, 0x21000000,
		0x00040080, 0x01000080, 0x20000080, 0x00040000,
		0x00000000, 0x20040000, 0x01040080, 0x20000080
	];

	protected static $sbox6 = [
		0x10000008, 0x10200000, 0x00002000, 0x10202008,
		0x10200000, 0x00000008, 0x10202008, 0x00200000,
		0x10002000, 0x00202008, 0x00200000, 0x10000008,
		0x00200008, 0x10002000, 0x10000000, 0x00002008,
		0x00000000, 0x00200008, 0x10002008, 0x00002000,
		0x00202000, 0x10002008, 0x00000008, 0x10200008,
		0x10200008, 0x00000000, 0x00202008, 0x10202000,
		0x00002008, 0x00202000, 0x10202000, 0x10000000,
		0x10002000, 0x00000008, 0x10200008, 0x00202000,
		0x10202008, 0x00200000, 0x00002008, 0x10000008,
		0x00200000, 0x10002000, 0x10000000, 0x00002008,
		0x10000008, 0x10202008, 0x00202000, 0x10200000,
		0x00202008, 0x10202000, 0x00000000, 0x10200008,
		0x00000008, 0x00002000, 0x10200000, 0x00202008,
		0x00002000, 0x00200008, 0x10002008, 0x00000000,
		0x10202000, 0x10000000, 0x00200008, 0x10002008
	];

	protected static $sbox7 = [
		0x00100000, 0x02100001, 0x02000401, 0x00000000,
		0x00000400, 0x02000401, 0x00100401, 0x02100400,
		0x02100401, 0x00100000, 0x00000000, 0x02000001,
		0x00000001, 0x02000000, 0x02100001, 0x00000401,
		0x02000400, 0x00100401, 0x00100001, 0x02000400,
		0x02000001, 0x02100000, 0x02100400, 0x00100001,
		0x02100000, 0x00000400, 0x00000401, 0x02100401,
		0x00100400, 0x00000001, 0x02000000, 0x00100400,
		0x02000000, 0x00100400, 0x00100000, 0x02000401,
		0x02000401, 0x02100001, 0x02100001, 0x00000001,
		0x00100001, 0x02000000, 0x02000400, 0x00100000,
		0x02100400, 0x00000401, 0x00100401, 0x02100400,
		0x00000401, 0x02000001, 0x02100401, 0x02100000,
		0x00100400, 0x00000000, 0x00000001, 0x02100401,
		0x00000000, 0x00100401, 0x02100000, 0x00000400,
		0x02000001, 0x02000400, 0x00000400, 0x00100001
	];

	protected static $sbox8 = [
		0x08000820, 0x00000800, 0x00020000, 0x08020820,
		0x08000000, 0x08000820, 0x00000020, 0x08000000,
		0x00020020, 0x08020000, 0x08020820, 0x00020800,
		0x08020800, 0x00020820, 0x00000800, 0x00000020,
		0x08020000, 0x08000020, 0x08000800, 0x00000820,
		0x00020800, 0x00020020, 0x08020020, 0x08020800,
		0x00000820, 0x00000000, 0x00000000, 0x08020020,
		0x08000020, 0x08000800, 0x00020820, 0x00020000,
		0x00020820, 0x00020000, 0x08020800, 0x00000800,
		0x00000020, 0x08020020, 0x00000800, 0x00020820,
		0x08000800, 0x00000020, 0x08000020, 0x08020000,
		0x08020020, 0x08000000, 0x00020000, 0x08000820,
		0x00000000, 0x08020820, 0x00020020, 0x08000020,
		0x08020000, 0x08000800, 0x08000820, 0x00000000,
		0x08020820, 0x00020800, 0x00020800, 0x00000820,
		0x00000820, 0x00020020, 0x08000000, 0x08020800
	];

	public function __construct($mode)
	{
		parent::__construct($mode);

		if ($this->mode == self::MODE_STREAM) {
			throw new BadModeException('Block ciphers cannot be ran in stream mode');
		}
	}

	protected function isValidEngineHelper($engine)
	{
		if ($this->key_length_max == 8) {
			if ($engine == self::ENGINE_OPENSSL) {

				if (defined('OPENSSL_VERSION_TEXT') && version_compare(preg_replace('#OpenSSL (\d+\.\d+\.\d+) .*#', '$1', OPENSSL_VERSION_TEXT), '3.0.1', '>=')) {
					return false;
				}
				$this->cipher_name_openssl_ecb = 'des-ecb';
				$this->cipher_name_openssl = 'des-' . $this->openssl_translate_mode();
			}
		}

		return parent::isValidEngineHelper($engine);
	}

	public function setKey($key)
	{
		if (!($this instanceof TripleDES) && strlen($key) != 8) {
			throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of size 8 are supported');
		}

		parent::setKey($key);
	}

	protected function encryptBlock($in)
	{
		return $this->processBlock($in, self::ENCRYPT);
	}

	protected function decryptBlock($in)
	{
		return $this->processBlock($in, self::DECRYPT);
	}

	private function processBlock($block, $mode)
	{
		static $sbox1, $sbox2, $sbox3, $sbox4, $sbox5, $sbox6, $sbox7, $sbox8, $shuffleip, $shuffleinvip;
		if (!$sbox1) {
			$sbox1 = array_map('intval', self::$sbox1);
			$sbox2 = array_map('intval', self::$sbox2);
			$sbox3 = array_map('intval', self::$sbox3);
			$sbox4 = array_map('intval', self::$sbox4);
			$sbox5 = array_map('intval', self::$sbox5);
			$sbox6 = array_map('intval', self::$sbox6);
			$sbox7 = array_map('intval', self::$sbox7);
			$sbox8 = array_map('intval', self::$sbox8);

			for ($i = 0; $i < 256; ++$i) {
				$shuffleip[]	=	self::$shuffle[self::$ipmap[$i]];
				$shuffleinvip[] =	self::$shuffle[self::$invipmap[$i]];
			}
		}

		$keys	= $this->keys[$mode];
		$ki	= -1;

		$t = unpack('Nl/Nr', $block);
		list($l, $r) = [$t['l'], $t['r']];
		$block = ($shuffleip[ $r		& 0xFF] & "\x80\x80\x80\x80\x80\x80\x80\x80") |
				 ($shuffleip[($r >>	8) & 0xFF] & "\x40\x40\x40\x40\x40\x40\x40\x40") |
				 ($shuffleip[($r >> 16) & 0xFF] & "\x20\x20\x20\x20\x20\x20\x20\x20") |
				 ($shuffleip[($r >> 24) & 0xFF] & "\x10\x10\x10\x10\x10\x10\x10\x10") |
				 ($shuffleip[ $l		& 0xFF] & "\x08\x08\x08\x08\x08\x08\x08\x08") |
				 ($shuffleip[($l >>	8) & 0xFF] & "\x04\x04\x04\x04\x04\x04\x04\x04") |
				 ($shuffleip[($l >> 16) & 0xFF] & "\x02\x02\x02\x02\x02\x02\x02\x02") |
				 ($shuffleip[($l >> 24) & 0xFF] & "\x01\x01\x01\x01\x01\x01\x01\x01");

		$t = unpack('Nl/Nr', $block);
		list($l, $r) = [$t['l'], $t['r']];

		for ($des_round = 0; $des_round < $this->des_rounds; ++$des_round) {

			for ($i = 0; $i < 16; $i++) {

				$b1 = (($r >>	3) & 0x1FFFFFFF) ^ ($r << 29) ^ $keys[++$ki];
				$b2 = (($r >> 31) & 0x00000001) ^ ($r <<	1) ^ $keys[++$ki];

				$t = $sbox1[($b1 >> 24) & 0x3F] ^ $sbox2[($b2 >> 24) & 0x3F] ^
					 $sbox3[($b1 >> 16) & 0x3F] ^ $sbox4[($b2 >> 16) & 0x3F] ^
					 $sbox5[($b1 >>	8) & 0x3F] ^ $sbox6[($b2 >>	8) & 0x3F] ^
					 $sbox7[ $b1		& 0x3F] ^ $sbox8[ $b2		& 0x3F] ^ $l;

				$l = $r;
				$r = $t;
			}

			$t = $l;
			$l = $r;
			$r = $t;
		}

		return ($shuffleinvip[($r >> 24) & 0xFF] & "\x80\x80\x80\x80\x80\x80\x80\x80") |
				($shuffleinvip[($l >> 24) & 0xFF] & "\x40\x40\x40\x40\x40\x40\x40\x40") |
				($shuffleinvip[($r >> 16) & 0xFF] & "\x20\x20\x20\x20\x20\x20\x20\x20") |
				($shuffleinvip[($l >> 16) & 0xFF] & "\x10\x10\x10\x10\x10\x10\x10\x10") |
				($shuffleinvip[($r >>	8) & 0xFF] & "\x08\x08\x08\x08\x08\x08\x08\x08") |
				($shuffleinvip[($l >>	8) & 0xFF] & "\x04\x04\x04\x04\x04\x04\x04\x04") |
				($shuffleinvip[ $r		& 0xFF] & "\x02\x02\x02\x02\x02\x02\x02\x02") |
				($shuffleinvip[ $l		& 0xFF] & "\x01\x01\x01\x01\x01\x01\x01\x01");
	}

	protected function setupKey()
	{
		if (isset($this->kl['key']) && $this->key === $this->kl['key'] && $this->des_rounds === $this->kl['des_rounds']) {

			return;
		}
		$this->kl = ['key' => $this->key, 'des_rounds' => $this->des_rounds];

		static $shifts = [
			1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
		];

		static $pc1map = [
			0x00, 0x00, 0x08, 0x08, 0x04, 0x04, 0x0C, 0x0C,
			0x02, 0x02, 0x0A, 0x0A, 0x06, 0x06, 0x0E, 0x0E,
			0x10, 0x10, 0x18, 0x18, 0x14, 0x14, 0x1C, 0x1C,
			0x12, 0x12, 0x1A, 0x1A, 0x16, 0x16, 0x1E, 0x1E,
			0x20, 0x20, 0x28, 0x28, 0x24, 0x24, 0x2C, 0x2C,
			0x22, 0x22, 0x2A, 0x2A, 0x26, 0x26, 0x2E, 0x2E,
			0x30, 0x30, 0x38, 0x38, 0x34, 0x34, 0x3C, 0x3C,
			0x32, 0x32, 0x3A, 0x3A, 0x36, 0x36, 0x3E, 0x3E,
			0x40, 0x40, 0x48, 0x48, 0x44, 0x44, 0x4C, 0x4C,
			0x42, 0x42, 0x4A, 0x4A, 0x46, 0x46, 0x4E, 0x4E,
			0x50, 0x50, 0x58, 0x58, 0x54, 0x54, 0x5C, 0x5C,
			0x52, 0x52, 0x5A, 0x5A, 0x56, 0x56, 0x5E, 0x5E,
			0x60, 0x60, 0x68, 0x68, 0x64, 0x64, 0x6C, 0x6C,
			0x62, 0x62, 0x6A, 0x6A, 0x66, 0x66, 0x6E, 0x6E,
			0x70, 0x70, 0x78, 0x78, 0x74, 0x74, 0x7C, 0x7C,
			0x72, 0x72, 0x7A, 0x7A, 0x76, 0x76, 0x7E, 0x7E,
			0x80, 0x80, 0x88, 0x88, 0x84, 0x84, 0x8C, 0x8C,
			0x82, 0x82, 0x8A, 0x8A, 0x86, 0x86, 0x8E, 0x8E,
			0x90, 0x90, 0x98, 0x98, 0x94, 0x94, 0x9C, 0x9C,
			0x92, 0x92, 0x9A, 0x9A, 0x96, 0x96, 0x9E, 0x9E,
			0xA0, 0xA0, 0xA8, 0xA8, 0xA4, 0xA4, 0xAC, 0xAC,
			0xA2, 0xA2, 0xAA, 0xAA, 0xA6, 0xA6, 0xAE, 0xAE,
			0xB0, 0xB0, 0xB8, 0xB8, 0xB4, 0xB4, 0xBC, 0xBC,
			0xB2, 0xB2, 0xBA, 0xBA, 0xB6, 0xB6, 0xBE, 0xBE,
			0xC0, 0xC0, 0xC8, 0xC8, 0xC4, 0xC4, 0xCC, 0xCC,
			0xC2, 0xC2, 0xCA, 0xCA, 0xC6, 0xC6, 0xCE, 0xCE,
			0xD0, 0xD0, 0xD8, 0xD8, 0xD4, 0xD4, 0xDC, 0xDC,
			0xD2, 0xD2, 0xDA, 0xDA, 0xD6, 0xD6, 0xDE, 0xDE,
			0xE0, 0xE0, 0xE8, 0xE8, 0xE4, 0xE4, 0xEC, 0xEC,
			0xE2, 0xE2, 0xEA, 0xEA, 0xE6, 0xE6, 0xEE, 0xEE,
			0xF0, 0xF0, 0xF8, 0xF8, 0xF4, 0xF4, 0xFC, 0xFC,
			0xF2, 0xF2, 0xFA, 0xFA, 0xF6, 0xF6, 0xFE, 0xFE
		];

		static $pc2mapc1 = [
			0x00000000, 0x00000400, 0x00200000, 0x00200400,
			0x00000001, 0x00000401, 0x00200001, 0x00200401,
			0x02000000, 0x02000400, 0x02200000, 0x02200400,
			0x02000001, 0x02000401, 0x02200001, 0x02200401
		];
		static $pc2mapc2 = [
			0x00000000, 0x00000800, 0x08000000, 0x08000800,
			0x00010000, 0x00010800, 0x08010000, 0x08010800,
			0x00000000, 0x00000800, 0x08000000, 0x08000800,
			0x00010000, 0x00010800, 0x08010000, 0x08010800,
			0x00000100, 0x00000900, 0x08000100, 0x08000900,
			0x00010100, 0x00010900, 0x08010100, 0x08010900,
			0x00000100, 0x00000900, 0x08000100, 0x08000900,
			0x00010100, 0x00010900, 0x08010100, 0x08010900,
			0x00000010, 0x00000810, 0x08000010, 0x08000810,
			0x00010010, 0x00010810, 0x08010010, 0x08010810,
			0x00000010, 0x00000810, 0x08000010, 0x08000810,
			0x00010010, 0x00010810, 0x08010010, 0x08010810,
			0x00000110, 0x00000910, 0x08000110, 0x08000910,
			0x00010110, 0x00010910, 0x08010110, 0x08010910,
			0x00000110, 0x00000910, 0x08000110, 0x08000910,
			0x00010110, 0x00010910, 0x08010110, 0x08010910,
			0x00040000, 0x00040800, 0x08040000, 0x08040800,
			0x00050000, 0x00050800, 0x08050000, 0x08050800,
			0x00040000, 0x00040800, 0x08040000, 0x08040800,
			0x00050000, 0x00050800, 0x08050000, 0x08050800,
			0x00040100, 0x00040900, 0x08040100, 0x08040900,
			0x00050100, 0x00050900, 0x08050100, 0x08050900,
			0x00040100, 0x00040900, 0x08040100, 0x08040900,
			0x00050100, 0x00050900, 0x08050100, 0x08050900,
			0x00040010, 0x00040810, 0x08040010, 0x08040810,
			0x00050010, 0x00050810, 0x08050010, 0x08050810,
			0x00040010, 0x00040810, 0x08040010, 0x08040810,
			0x00050010, 0x00050810, 0x08050010, 0x08050810,
			0x00040110, 0x00040910, 0x08040110, 0x08040910,
			0x00050110, 0x00050910, 0x08050110, 0x08050910,
			0x00040110, 0x00040910, 0x08040110, 0x08040910,
			0x00050110, 0x00050910, 0x08050110, 0x08050910,
			0x01000000, 0x01000800, 0x09000000, 0x09000800,
			0x01010000, 0x01010800, 0x09010000, 0x09010800,
			0x01000000, 0x01000800, 0x09000000, 0x09000800,
			0x01010000, 0x01010800, 0x09010000, 0x09010800,
			0x01000100, 0x01000900, 0x09000100, 0x09000900,
			0x01010100, 0x01010900, 0x09010100, 0x09010900,
			0x01000100, 0x01000900, 0x09000100, 0x09000900,
			0x01010100, 0x01010900, 0x09010100, 0x09010900,
			0x01000010, 0x01000810, 0x09000010, 0x09000810,
			0x01010010, 0x01010810, 0x09010010, 0x09010810,
			0x01000010, 0x01000810, 0x09000010, 0x09000810,
			0x01010010, 0x01010810, 0x09010010, 0x09010810,
			0x01000110, 0x01000910, 0x09000110, 0x09000910,
			0x01010110, 0x01010910, 0x09010110, 0x09010910,
			0x01000110, 0x01000910, 0x09000110, 0x09000910,
			0x01010110, 0x01010910, 0x09010110, 0x09010910,
			0x01040000, 0x01040800, 0x09040000, 0x09040800,
			0x01050000, 0x01050800, 0x09050000, 0x09050800,
			0x01040000, 0x01040800, 0x09040000, 0x09040800,
			0x01050000, 0x01050800, 0x09050000, 0x09050800,
			0x01040100, 0x01040900, 0x09040100, 0x09040900,
			0x01050100, 0x01050900, 0x09050100, 0x09050900,
			0x01040100, 0x01040900, 0x09040100, 0x09040900,
			0x01050100, 0x01050900, 0x09050100, 0x09050900,
			0x01040010, 0x01040810, 0x09040010, 0x09040810,
			0x01050010, 0x01050810, 0x09050010, 0x09050810,
			0x01040010, 0x01040810, 0x09040010, 0x09040810,
			0x01050010, 0x01050810, 0x09050010, 0x09050810,
			0x01040110, 0x01040910, 0x09040110, 0x09040910,
			0x01050110, 0x01050910, 0x09050110, 0x09050910,
			0x01040110, 0x01040910, 0x09040110, 0x09040910,
			0x01050110, 0x01050910, 0x09050110, 0x09050910
		];
		static $pc2mapc3 = [
			0x00000000, 0x00000004, 0x00001000, 0x00001004,
			0x00000000, 0x00000004, 0x00001000, 0x00001004,
			0x10000000, 0x10000004, 0x10001000, 0x10001004,
			0x10000000, 0x10000004, 0x10001000, 0x10001004,
			0x00000020, 0x00000024, 0x00001020, 0x00001024,
			0x00000020, 0x00000024, 0x00001020, 0x00001024,
			0x10000020, 0x10000024, 0x10001020, 0x10001024,
			0x10000020, 0x10000024, 0x10001020, 0x10001024,
			0x00080000, 0x00080004, 0x00081000, 0x00081004,
			0x00080000, 0x00080004, 0x00081000, 0x00081004,
			0x10080000, 0x10080004, 0x10081000, 0x10081004,
			0x10080000, 0x10080004, 0x10081000, 0x10081004,
			0x00080020, 0x00080024, 0x00081020, 0x00081024,
			0x00080020, 0x00080024, 0x00081020, 0x00081024,
			0x10080020, 0x10080024, 0x10081020, 0x10081024,
			0x10080020, 0x10080024, 0x10081020, 0x10081024,
			0x20000000, 0x20000004, 0x20001000, 0x20001004,
			0x20000000, 0x20000004, 0x20001000, 0x20001004,
			0x30000000, 0x30000004, 0x30001000, 0x30001004,
			0x30000000, 0x30000004, 0x30001000, 0x30001004,
			0x20000020, 0x20000024, 0x20001020, 0x20001024,
			0x20000020, 0x20000024, 0x20001020, 0x20001024,
			0x30000020, 0x30000024, 0x30001020, 0x30001024,
			0x30000020, 0x30000024, 0x30001020, 0x30001024,
			0x20080000, 0x20080004, 0x20081000, 0x20081004,
			0x20080000, 0x20080004, 0x20081000, 0x20081004,
			0x30080000, 0x30080004, 0x30081000, 0x30081004,
			0x30080000, 0x30080004, 0x30081000, 0x30081004,
			0x20080020, 0x20080024, 0x20081020, 0x20081024,
			0x20080020, 0x20080024, 0x20081020, 0x20081024,
			0x30080020, 0x30080024, 0x30081020, 0x30081024,
			0x30080020, 0x30080024, 0x30081020, 0x30081024,
			0x00000002, 0x00000006, 0x00001002, 0x00001006,
			0x00000002, 0x00000006, 0x00001002, 0x00001006,
			0x10000002, 0x10000006, 0x10001002, 0x10001006,
			0x10000002, 0x10000006, 0x10001002, 0x10001006,
			0x00000022, 0x00000026, 0x00001022, 0x00001026,
			0x00000022, 0x00000026, 0x00001022, 0x00001026,
			0x10000022, 0x10000026, 0x10001022, 0x10001026,
			0x10000022, 0x10000026, 0x10001022, 0x10001026,
			0x00080002, 0x00080006, 0x00081002, 0x00081006,
			0x00080002, 0x00080006, 0x00081002, 0x00081006,
			0x10080002, 0x10080006, 0x10081002, 0x10081006,
			0x10080002, 0x10080006, 0x10081002, 0x10081006,
			0x00080022, 0x00080026, 0x00081022, 0x00081026,
			0x00080022, 0x00080026, 0x00081022, 0x00081026,
			0x10080022, 0x10080026, 0x10081022, 0x10081026,
			0x10080022, 0x10080026, 0x10081022, 0x10081026,
			0x20000002, 0x20000006, 0x20001002, 0x20001006,
			0x20000002, 0x20000006, 0x20001002, 0x20001006,
			0x30000002, 0x30000006, 0x30001002, 0x30001006,
			0x30000002, 0x30000006, 0x30001002, 0x30001006,
			0x20000022, 0x20000026, 0x20001022, 0x20001026,
			0x20000022, 0x20000026, 0x20001022, 0x20001026,
			0x30000022, 0x30000026, 0x30001022, 0x30001026,
			0x30000022, 0x30000026, 0x30001022, 0x30001026,
			0x20080002, 0x20080006, 0x20081002, 0x20081006,
			0x20080002, 0x20080006, 0x20081002, 0x20081006,
			0x30080002, 0x30080006, 0x30081002, 0x30081006,
			0x30080002, 0x30080006, 0x30081002, 0x30081006,
			0x20080022, 0x20080026, 0x20081022, 0x20081026,
			0x20080022, 0x20080026, 0x20081022, 0x20081026,
			0x30080022, 0x30080026, 0x30081022, 0x30081026,
			0x30080022, 0x30080026, 0x30081022, 0x30081026
		];
		static $pc2mapc4 = [
			0x00000000, 0x00100000, 0x00000008, 0x00100008,
			0x00000200, 0x00100200, 0x00000208, 0x00100208,
			0x00000000, 0x00100000, 0x00000008, 0x00100008,
			0x00000200, 0x00100200, 0x00000208, 0x00100208,
			0x04000000, 0x04100000, 0x04000008, 0x04100008,
			0x04000200, 0x04100200, 0x04000208, 0x04100208,
			0x04000000, 0x04100000, 0x04000008, 0x04100008,
			0x04000200, 0x04100200, 0x04000208, 0x04100208,
			0x00002000, 0x00102000, 0x00002008, 0x00102008,
			0x00002200, 0x00102200, 0x00002208, 0x00102208,
			0x00002000, 0x00102000, 0x00002008, 0x00102008,
			0x00002200, 0x00102200, 0x00002208, 0x00102208,
			0x04002000, 0x04102000, 0x04002008, 0x04102008,
			0x04002200, 0x04102200, 0x04002208, 0x04102208,
			0x04002000, 0x04102000, 0x04002008, 0x04102008,
			0x04002200, 0x04102200, 0x04002208, 0x04102208,
			0x00000000, 0x00100000, 0x00000008, 0x00100008,
			0x00000200, 0x00100200, 0x00000208, 0x00100208,
			0x00000000, 0x00100000, 0x00000008, 0x00100008,
			0x00000200, 0x00100200, 0x00000208, 0x00100208,
			0x04000000, 0x04100000, 0x04000008, 0x04100008,
			0x04000200, 0x04100200, 0x04000208, 0x04100208,
			0x04000000, 0x04100000, 0x04000008, 0x04100008,
			0x04000200, 0x04100200, 0x04000208, 0x04100208,
			0x00002000, 0x00102000, 0x00002008, 0x00102008,
			0x00002200, 0x00102200, 0x00002208, 0x00102208,
			0x00002000, 0x00102000, 0x00002008, 0x00102008,
			0x00002200, 0x00102200, 0x00002208, 0x00102208,
			0x04002000, 0x04102000, 0x04002008, 0x04102008,
			0x04002200, 0x04102200, 0x04002208, 0x04102208,
			0x04002000, 0x04102000, 0x04002008, 0x04102008,
			0x04002200, 0x04102200, 0x04002208, 0x04102208,
			0x00020000, 0x00120000, 0x00020008, 0x00120008,
			0x00020200, 0x00120200, 0x00020208, 0x00120208,
			0x00020000, 0x00120000, 0x00020008, 0x00120008,
			0x00020200, 0x00120200, 0x00020208, 0x00120208,
			0x04020000, 0x04120000, 0x04020008, 0x04120008,
			0x04020200, 0x04120200, 0x04020208, 0x04120208,
			0x04020000, 0x04120000, 0x04020008, 0x04120008,
			0x04020200, 0x04120200, 0x04020208, 0x04120208,
			0x00022000, 0x00122000, 0x00022008, 0x00122008,
			0x00022200, 0x00122200, 0x00022208, 0x00122208,
			0x00022000, 0x00122000, 0x00022008, 0x00122008,
			0x00022200, 0x00122200, 0x00022208, 0x00122208,
			0x04022000, 0x04122000, 0x04022008, 0x04122008,
			0x04022200, 0x04122200, 0x04022208, 0x04122208,
			0x04022000, 0x04122000, 0x04022008, 0x04122008,
			0x04022200, 0x04122200, 0x04022208, 0x04122208,
			0x00020000, 0x00120000, 0x00020008, 0x00120008,
			0x00020200, 0x00120200, 0x00020208, 0x00120208,
			0x00020000, 0x00120000, 0x00020008, 0x00120008,
			0x00020200, 0x00120200, 0x00020208, 0x00120208,
			0x04020000, 0x04120000, 0x04020008, 0x04120008,
			0x04020200, 0x04120200, 0x04020208, 0x04120208,
			0x04020000, 0x04120000, 0x04020008, 0x04120008,
			0x04020200, 0x04120200, 0x04020208, 0x04120208,
			0x00022000, 0x00122000, 0x00022008, 0x00122008,
			0x00022200, 0x00122200, 0x00022208, 0x00122208,
			0x00022000, 0x00122000, 0x00022008, 0x00122008,
			0x00022200, 0x00122200, 0x00022208, 0x00122208,
			0x04022000, 0x04122000, 0x04022008, 0x04122008,
			0x04022200, 0x04122200, 0x04022208, 0x04122208,
			0x04022000, 0x04122000, 0x04022008, 0x04122008,
			0x04022200, 0x04122200, 0x04022208, 0x04122208
		];
		static $pc2mapd1 = [
			0x00000000, 0x00000001, 0x08000000, 0x08000001,
			0x00200000, 0x00200001, 0x08200000, 0x08200001,
			0x00000002, 0x00000003, 0x08000002, 0x08000003,
			0x00200002, 0x00200003, 0x08200002, 0x08200003
		];
		static $pc2mapd2 = [
			0x00000000, 0x00100000, 0x00000800, 0x00100800,
			0x00000000, 0x00100000, 0x00000800, 0x00100800,
			0x04000000, 0x04100000, 0x04000800, 0x04100800,
			0x04000000, 0x04100000, 0x04000800, 0x04100800,
			0x00000004, 0x00100004, 0x00000804, 0x00100804,
			0x00000004, 0x00100004, 0x00000804, 0x00100804,
			0x04000004, 0x04100004, 0x04000804, 0x04100804,
			0x04000004, 0x04100004, 0x04000804, 0x04100804,
			0x00000000, 0x00100000, 0x00000800, 0x00100800,
			0x00000000, 0x00100000, 0x00000800, 0x00100800,
			0x04000000, 0x04100000, 0x04000800, 0x04100800,
			0x04000000, 0x04100000, 0x04000800, 0x04100800,
			0x00000004, 0x00100004, 0x00000804, 0x00100804,
			0x00000004, 0x00100004, 0x00000804, 0x00100804,
			0x04000004, 0x04100004, 0x04000804, 0x04100804,
			0x04000004, 0x04100004, 0x04000804, 0x04100804,
			0x00000200, 0x00100200, 0x00000A00, 0x00100A00,
			0x00000200, 0x00100200, 0x00000A00, 0x00100A00,
			0x04000200, 0x04100200, 0x04000A00, 0x04100A00,
			0x04000200, 0x04100200, 0x04000A00, 0x04100A00,
			0x00000204, 0x00100204, 0x00000A04, 0x00100A04,
			0x00000204, 0x00100204, 0x00000A04, 0x00100A04,
			0x04000204, 0x04100204, 0x04000A04, 0x04100A04,
			0x04000204, 0x04100204, 0x04000A04, 0x04100A04,
			0x00000200, 0x00100200, 0x00000A00, 0x00100A00,
			0x00000200, 0x00100200, 0x00000A00, 0x00100A00,
			0x04000200, 0x04100200, 0x04000A00, 0x04100A00,
			0x04000200, 0x04100200, 0x04000A00, 0x04100A00,
			0x00000204, 0x00100204, 0x00000A04, 0x00100A04,
			0x00000204, 0x00100204, 0x00000A04, 0x00100A04,
			0x04000204, 0x04100204, 0x04000A04, 0x04100A04,
			0x04000204, 0x04100204, 0x04000A04, 0x04100A04,
			0x00020000, 0x00120000, 0x00020800, 0x00120800,
			0x00020000, 0x00120000, 0x00020800, 0x00120800,
			0x04020000, 0x04120000, 0x04020800, 0x04120800,
			0x04020000, 0x04120000, 0x04020800, 0x04120800,
			0x00020004, 0x00120004, 0x00020804, 0x00120804,
			0x00020004, 0x00120004, 0x00020804, 0x00120804,
			0x04020004, 0x04120004, 0x04020804, 0x04120804,
			0x04020004, 0x04120004, 0x04020804, 0x04120804,
			0x00020000, 0x00120000, 0x00020800, 0x00120800,
			0x00020000, 0x00120000, 0x00020800, 0x00120800,
			0x04020000, 0x04120000, 0x04020800, 0x04120800,
			0x04020000, 0x04120000, 0x04020800, 0x04120800,
			0x00020004, 0x00120004, 0x00020804, 0x00120804,
			0x00020004, 0x00120004, 0x00020804, 0x00120804,
			0x04020004, 0x04120004, 0x04020804, 0x04120804,
			0x04020004, 0x04120004, 0x04020804, 0x04120804,
			0x00020200, 0x00120200, 0x00020A00, 0x00120A00,
			0x00020200, 0x00120200, 0x00020A00, 0x00120A00,
			0x04020200, 0x04120200, 0x04020A00, 0x04120A00,
			0x04020200, 0x04120200, 0x04020A00, 0x04120A00,
			0x00020204, 0x00120204, 0x00020A04, 0x00120A04,
			0x00020204, 0x00120204, 0x00020A04, 0x00120A04,
			0x04020204, 0x04120204, 0x04020A04, 0x04120A04,
			0x04020204, 0x04120204, 0x04020A04, 0x04120A04,
			0x00020200, 0x00120200, 0x00020A00, 0x00120A00,
			0x00020200, 0x00120200, 0x00020A00, 0x00120A00,
			0x04020200, 0x04120200, 0x04020A00, 0x04120A00,
			0x04020200, 0x04120200, 0x04020A00, 0x04120A00,
			0x00020204, 0x00120204, 0x00020A04, 0x00120A04,
			0x00020204, 0x00120204, 0x00020A04, 0x00120A04,
			0x04020204, 0x04120204, 0x04020A04, 0x04120A04,
			0x04020204, 0x04120204, 0x04020A04, 0x04120A04
		];
		static $pc2mapd3 = [
			0x00000000, 0x00010000, 0x02000000, 0x02010000,
			0x00000020, 0x00010020, 0x02000020, 0x02010020,
			0x00040000, 0x00050000, 0x02040000, 0x02050000,
			0x00040020, 0x00050020, 0x02040020, 0x02050020,
			0x00002000, 0x00012000, 0x02002000, 0x02012000,
			0x00002020, 0x00012020, 0x02002020, 0x02012020,
			0x00042000, 0x00052000, 0x02042000, 0x02052000,
			0x00042020, 0x00052020, 0x02042020, 0x02052020,
			0x00000000, 0x00010000, 0x02000000, 0x02010000,
			0x00000020, 0x00010020, 0x02000020, 0x02010020,
			0x00040000, 0x00050000, 0x02040000, 0x02050000,
			0x00040020, 0x00050020, 0x02040020, 0x02050020,
			0x00002000, 0x00012000, 0x02002000, 0x02012000,
			0x00002020, 0x00012020, 0x02002020, 0x02012020,
			0x00042000, 0x00052000, 0x02042000, 0x02052000,
			0x00042020, 0x00052020, 0x02042020, 0x02052020,
			0x00000010, 0x00010010, 0x02000010, 0x02010010,
			0x00000030, 0x00010030, 0x02000030, 0x02010030,
			0x00040010, 0x00050010, 0x02040010, 0x02050010,
			0x00040030, 0x00050030, 0x02040030, 0x02050030,
			0x00002010, 0x00012010, 0x02002010, 0x02012010,
			0x00002030, 0x00012030, 0x02002030, 0x02012030,
			0x00042010, 0x00052010, 0x02042010, 0x02052010,
			0x00042030, 0x00052030, 0x02042030, 0x02052030,
			0x00000010, 0x00010010, 0x02000010, 0x02010010,
			0x00000030, 0x00010030, 0x02000030, 0x02010030,
			0x00040010, 0x00050010, 0x02040010, 0x02050010,
			0x00040030, 0x00050030, 0x02040030, 0x02050030,
			0x00002010, 0x00012010, 0x02002010, 0x02012010,
			0x00002030, 0x00012030, 0x02002030, 0x02012030,
			0x00042010, 0x00052010, 0x02042010, 0x02052010,
			0x00042030, 0x00052030, 0x02042030, 0x02052030,
			0x20000000, 0x20010000, 0x22000000, 0x22010000,
			0x20000020, 0x20010020, 0x22000020, 0x22010020,
			0x20040000, 0x20050000, 0x22040000, 0x22050000,
			0x20040020, 0x20050020, 0x22040020, 0x22050020,
			0x20002000, 0x20012000, 0x22002000, 0x22012000,
			0x20002020, 0x20012020, 0x22002020, 0x22012020,
			0x20042000, 0x20052000, 0x22042000, 0x22052000,
			0x20042020, 0x20052020, 0x22042020, 0x22052020,
			0x20000000, 0x20010000, 0x22000000, 0x22010000,
			0x20000020, 0x20010020, 0x22000020, 0x22010020,
			0x20040000, 0x20050000, 0x22040000, 0x22050000,
			0x20040020, 0x20050020, 0x22040020, 0x22050020,
			0x20002000, 0x20012000, 0x22002000, 0x22012000,
			0x20002020, 0x20012020, 0x22002020, 0x22012020,
			0x20042000, 0x20052000, 0x22042000, 0x22052000,
			0x20042020, 0x20052020, 0x22042020, 0x22052020,
			0x20000010, 0x20010010, 0x22000010, 0x22010010,
			0x20000030, 0x20010030, 0x22000030, 0x22010030,
			0x20040010, 0x20050010, 0x22040010, 0x22050010,
			0x20040030, 0x20050030, 0x22040030, 0x22050030,
			0x20002010, 0x20012010, 0x22002010, 0x22012010,
			0x20002030, 0x20012030, 0x22002030, 0x22012030,
			0x20042010, 0x20052010, 0x22042010, 0x22052010,
			0x20042030, 0x20052030, 0x22042030, 0x22052030,
			0x20000010, 0x20010010, 0x22000010, 0x22010010,
			0x20000030, 0x20010030, 0x22000030, 0x22010030,
			0x20040010, 0x20050010, 0x22040010, 0x22050010,
			0x20040030, 0x20050030, 0x22040030, 0x22050030,
			0x20002010, 0x20012010, 0x22002010, 0x22012010,
			0x20002030, 0x20012030, 0x22002030, 0x22012030,
			0x20042010, 0x20052010, 0x22042010, 0x22052010,
			0x20042030, 0x20052030, 0x22042030, 0x22052030
		];
		static $pc2mapd4 = [
			0x00000000, 0x00000400, 0x01000000, 0x01000400,
			0x00000000, 0x00000400, 0x01000000, 0x01000400,
			0x00000100, 0x00000500, 0x01000100, 0x01000500,
			0x00000100, 0x00000500, 0x01000100, 0x01000500,
			0x10000000, 0x10000400, 0x11000000, 0x11000400,
			0x10000000, 0x10000400, 0x11000000, 0x11000400,
			0x10000100, 0x10000500, 0x11000100, 0x11000500,
			0x10000100, 0x10000500, 0x11000100, 0x11000500,
			0x00080000, 0x00080400, 0x01080000, 0x01080400,
			0x00080000, 0x00080400, 0x01080000, 0x01080400,
			0x00080100, 0x00080500, 0x01080100, 0x01080500,
			0x00080100, 0x00080500, 0x01080100, 0x01080500,
			0x10080000, 0x10080400, 0x11080000, 0x11080400,
			0x10080000, 0x10080400, 0x11080000, 0x11080400,
			0x10080100, 0x10080500, 0x11080100, 0x11080500,
			0x10080100, 0x10080500, 0x11080100, 0x11080500,
			0x00000008, 0x00000408, 0x01000008, 0x01000408,
			0x00000008, 0x00000408, 0x01000008, 0x01000408,
			0x00000108, 0x00000508, 0x01000108, 0x01000508,
			0x00000108, 0x00000508, 0x01000108, 0x01000508,
			0x10000008, 0x10000408, 0x11000008, 0x11000408,
			0x10000008, 0x10000408, 0x11000008, 0x11000408,
			0x10000108, 0x10000508, 0x11000108, 0x11000508,
			0x10000108, 0x10000508, 0x11000108, 0x11000508,
			0x00080008, 0x00080408, 0x01080008, 0x01080408,
			0x00080008, 0x00080408, 0x01080008, 0x01080408,
			0x00080108, 0x00080508, 0x01080108, 0x01080508,
			0x00080108, 0x00080508, 0x01080108, 0x01080508,
			0x10080008, 0x10080408, 0x11080008, 0x11080408,
			0x10080008, 0x10080408, 0x11080008, 0x11080408,
			0x10080108, 0x10080508, 0x11080108, 0x11080508,
			0x10080108, 0x10080508, 0x11080108, 0x11080508,
			0x00001000, 0x00001400, 0x01001000, 0x01001400,
			0x00001000, 0x00001400, 0x01001000, 0x01001400,
			0x00001100, 0x00001500, 0x01001100, 0x01001500,
			0x00001100, 0x00001500, 0x01001100, 0x01001500,
			0x10001000, 0x10001400, 0x11001000, 0x11001400,
			0x10001000, 0x10001400, 0x11001000, 0x11001400,
			0x10001100, 0x10001500, 0x11001100, 0x11001500,
			0x10001100, 0x10001500, 0x11001100, 0x11001500,
			0x00081000, 0x00081400, 0x01081000, 0x01081400,
			0x00081000, 0x00081400, 0x01081000, 0x01081400,
			0x00081100, 0x00081500, 0x01081100, 0x01081500,
			0x00081100, 0x00081500, 0x01081100, 0x01081500,
			0x10081000, 0x10081400, 0x11081000, 0x11081400,
			0x10081000, 0x10081400, 0x11081000, 0x11081400,
			0x10081100, 0x10081500, 0x11081100, 0x11081500,
			0x10081100, 0x10081500, 0x11081100, 0x11081500,
			0x00001008, 0x00001408, 0x01001008, 0x01001408,
			0x00001008, 0x00001408, 0x01001008, 0x01001408,
			0x00001108, 0x00001508, 0x01001108, 0x01001508,
			0x00001108, 0x00001508, 0x01001108, 0x01001508,
			0x10001008, 0x10001408, 0x11001008, 0x11001408,
			0x10001008, 0x10001408, 0x11001008, 0x11001408,
			0x10001108, 0x10001508, 0x11001108, 0x11001508,
			0x10001108, 0x10001508, 0x11001108, 0x11001508,
			0x00081008, 0x00081408, 0x01081008, 0x01081408,
			0x00081008, 0x00081408, 0x01081008, 0x01081408,
			0x00081108, 0x00081508, 0x01081108, 0x01081508,
			0x00081108, 0x00081508, 0x01081108, 0x01081508,
			0x10081008, 0x10081408, 0x11081008, 0x11081408,
			0x10081008, 0x10081408, 0x11081008, 0x11081408,
			0x10081108, 0x10081508, 0x11081108, 0x11081508,
			0x10081108, 0x10081508, 0x11081108, 0x11081508
		];

		$keys = [];
		for ($des_round = 0; $des_round < $this->des_rounds; ++$des_round) {

			$key = str_pad(substr($this->key, $des_round * 8, 8), 8, "\0");

			$t = unpack('Nl/Nr', $key);
			list($l, $r) = [$t['l'], $t['r']];
			$key = (self::$shuffle[$pc1map[ $r		& 0xFF]] & "\x80\x80\x80\x80\x80\x80\x80\x00") |
					(self::$shuffle[$pc1map[($r >>	8) & 0xFF]] & "\x40\x40\x40\x40\x40\x40\x40\x00") |
					(self::$shuffle[$pc1map[($r >> 16) & 0xFF]] & "\x20\x20\x20\x20\x20\x20\x20\x00") |
					(self::$shuffle[$pc1map[($r >> 24) & 0xFF]] & "\x10\x10\x10\x10\x10\x10\x10\x00") |
					(self::$shuffle[$pc1map[ $l		& 0xFF]] & "\x08\x08\x08\x08\x08\x08\x08\x00") |
					(self::$shuffle[$pc1map[($l >>	8) & 0xFF]] & "\x04\x04\x04\x04\x04\x04\x04\x00") |
					(self::$shuffle[$pc1map[($l >> 16) & 0xFF]] & "\x02\x02\x02\x02\x02\x02\x02\x00") |
					(self::$shuffle[$pc1map[($l >> 24) & 0xFF]] & "\x01\x01\x01\x01\x01\x01\x01\x00");
			$key = unpack('Nc/Nd', $key);
			$c = ( $key['c'] >> 4) & 0x0FFFFFFF;
			$d = (($key['d'] >> 4) & 0x0FFFFFF0) | ($key['c'] & 0x0F);

			$keys[$des_round] = [
				self::ENCRYPT => [],
				self::DECRYPT => array_fill(0, 32, 0)
			];
			for ($i = 0, $ki = 31; $i < 16; ++$i, $ki -= 2) {
				$c <<= $shifts[$i];
				$c = ($c | ($c >> 28)) & 0x0FFFFFFF;
				$d <<= $shifts[$i];
				$d = ($d | ($d >> 28)) & 0x0FFFFFFF;

				$cp = $pc2mapc1[ $c >> 24		] | $pc2mapc2[($c >> 16) & 0xFF] |
						$pc2mapc3[($c >>	8) & 0xFF] | $pc2mapc4[ $c		& 0xFF];
				$dp = $pc2mapd1[ $d >> 24		] | $pc2mapd2[($d >> 16) & 0xFF] |
						$pc2mapd3[($d >>	8) & 0xFF] | $pc2mapd4[ $d		& 0xFF];

				$val1 = ( $cp		& intval(0xFF000000)) | (($cp <<	8) & 0x00FF0000) |
						(($dp >> 16) & 0x0000FF00) | (($dp >>	8) & 0x000000FF);
				$val2 = (($cp <<	8) & intval(0xFF000000)) | (($cp << 16) & 0x00FF0000) |
						(($dp >>	8) & 0x0000FF00) | ( $dp		& 0x000000FF);
				$keys[$des_round][self::ENCRYPT][		] = $val1;
				$keys[$des_round][self::DECRYPT][$ki - 1] = $val1;
				$keys[$des_round][self::ENCRYPT][		] = $val2;
				$keys[$des_round][self::DECRYPT][$ki	] = $val2;
			}
		}

		switch ($this->des_rounds) {
			case 3:
				$this->keys = [
					self::ENCRYPT => array_merge(
						$keys[0][self::ENCRYPT],
						$keys[1][self::DECRYPT],
						$keys[2][self::ENCRYPT]
					),
					self::DECRYPT => array_merge(
						$keys[2][self::DECRYPT],
						$keys[1][self::ENCRYPT],
						$keys[0][self::DECRYPT]
					)
				];
				break;

			default:
				$this->keys = [
					self::ENCRYPT => $keys[0][self::ENCRYPT],
					self::DECRYPT => $keys[0][self::DECRYPT]
				];
		}
	}

	protected function setupInlineCrypt()
	{

		$des_rounds = $this->des_rounds;

		$init_crypt = 'static $sbox1, $sbox2, $sbox3, $sbox4, $sbox5, $sbox6, $sbox7, $sbox8, $shuffleip, $shuffleinvip;
            if (!$sbox1) {
                $sbox1 = array_map("intval", self::$sbox1);
                $sbox2 = array_map("intval", self::$sbox2);
                $sbox3 = array_map("intval", self::$sbox3);
                $sbox4 = array_map("intval", self::$sbox4);
                $sbox5 = array_map("intval", self::$sbox5);
                $sbox6 = array_map("intval", self::$sbox6);
                $sbox7 = array_map("intval", self::$sbox7);
                $sbox8 = array_map("intval", self::$sbox8);'
				 . '
                for ($i = 0; $i < 256; ++$i) {
                    $shuffleip[]    =  self::$shuffle[self::$ipmap[$i]];
                    $shuffleinvip[] =  self::$shuffle[self::$invipmap[$i]];
                }
            }
        ';

		$k = [
			self::ENCRYPT => $this->keys[self::ENCRYPT],
			self::DECRYPT => $this->keys[self::DECRYPT]
		];
		$init_encrypt = '';
		$init_decrypt = '';

		$crypt_block = [];
		foreach ([self::ENCRYPT, self::DECRYPT] as $c) {

			$crypt_block[$c] = '
                $in = unpack("N*", $in);
                $l  = $in[1];
                $r  = $in[2];
                $in = unpack("N*",
                    ($shuffleip[ $r        & 0xFF] & "\x80\x80\x80\x80\x80\x80\x80\x80") |
                    ($shuffleip[($r >>  8) & 0xFF] & "\x40\x40\x40\x40\x40\x40\x40\x40") |
                    ($shuffleip[($r >> 16) & 0xFF] & "\x20\x20\x20\x20\x20\x20\x20\x20") |
                    ($shuffleip[($r >> 24) & 0xFF] & "\x10\x10\x10\x10\x10\x10\x10\x10") |
                    ($shuffleip[ $l        & 0xFF] & "\x08\x08\x08\x08\x08\x08\x08\x08") |
                    ($shuffleip[($l >>  8) & 0xFF] & "\x04\x04\x04\x04\x04\x04\x04\x04") |
                    ($shuffleip[($l >> 16) & 0xFF] & "\x02\x02\x02\x02\x02\x02\x02\x02") |
                    ($shuffleip[($l >> 24) & 0xFF] & "\x01\x01\x01\x01\x01\x01\x01\x01")
                );
                ' .  '
                $l = $in[1];
                $r = $in[2];
            ';

			$l = '$l';
			$r = '$r';

			for ($ki = -1, $des_round = 0; $des_round < $des_rounds; ++$des_round) {

				for ($i = 0; $i < 16; ++$i) {

					$crypt_block[$c] .= '
                        $b1 = ((' . $r . ' >>  3) & 0x1FFFFFFF)  ^ (' . $r . ' << 29) ^ ' . $k[$c][++$ki] . ';
                        $b2 = ((' . $r . ' >> 31) & 0x00000001)  ^ (' . $r . ' <<  1) ^ ' . $k[$c][++$ki] . ';' .

						$l . ' = $sbox1[($b1 >> 24) & 0x3F] ^ $sbox2[($b2 >> 24) & 0x3F] ^
                                 $sbox3[($b1 >> 16) & 0x3F] ^ $sbox4[($b2 >> 16) & 0x3F] ^
                                 $sbox5[($b1 >>  8) & 0x3F] ^ $sbox6[($b2 >>  8) & 0x3F] ^
                                 $sbox7[ $b1        & 0x3F] ^ $sbox8[ $b2        & 0x3F] ^ ' . $l . ';
                    ';

					list($l, $r) = [$r, $l];
				}
				list($l, $r) = [$r, $l];
			}

			$crypt_block[$c] .= '$in =
                ($shuffleinvip[($l >> 24) & 0xFF] & "\x80\x80\x80\x80\x80\x80\x80\x80") |
                ($shuffleinvip[($r >> 24) & 0xFF] & "\x40\x40\x40\x40\x40\x40\x40\x40") |
                ($shuffleinvip[($l >> 16) & 0xFF] & "\x20\x20\x20\x20\x20\x20\x20\x20") |
                ($shuffleinvip[($r >> 16) & 0xFF] & "\x10\x10\x10\x10\x10\x10\x10\x10") |
                ($shuffleinvip[($l >>  8) & 0xFF] & "\x08\x08\x08\x08\x08\x08\x08\x08") |
                ($shuffleinvip[($r >>  8) & 0xFF] & "\x04\x04\x04\x04\x04\x04\x04\x04") |
                ($shuffleinvip[ $l        & 0xFF] & "\x02\x02\x02\x02\x02\x02\x02\x02") |
                ($shuffleinvip[ $r        & 0xFF] & "\x01\x01\x01\x01\x01\x01\x01\x01");
            ';
		}

		$this->inline_crypt = $this->createInlineCryptFunction(
			[
				'init_crypt'	=> $init_crypt,
				'init_encrypt'	=> $init_encrypt,
				'init_decrypt'	=> $init_decrypt,
				'encrypt_block' => $crypt_block[self::ENCRYPT],
				'decrypt_block' => $crypt_block[self::DECRYPT]
			]
		);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\DH\Parameters;
use phpseclib3\Crypt\DH\PrivateKey;
use phpseclib3\Crypt\DH\PublicKey;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\Math\BigInteger;

abstract class DH extends AsymmetricKey
{

	const ALGORITHM = 'DH';

	protected $prime;

	protected $base;

	protected $publicKey;

	public static function createParameters(...$args)
	{
		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createParameters() should not be called from final classes (' . static::class . ')');
		}

		$params = new Parameters();
		if (count($args) == 2 && $args[0] instanceof BigInteger && $args[1] instanceof BigInteger) {

			$params->prime = $args[0];
			$params->base = $args[1];
			return $params;
		} elseif (count($args) == 1 && is_numeric($args[0])) {
			$params->prime = BigInteger::randomPrime($args[0]);
			$params->base = new BigInteger(2);
			return $params;
		} elseif (count($args) != 1 || !is_string($args[0])) {
			throw new \InvalidArgumentException('Valid parameters are either: two BigInteger\'s (prime and base), a single integer (the length of the prime; base is assumed to be 2) or a string');
		}
		switch ($args[0]) {

			case 'diffie-hellman-group1-sha1':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF';
				break;

			case 'diffie-hellman-group14-sha1':
			case 'diffie-hellman-group14-sha256':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
						 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
						 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
						 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
						 '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF';
				break;

			case 'diffie-hellman-group15-sha512':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
						 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
						 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
						 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
						 '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' .
						 'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
						 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' .
						 'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' .
						 '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF';
				break;

			case 'diffie-hellman-group16-sha512':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
						 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
						 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
						 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
						 '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' .
						 'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
						 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' .
						 'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' .
						 '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' .
						 '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8' .
						 'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' .
						 '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' .
						 '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF';
				break;

			case 'diffie-hellman-group17-sha512':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
						 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
						 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
						 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
						 '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' .
						 'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
						 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' .
						 'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' .
						 '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' .
						 '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8' .
						 'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' .
						 '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' .
						 '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026' .
						 'C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE' .
						 'B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B' .
						 'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC' .
						 'F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E' .
						 '59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' .
						 'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76' .
						 'F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468' .
						 '043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF';
				break;

			case 'diffie-hellman-group18-sha512':
				$prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' .
						 '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' .
						 '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' .
						 'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' .
						 '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' .
						 '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' .
						 'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' .
						 '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33' .
						 'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' .
						 'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' .
						 'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' .
						 '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7' .
						 '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8' .
						 'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' .
						 '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9' .
						 '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026' .
						 'C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE' .
						 'B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B' .
						 'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC' .
						 'F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E' .
						 '59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' .
						 'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76' .
						 'F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468' .
						 '043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4' .
						 '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED' .
						 '2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652D' .
						 'E3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B' .
						 '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6' .
						 '6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851D' .
						 'F9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92' .
						 '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA' .
						 '9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF';
				break;
			default:
				throw new \InvalidArgumentException('Invalid named prime provided');
		}

		$params->prime = new BigInteger($prime, 16);
		$params->base = new BigInteger(2);

		return $params;
	}

	public static function createKey(Parameters $params, $length = 0)
	{
		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
		}

		$one = new BigInteger(1);
		if ($length) {
			$max = $one->bitwise_leftShift($length);
			$max = $max->subtract($one);
		} else {
			$max = $params->prime->subtract($one);
		}

		$key = new PrivateKey();
		$key->prime = $params->prime;
		$key->base = $params->base;
		$key->privateKey = BigInteger::randomRange($one, $max);
		$key->publicKey = $key->base->powMod($key->privateKey, $key->prime);
		return $key;
	}

	public static function computeSecret($private, $public)
	{
		if ($private instanceof PrivateKey) {
			switch (true) {
				case $public instanceof PublicKey:
					if (!$private->prime->equals($public->prime) || !$private->base->equals($public->base)) {
						throw new \InvalidArgumentException('The public and private key do not share the same prime and / or base numbers');
					}
					return $public->publicKey->powMod($private->privateKey, $private->prime)->toBytes(true);
				case is_string($public):
					$public = new BigInteger($public, -256);

				case $public instanceof BigInteger:
					return $public->powMod($private->privateKey, $private->prime)->toBytes(true);
				default:
					throw new \InvalidArgumentException('$public needs to be an instance of DH\PublicKey, a BigInteger or a string');
			}
		}

		if ($private instanceof EC\PrivateKey) {
			switch (true) {
				case $public instanceof EC\PublicKey:
					$public = $public->getEncodedCoordinates();

				case is_string($public):
					$point = $private->multiply($public);
					switch ($private->getCurve()) {
						case 'Curve25519':
						case 'Curve448':
							$secret = $point;
							break;
						default:

							$secret = substr($point, 1, (strlen($point) - 1) >> 1);
					}

					return $secret;
				default:
					throw new \InvalidArgumentException('$public needs to be an instance of EC\PublicKey or a string (an encoded coordinate)');
			}
		}
	}

	public static function load($key, $password = false)
	{
		try {
			return EC::load($key, $password);
		} catch (NoKeyLoadedException $e) {
		}

		return parent::load($key, $password);
	}

	protected static function onLoad(array $components)
	{
		if (!isset($components['privateKey']) && !isset($components['publicKey'])) {
			$new = new Parameters();
		} else {
			$new = isset($components['privateKey']) ?
				new PrivateKey() :
				new PublicKey();
		}

		$new->prime = $components['prime'];
		$new->base = $components['base'];

		if (isset($components['privateKey'])) {
			$new->privateKey = $components['privateKey'];
		}
		if (isset($components['publicKey'])) {
			$new->publicKey = $components['publicKey'];
		}

		return $new;
	}

	public function withHash($hash)
	{
		throw new UnsupportedOperationException('DH does not use a hash algorithm');
	}

	public function getHash()
	{
		throw new UnsupportedOperationException('DH does not use a hash algorithm');
	}

	public function getParameters()
	{
		$type = DH::validatePlugin('Keys', 'PKCS1', 'saveParameters');

		$key = $type::saveParameters($this->prime, $this->base);
		return DH::load($key, 'PKCS1');
	}
}
}

namespace phpseclib3\Crypt\DH {

use phpseclib3\Crypt\DH;

final class Parameters extends DH
{

	public function toString($type = 'PKCS1', array $options = [])
	{
		$type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

		return $type::saveParameters($this->prime, $this->base, $options);
	}
}
}

namespace phpseclib3\Crypt\DH {

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DH;

final class PrivateKey extends DH
{
	use Common\Traits\PasswordProtected;

	protected $privateKey;

	protected $publicKey;

	public function getPublicKey()
	{
		$type = self::validatePlugin('Keys', 'PKCS8', 'savePublicKey');

		if (!isset($this->publicKey)) {
			$this->publicKey = $this->base->powMod($this->privateKey, $this->prime);
		}

		$key = $type::savePublicKey($this->prime, $this->base, $this->publicKey);

		return DH::loadFormat('PKCS8', $key);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePrivateKey');

		if (!isset($this->publicKey)) {
			$this->publicKey = $this->base->powMod($this->privateKey, $this->prime);
		}

		return $type::savePrivateKey($this->prime, $this->base, $this->privateKey, $this->publicKey, $this->password, $options);
	}
}
}

namespace phpseclib3\Crypt\DH {

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DH;

final class PublicKey extends DH
{
	use Common\Traits\Fingerprint;

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePublicKey');

		return $type::savePublicKey($this->prime, $this->base, $this->publicKey, $options);
	}

	public function toBigInteger()
	{
		return $this->publicKey;
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\DSA\Parameters;
use phpseclib3\Crypt\DSA\PrivateKey;
use phpseclib3\Crypt\DSA\PublicKey;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Math\BigInteger;

abstract class DSA extends AsymmetricKey
{

	const ALGORITHM = 'DSA';

	protected $p;

	protected $q;

	protected $g;

	protected $y;

	protected $sigFormat;

	protected $shortFormat;

	public static function createParameters($L = 2048, $N = 224)
	{
		self::initialize_static_variables();

		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createParameters() should not be called from final classes (' . static::class . ')');
		}

		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}

		switch (true) {
			case $N == 160:

			case $L == 2048 && $N == 224:
			case $L == 2048 && $N == 256:
			case $L == 3072 && $N == 256:
				break;
			default:
				throw new \InvalidArgumentException('Invalid values for N and L');
		}

		$two = new BigInteger(2);

		$q = BigInteger::randomPrime($N);
		$divisor = $q->multiply($two);

		do {
			$x = BigInteger::random($L);
			list(, $c) = $x->divide($divisor);
			$p = $x->subtract($c->subtract(self::$one));
		} while ($p->getLength() != $L || !$p->isPrime());

		$p_1 = $p->subtract(self::$one);
		list($e) = $p_1->divide($q);

		$h = clone $two;
		while (true) {
			$g = $h->powMod($e, $p);
			if (!$g->equals(self::$one)) {
				break;
			}
			$h = $h->add(self::$one);
		}

		$dsa = new Parameters();
		$dsa->p = $p;
		$dsa->q = $q;
		$dsa->g = $g;

		return $dsa;
	}

	public static function createKey(...$args)
	{
		self::initialize_static_variables();

		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
		}

		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}

		if (count($args) == 2 && is_int($args[0]) && is_int($args[1])) {
			$params = self::createParameters($args[0], $args[1]);
		} elseif (count($args) == 1 && $args[0] instanceof Parameters) {
			$params = $args[0];
		} elseif (!count($args)) {
			$params = self::createParameters();
		} else {
			throw new InsufficientSetupException('Valid parameters are either two integers (L and N), a single DSA object or no parameters at all.');
		}

		$private = new PrivateKey();
		$private->p = $params->p;
		$private->q = $params->q;
		$private->g = $params->g;

		$private->x = BigInteger::randomRange(self::$one, $private->q->subtract(self::$one));
		$private->y = $private->g->powMod($private->x, $private->p);

		return $private
			->withHash($params->hash->getHash())
			->withSignatureFormat($params->shortFormat);
	}

	protected static function onLoad(array $components)
	{
		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}

		if (!isset($components['x']) && !isset($components['y'])) {
			$new = new Parameters();
		} elseif (isset($components['x'])) {
			$new = new PrivateKey();
			$new->x = $components['x'];
		} else {
			$new = new PublicKey();
		}

		$new->p = $components['p'];
		$new->q = $components['q'];
		$new->g = $components['g'];

		if (isset($components['y'])) {
			$new->y = $components['y'];
		}

		return $new;
	}

	protected function __construct()
	{
		$this->sigFormat = self::validatePlugin('Signature', 'ASN1');
		$this->shortFormat = 'ASN1';

		parent::__construct();
	}

	public function getLength()
	{
		return ['L' => $this->p->getLength(), 'N' => $this->q->getLength()];
	}

	public function getEngine()
	{
		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}
		return self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods()) ?
			'OpenSSL' : 'PHP';
	}

	public function getParameters()
	{
		$type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

		$key = $type::saveParameters($this->p, $this->q, $this->g);
		return DSA::load($key, 'PKCS1')
			->withHash($this->hash->getHash())
			->withSignatureFormat($this->shortFormat);
	}

	public function withSignatureFormat($format)
	{
		$new = clone $this;
		$new->shortFormat = $format;
		$new->sigFormat = self::validatePlugin('Signature', $format);
		return $new;
	}

	public function getSignatureFormat()
	{
		return $this->shortFormat;
	}
}
}

namespace phpseclib3\Crypt\DSA {

use phpseclib3\Crypt\DSA;

final class Parameters extends DSA
{

	public function toString($type = 'PKCS1', array $options = [])
	{
		$type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

		return $type::saveParameters($this->p, $this->q, $this->g, $options);
	}
}
}

namespace phpseclib3\Crypt\DSA {

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\DSA\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib3\Math\BigInteger;

final class PrivateKey extends DSA implements Common\PrivateKey
{
	use Common\Traits\PasswordProtected;

	protected $x;

	public function getPublicKey()
	{
		$type = self::validatePlugin('Keys', 'PKCS8', 'savePublicKey');

		if (!isset($this->y)) {
			$this->y = $this->g->powMod($this->x, $this->p);
		}

		$key = $type::savePublicKey($this->p, $this->q, $this->g, $this->y);

		return DSA::loadFormat('PKCS8', $key)
			->withHash($this->hash->getHash())
			->withSignatureFormat($this->shortFormat);
	}

	public function sign($message)
	{
		$format = $this->sigFormat;

		if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
			$signature = '';
			$result = openssl_sign($message, $signature, $this->toString('PKCS8'), $this->hash->getHash());

			if ($result) {
				if ($this->shortFormat == 'ASN1') {
					return $signature;
				}

				extract(ASN1Signature::load($signature));

				return $format::save($r, $s);
			}
		}

		$h = $this->hash->hash($message);
		$h = $this->bits2int($h);

		while (true) {
			$k = BigInteger::randomRange(self::$one, $this->q->subtract(self::$one));
			$r = $this->g->powMod($k, $this->p);
			list(, $r) = $r->divide($this->q);
			if ($r->equals(self::$zero)) {
				continue;
			}
			$kinv = $k->modInverse($this->q);
			$temp = $h->add($this->x->multiply($r));
			$temp = $kinv->multiply($temp);
			list(, $s) = $temp->divide($this->q);
			if (!$s->equals(self::$zero)) {
				break;
			}
		}

		return $format::save($r, $s);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePrivateKey');

		if (!isset($this->y)) {
			$this->y = $this->g->powMod($this->x, $this->p);
		}

		return $type::savePrivateKey($this->p, $this->q, $this->g, $this->y, $this->x, $this->password, $options);
	}
}
}

namespace phpseclib3\Crypt\DSA {

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\DSA\Formats\Signature\ASN1 as ASN1Signature;

final class PublicKey extends DSA implements Common\PublicKey
{
	use Common\Traits\Fingerprint;

	public function verify($message, $signature)
	{
		$format = $this->sigFormat;

		$params = $format::load($signature);
		if ($params === false || count($params) != 2) {
			return false;
		}
		extract($params);

		if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
			$sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

			$result = openssl_verify($message, $sig, $this->toString('PKCS8'), $this->hash->getHash());

			if ($result != -1) {
				return (bool) $result;
			}
		}

		$q_1 = $this->q->subtract(self::$one);
		if (!$r->between(self::$one, $q_1) || !$s->between(self::$one, $q_1)) {
			return false;
		}

		$w = $s->modInverse($this->q);
		$h = $this->hash->hash($message);
		$h = $this->bits2int($h);
		list(, $u1) = $h->multiply($w)->divide($this->q);
		list(, $u2) = $r->multiply($w)->divide($this->q);
		$v1 = $this->g->powMod($u1, $this->p);
		$v2 = $this->y->powMod($u2, $this->p);
		list(, $v) = $v1->multiply($v2)->divide($this->p);
		list(, $v) = $v->divide($this->q);

		return $v->equals($r);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePublicKey');

		return $type::savePublicKey($this->p, $this->q, $this->g, $this->y, $options);
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Math\BigInteger;

abstract class Base
{

	protected $order;

	protected $factory;

	public function randomInteger()
	{
		return $this->factory->randomInteger();
	}

	public function convertInteger(BigInteger $x)
	{
		return $this->factory->newInteger($x);
	}

	public function getLengthInBytes()
	{
		return $this->factory->getLengthInBytes();
	}

	public function getLength()
	{
		return $this->factory->getLength();
	}

	public function multiplyPoint(array $p, BigInteger $d)
	{
		$alreadyInternal = isset($p[2]);
		$r = $alreadyInternal ?
			[[], $p] :
			[[], $this->convertToInternal($p)];

		$d = $d->toBits();
		for ($i = 0; $i < strlen($d); $i++) {
			$d_i = (int) $d[$i];
			$r[1 - $d_i] = $this->addPoint($r[0], $r[1]);
			$r[$d_i] = $this->doublePoint($r[$d_i]);
		}

		return $alreadyInternal ? $r[0] : $this->convertToAffine($r[0]);
	}

	public function createRandomMultiplier()
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		return BigInteger::randomRange($one, $this->order->subtract($one));
	}

	public function rangeCheck(BigInteger $x)
	{
		static $zero;
		if (!isset($zero)) {
			$zero = new BigInteger();
		}

		if (!isset($this->order)) {
			throw new \RuntimeException('setOrder needs to be called before this method');
		}
		if ($x->compare($this->order) > 0 || $x->compare($zero) <= 0) {
			throw new \RangeException('x must be between 1 and the order of the curve');
		}
	}

	public function setOrder(BigInteger $order)
	{
		$this->order = $order;
	}

	public function getOrder()
	{
		return $this->order;
	}

	public function setReduction(callable $func)
	{
		$this->factory->setReduction($func);
	}

	public function convertToAffine(array $p)
	{
		return $p;
	}

	public function convertToInternal(array $p)
	{
		return $p;
	}

	public function negatePoint(array $p)
	{
		$temp = [
			$p[0],
			$p[1]->negate()
		];
		if (isset($p[2])) {
			$temp[] = $p[2];
		}
		return $temp;
	}

	public function multiplyAddPoints(array $points, array $scalars)
	{
		$p1 = $this->convertToInternal($points[0]);
		$p2 = $this->convertToInternal($points[1]);
		$p1 = $this->multiplyPoint($p1, $scalars[0]);
		$p2 = $this->multiplyPoint($p2, $scalars[1]);
		$r = $this->addPoint($p1, $p2);
		return $this->convertToAffine($r);
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BinaryField;
use phpseclib3\Math\BinaryField\Integer as BinaryInteger;

class Binary extends Base
{

	protected $factory;

	protected $a;

	protected $b;

	protected $p;

	protected $one;

	protected $modulo;

	protected $order;

	public function setModulo(...$modulo)
	{
		$this->modulo = $modulo;
		$this->factory = new BinaryField(...$modulo);

		$this->one = $this->factory->newInteger("\1");
	}

	public function setCoefficients($a, $b)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->a = $this->factory->newInteger(pack('H*', $a));
		$this->b = $this->factory->newInteger(pack('H*', $b));
	}

	public function setBasePoint($x, $y)
	{
		switch (true) {
			case !is_string($x) && !$x instanceof BinaryInteger:
				throw new \UnexpectedValueException('Argument 1 passed to Binary::setBasePoint() must be a string or an instance of BinaryField\Integer');
			case !is_string($y) && !$y instanceof BinaryInteger:
				throw new \UnexpectedValueException('Argument 2 passed to Binary::setBasePoint() must be a string or an instance of BinaryField\Integer');
		}
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->p = [
			is_string($x) ? $this->factory->newInteger(pack('H*', $x)) : $x,
			is_string($y) ? $this->factory->newInteger(pack('H*', $y)) : $y
		];
	}

	public function getBasePoint()
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		return $this->p;
	}

	public function addPoint(array $p, array $q)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p) || !count($q)) {
			if (count($q)) {
				return $q;
			}
			if (count($p)) {
				return $p;
			}
			return [];
		}

		if (!isset($p[2]) || !isset($q[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		if ($p[0]->equals($q[0])) {
			return !$p[1]->equals($q[1]) ? [] : $this->doublePoint($p);
		}

		list($x1, $y1, $z1) = $p;
		list($x2, $y2, $z2) = $q;

		$o1 = $z1->multiply($z1);
		$b = $x2->multiply($o1);

		if ($z2->equals($this->one)) {
			$d = $y2->multiply($o1)->multiply($z1);
			$e = $x1->add($b);
			$f = $y1->add($d);
			$z3 = $e->multiply($z1);
			$h = $f->multiply($x2)->add($z3->multiply($y2));
			$i = $f->add($z3);
			$g = $z3->multiply($z3);
			$p1 = $this->a->multiply($g);
			$p2 = $f->multiply($i);
			$p3 = $e->multiply($e)->multiply($e);
			$x3 = $p1->add($p2)->add($p3);
			$y3 = $i->multiply($x3)->add($g->multiply($h));

			return [$x3, $y3, $z3];
		}

		$o2 = $z2->multiply($z2);
		$a = $x1->multiply($o2);
		$c = $y1->multiply($o2)->multiply($z2);
		$d = $y2->multiply($o1)->multiply($z1);
		$e = $a->add($b);
		$f = $c->add($d);
		$g = $e->multiply($z1);
		$h = $f->multiply($x2)->add($g->multiply($y2));
		$z3 = $g->multiply($z2);
		$i = $f->add($z3);
		$p1 = $this->a->multiply($z3->multiply($z3));
		$p2 = $f->multiply($i);
		$p3 = $e->multiply($e)->multiply($e);
		$x3 = $p1->add($p2)->add($p3);
		$y3 = $i->multiply($x3)->add($g->multiply($g)->multiply($h));

		return [$x3, $y3, $z3];
	}

	public function doublePoint(array $p)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p)) {
			return [];
		}

		if (!isset($p[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		list($x1, $y1, $z1) = $p;

		$a = $x1->multiply($x1);
		$b = $a->multiply($a);

		if ($z1->equals($this->one)) {
			$x3 = $b->add($this->b);
			$z3 = clone $x1;
			$p1 = $a->add($y1)->add($z3)->multiply($this->b);
			$p2 = $a->add($y1)->multiply($b);
			$y3 = $p1->add($p2);

			return [$x3, $y3, $z3];
		}

		$c = $z1->multiply($z1);
		$d = $c->multiply($c);
		$x3 = $b->add($this->b->multiply($d->multiply($d)));
		$z3 = $x1->multiply($c);
		$p1 = $b->multiply($z3);
		$p2 = $a->add($y1->multiply($z1))->add($z3)->multiply($x3);
		$y3 = $p1->add($p2);

		return [$x3, $y3, $z3];
	}

	public function derivePoint($m)
	{
		throw new \RuntimeException('Point compression on binary finite field elliptic curves is not supported');
	}

	public function verifyPoint(array $p)
	{
		list($x, $y) = $p;
		$lhs = $y->multiply($y);
		$lhs = $lhs->add($x->multiply($y));
		$x2 = $x->multiply($x);
		$x3 = $x2->multiply($x);
		$rhs = $x3->add($this->a->multiply($x2))->add($this->b);

		return $lhs->equals($rhs);
	}

	public function getModulo()
	{
		return $this->modulo;
	}

	public function getA()
	{
		return $this->a;
	}

	public function getB()
	{
		return $this->b;
	}

	public function convertToAffine(array $p)
	{
		if (!isset($p[2])) {
			return $p;
		}
		list($x, $y, $z) = $p;
		$z = $this->one->divide($z);
		$z2 = $z->multiply($z);
		return [
			$x->multiply($z2),
			$y->multiply($z2)->multiply($z)
		];
	}

	public function convertToInternal(array $p)
	{
		if (isset($p[2])) {
			return $p;
		}

		$p[2] = clone $this->one;
		$p['fresh'] = true;
		return $p;
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\Common\FiniteField\Integer;
use phpseclib3\Math\PrimeField;
use phpseclib3\Math\PrimeField\Integer as PrimeInteger;

class Prime extends Base
{

	protected $factory;

	protected $a;

	protected $b;

	protected $p;

	protected $one;

	protected $two;

	protected $three;

	protected $four;

	protected $eight;

	protected $modulo;

	protected $order;

	public function setModulo(BigInteger $modulo)
	{
		$this->modulo = $modulo;
		$this->factory = new PrimeField($modulo);
		$this->two = $this->factory->newInteger(new BigInteger(2));
		$this->three = $this->factory->newInteger(new BigInteger(3));

		$this->one = $this->factory->newInteger(new BigInteger(1));
		$this->four = $this->factory->newInteger(new BigInteger(4));
		$this->eight = $this->factory->newInteger(new BigInteger(8));
	}

	public function setCoefficients(BigInteger $a, BigInteger $b)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->a = $this->factory->newInteger($a);
		$this->b = $this->factory->newInteger($b);
	}

	public function setBasePoint($x, $y)
	{
		switch (true) {
			case !$x instanceof BigInteger && !$x instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 1 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
			case !$y instanceof BigInteger && !$y instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 2 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
		}
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->p = [
			$x instanceof BigInteger ? $this->factory->newInteger($x) : $x,
			$y instanceof BigInteger ? $this->factory->newInteger($y) : $y
		];
	}

	public function getBasePoint()
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		return $this->p;
	}

	protected function jacobianAddPointMixedXY(array $p, array $q)
	{
		list($u1, $s1) = $p;
		list($u2, $s2) = $q;
		if ($u1->equals($u2)) {
			if (!$s1->equals($s2)) {
				return [];
			} else {
				return $this->doublePoint($p);
			}
		}
		$h = $u2->subtract($u1);
		$r = $s2->subtract($s1);
		$h2 = $h->multiply($h);
		$h3 = $h2->multiply($h);
		$v = $u1->multiply($h2);
		$x3 = $r->multiply($r)->subtract($h3)->subtract($v->multiply($this->two));
		$y3 = $r->multiply(
			$v->subtract($x3)
		)->subtract(
			$s1->multiply($h3)
		);
		return [$x3, $y3, $h];
	}

	protected function jacobianAddPointMixedX(array $p, array $q)
	{
		list($u1, $s1, $z1) = $p;
		list($x2, $y2) = $q;

		$z12 = $z1->multiply($z1);

		$u2 = $x2->multiply($z12);
		$s2 = $y2->multiply($z12->multiply($z1));
		if ($u1->equals($u2)) {
			if (!$s1->equals($s2)) {
				return [];
			} else {
				return $this->doublePoint($p);
			}
		}
		$h = $u2->subtract($u1);
		$r = $s2->subtract($s1);
		$h2 = $h->multiply($h);
		$h3 = $h2->multiply($h);
		$v = $u1->multiply($h2);
		$x3 = $r->multiply($r)->subtract($h3)->subtract($v->multiply($this->two));
		$y3 = $r->multiply(
			$v->subtract($x3)
		)->subtract(
			$s1->multiply($h3)
		);
		$z3 = $h->multiply($z1);
		return [$x3, $y3, $z3];
	}

	protected function jacobianAddPoint(array $p, array $q)
	{
		list($x1, $y1, $z1) = $p;
		list($x2, $y2, $z2) = $q;

		$z12 = $z1->multiply($z1);
		$z22 = $z2->multiply($z2);

		$u1 = $x1->multiply($z22);
		$u2 = $x2->multiply($z12);
		$s1 = $y1->multiply($z22->multiply($z2));
		$s2 = $y2->multiply($z12->multiply($z1));
		if ($u1->equals($u2)) {
			if (!$s1->equals($s2)) {
				return [];
			} else {
				return $this->doublePoint($p);
			}
		}
		$h = $u2->subtract($u1);
		$r = $s2->subtract($s1);
		$h2 = $h->multiply($h);
		$h3 = $h2->multiply($h);
		$v = $u1->multiply($h2);
		$x3 = $r->multiply($r)->subtract($h3)->subtract($v->multiply($this->two));
		$y3 = $r->multiply(
			$v->subtract($x3)
		)->subtract(
			$s1->multiply($h3)
		);
		$z3 = $h->multiply($z1)->multiply($z2);
		return [$x3, $y3, $z3];
	}

	public function addPoint(array $p, array $q)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p) || !count($q)) {
			if (count($q)) {
				return $q;
			}
			if (count($p)) {
				return $p;
			}
			return [];
		}

		if (isset($p[2]) && isset($q[2])) {
			if (isset($p['fresh']) && isset($q['fresh'])) {
				return $this->jacobianAddPointMixedXY($p, $q);
			}
			if (isset($p['fresh'])) {
				return $this->jacobianAddPointMixedX($q, $p);
			}
			if (isset($q['fresh'])) {
				return $this->jacobianAddPointMixedX($p, $q);
			}
			return $this->jacobianAddPoint($p, $q);
		}

		if (isset($p[2]) || isset($q[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to Jacobi coordinates or vice versa');
		}

		if ($p[0]->equals($q[0])) {
			if (!$p[1]->equals($q[1])) {
				return [];
			} else {
				list($numerator, $denominator) = $this->doublePointHelper($p);
			}
		} else {
			$numerator = $q[1]->subtract($p[1]);
			$denominator = $q[0]->subtract($p[0]);
		}
		$slope = $numerator->divide($denominator);
		$x = $slope->multiply($slope)->subtract($p[0])->subtract($q[0]);
		$y = $slope->multiply($p[0]->subtract($x))->subtract($p[1]);

		return [$x, $y];
	}

	protected function doublePointHelper(array $p)
	{
		$numerator = $this->three->multiply($p[0])->multiply($p[0])->add($this->a);
		$denominator = $this->two->multiply($p[1]);
		return [$numerator, $denominator];
	}

	protected function jacobianDoublePoint(array $p)
	{
		list($x, $y, $z) = $p;
		$x2 = $x->multiply($x);
		$y2 = $y->multiply($y);
		$z2 = $z->multiply($z);
		$s = $this->four->multiply($x)->multiply($y2);
		$m1 = $this->three->multiply($x2);
		$m2 = $this->a->multiply($z2->multiply($z2));
		$m = $m1->add($m2);
		$x1 = $m->multiply($m)->subtract($this->two->multiply($s));
		$y1 = $m->multiply($s->subtract($x1))->subtract(
			$this->eight->multiply($y2->multiply($y2))
		);
		$z1 = $this->two->multiply($y)->multiply($z);
		return [$x1, $y1, $z1];
	}

	protected function jacobianDoublePointMixed(array $p)
	{
		list($x, $y) = $p;
		$x2 = $x->multiply($x);
		$y2 = $y->multiply($y);
		$s = $this->four->multiply($x)->multiply($y2);
		$m1 = $this->three->multiply($x2);
		$m = $m1->add($this->a);
		$x1 = $m->multiply($m)->subtract($this->two->multiply($s));
		$y1 = $m->multiply($s->subtract($x1))->subtract(
			$this->eight->multiply($y2->multiply($y2))
		);
		$z1 = $this->two->multiply($y);
		return [$x1, $y1, $z1];
	}

	public function doublePoint(array $p)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p)) {
			return [];
		}

		if (isset($p[2])) {
			if (isset($p['fresh'])) {
				return $this->jacobianDoublePointMixed($p);
			}
			return $this->jacobianDoublePoint($p);
		}

		list($numerator, $denominator) = $this->doublePointHelper($p);

		$slope = $numerator->divide($denominator);

		$x = $slope->multiply($slope)->subtract($p[0])->subtract($p[0]);
		$y = $slope->multiply($p[0]->subtract($x))->subtract($p[1]);

		return [$x, $y];
	}

	public function derivePoint($m)
	{
		$y = ord(Strings::shift($m));
		$x = new BigInteger($m, 256);
		$xp = $this->convertInteger($x);
		switch ($y) {
			case 2:
				$ypn = false;
				break;
			case 3:
				$ypn = true;
				break;
			default:
				throw new \RuntimeException('Coordinate not in recognized format');
		}
		$temp = $xp->multiply($this->a);
		$temp = $xp->multiply($xp)->multiply($xp)->add($temp);
		$temp = $temp->add($this->b);
		$b = $temp->squareRoot();
		if (!$b) {
			throw new \RuntimeException('Unable to derive Y coordinate');
		}
		$bn = $b->isOdd();
		$yp = $ypn == $bn ? $b : $b->negate();
		return [$xp, $yp];
	}

	public function verifyPoint(array $p)
	{
		list($x, $y) = $p;
		$lhs = $y->multiply($y);
		$temp = $x->multiply($this->a);
		$temp = $x->multiply($x)->multiply($x)->add($temp);
		$rhs = $temp->add($this->b);

		return $lhs->equals($rhs);
	}

	public function getModulo()
	{
		return $this->modulo;
	}

	public function getA()
	{
		return $this->a;
	}

	public function getB()
	{
		return $this->b;
	}

	public function multiplyAddPoints(array $points, array $scalars)
	{
		$length = count($points);

		foreach ($points as &$point) {
			$point = $this->convertToInternal($point);
		}

		$wnd = [$this->getNAFPoints($points[0], 7)];
		$wndWidth = [isset($points[0]['nafwidth']) ? $points[0]['nafwidth'] : 7];
		for ($i = 1; $i < $length; $i++) {
			$wnd[] = $this->getNAFPoints($points[$i], 1);
			$wndWidth[] = isset($points[$i]['nafwidth']) ? $points[$i]['nafwidth'] : 1;
		}

		$naf = [];

		$max = 0;
		for ($i = $length - 1; $i >= 1; $i -= 2) {
			$a = $i - 1;
			$b = $i;
			if ($wndWidth[$a] != 1 || $wndWidth[$b] != 1) {
				$naf[$a] = $scalars[$a]->getNAF($wndWidth[$a]);
				$naf[$b] = $scalars[$b]->getNAF($wndWidth[$b]);
				$max = max(count($naf[$a]), count($naf[$b]), $max);
				continue;
			}

			$comb = [
				$points[$a],
				null,
				null,
				$points[$b]
			];

			$comb[1] = $this->addPoint($points[$a], $points[$b]);
			$comb[2] = $this->addPoint($points[$a], $this->negatePoint($points[$b]));

			$index = [
				-3,
				-1,
				-5,
				-7,
				 0,
				 7,
				 5,
				 1,
				 3
			];

			$jsf = self::getJSFPoints($scalars[$a], $scalars[$b]);

			$max = max(count($jsf[0]), $max);
			if ($max > 0) {
				$naf[$a] = array_fill(0, $max, 0);
				$naf[$b] = array_fill(0, $max, 0);
			} else {
				$naf[$a] = [];
				$naf[$b] = [];
			}

			for ($j = 0; $j < $max; $j++) {
				$ja = isset($jsf[0][$j]) ? $jsf[0][$j] : 0;
				$jb = isset($jsf[1][$j]) ? $jsf[1][$j] : 0;

				$naf[$a][$j] = $index[3 * ($ja + 1) + $jb + 1];
				$naf[$b][$j] = 0;
				$wnd[$a] = $comb;
			}
		}

		$acc = [];
		$temp = [0, 0, 0, 0];
		for ($i = $max; $i >= 0; $i--) {
			$k = 0;
			while ($i >= 0) {
				$zero = true;
				for ($j = 0; $j < $length; $j++) {
					$temp[$j] = isset($naf[$j][$i]) ? $naf[$j][$i] : 0;
					if ($temp[$j] != 0) {
						$zero = false;
					}
				}
				if (!$zero) {
					break;
				}
				$k++;
				$i--;
			}

			if ($i >= 0) {
				$k++;
			}
			while ($k--) {
				$acc = $this->doublePoint($acc);
			}

			if ($i < 0) {
				break;
			}

			for ($j = 0; $j < $length; $j++) {
				$z = $temp[$j];
				$p = null;
				if ($z == 0) {
					continue;
				}
				$p = $z > 0 ?
					$wnd[$j][($z - 1) >> 1] :
					$this->negatePoint($wnd[$j][(-$z - 1) >> 1]);
				$acc = $this->addPoint($acc, $p);
			}
		}

		return $this->convertToAffine($acc);
	}

	private function getNAFPoints(array $point, $wnd)
	{
		if (isset($point['naf'])) {
			return $point['naf'];
		}

		$res = [$point];
		$max = (1 << $wnd) - 1;
		$dbl = $max == 1 ? null : $this->doublePoint($point);
		for ($i = 1; $i < $max; $i++) {
			$res[] = $this->addPoint($res[$i - 1], $dbl);
		}

		$point['naf'] = $res;

		return $res;
	}

	private static function getJSFPoints(Integer $k1, Integer $k2)
	{
		static $three;
		if (!isset($three)) {
			$three = new BigInteger(3);
		}

		$jsf = [[], []];
		$k1 = $k1->toBigInteger();
		$k2 = $k2->toBigInteger();
		$d1 = 0;
		$d2 = 0;

		while ($k1->compare(new BigInteger(-$d1)) > 0 || $k2->compare(new BigInteger(-$d2)) > 0) {

			$m14 = $k1->testBit(0) + 2 * $k1->testBit(1);
			$m14 += $d1;
			$m14 &= 3;

			$m24 = $k2->testBit(0) + 2 * $k2->testBit(1);
			$m24 += $d2;
			$m24 &= 3;

			if ($m14 == 3) {
				$m14 = -1;
			}
			if ($m24 == 3) {
				$m24 = -1;
			}

			$u1 = 0;
			if ($m14 & 1) {
				$m8 = $k1->testBit(0) + 2 * $k1->testBit(1) + 4 * $k1->testBit(2);
				$m8 += $d1;
				$m8 &= 7;
				$u1 = ($m8 == 3 || $m8 == 5) && $m24 == 2 ? -$m14 : $m14;
			}
			$jsf[0][] = $u1;

			$u2 = 0;
			if ($m24 & 1) {
				$m8 = $k2->testBit(0) + 2 * $k2->testBit(1) + 4 * $k2->testBit(2);
				$m8 += $d2;
				$m8 &= 7;
				$u2 = ($m8 == 3 || $m8 == 5) && $m14 == 2 ? -$m24 : $m24;
			}
			$jsf[1][] = $u2;

			if (2 * $d1 == $u1 + 1) {
				$d1 = 1 - $d1;
			}
			if (2 * $d2 == $u2 + 1) {
				$d2 = 1 - $d2;
			}
			$k1 = $k1->bitwise_rightShift(1);
			$k2 = $k2->bitwise_rightShift(1);
		}

		return $jsf;
	}

	public function convertToAffine(array $p)
	{
		if (!isset($p[2])) {
			return $p;
		}
		list($x, $y, $z) = $p;
		$z = $this->one->divide($z);
		$z2 = $z->multiply($z);
		return [
			$x->multiply($z2),
			$y->multiply($z2)->multiply($z)
		];
	}

	public function convertToInternal(array $p)
	{
		if (isset($p[2])) {
			return $p;
		}

		$p[2] = clone $this->one;
		$p['fresh'] = true;
		return $p;
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;

class KoblitzPrime extends Prime
{

	protected $basis;

	protected $beta;

	public function multiplyAddPoints(array $points, array $scalars)
	{
		static $zero, $one, $two;
		if (!isset($two)) {
			$two = new BigInteger(2);
			$one = new BigInteger(1);
		}

		if (!isset($this->beta)) {

			$inv = $this->one->divide($this->two)->negate();
			$s = $this->three->negate()->squareRoot()->multiply($inv);
			$betas = [
				$inv->add($s),
				$inv->subtract($s)
			];
			$this->beta = $betas[0]->compare($betas[1]) < 0 ? $betas[0] : $betas[1];

		}

		if (!isset($this->basis)) {
			$factory = new PrimeField($this->order);
			$tempOne = $factory->newInteger($one);
			$tempTwo = $factory->newInteger($two);
			$tempThree = $factory->newInteger(new BigInteger(3));

			$inv = $tempOne->divide($tempTwo)->negate();
			$s = $tempThree->negate()->squareRoot()->multiply($inv);

			$lambdas = [
				$inv->add($s),
				$inv->subtract($s)
			];

			$lhs = $this->multiplyPoint($this->p, $lambdas[0])[0];
			$rhs = $this->p[0]->multiply($this->beta);
			$lambda = $lhs->equals($rhs) ? $lambdas[0] : $lambdas[1];

			$this->basis = static::extendedGCD($lambda->toBigInteger(), $this->order);

			foreach ($this->basis as $basis) {
				echo strtoupper($basis['a']->toHex(true)) . "\n";
				echo strtoupper($basis['b']->toHex(true)) . "\n\n";
			}
			exit;

		}

		$npoints = $nscalars = [];
		for ($i = 0; $i < count($points); $i++) {
			$p = $points[$i];
			$k = $scalars[$i]->toBigInteger();

			list($v1, $v2) = $this->basis;

			$c1 = $v2['b']->multiply($k);
			list($c1, $r) = $c1->divide($this->order);
			if ($this->order->compare($r->multiply($two)) <= 0) {
				$c1 = $c1->add($one);
			}

			$c2 = $v1['b']->negate()->multiply($k);
			list($c2, $r) = $c2->divide($this->order);
			if ($this->order->compare($r->multiply($two)) <= 0) {
				$c2 = $c2->add($one);
			}

			$p1 = $c1->multiply($v1['a']);
			$p2 = $c2->multiply($v2['a']);
			$q1 = $c1->multiply($v1['b']);
			$q2 = $c2->multiply($v2['b']);

			$k1 = $k->subtract($p1)->subtract($p2);
			$k2 = $q1->add($q2)->negate();

			$beta = [
				$p[0]->multiply($this->beta),
				$p[1],
				clone $this->one
			];

			if (isset($p['naf'])) {
				$beta['naf'] = array_map(function ($p) {
					return [
						$p[0]->multiply($this->beta),
						$p[1],
						clone $this->one
					];
				}, $p['naf']);
				$beta['nafwidth'] = $p['nafwidth'];
			}

			if ($k1->isNegative()) {
				$k1 = $k1->negate();
				$p = $this->negatePoint($p);
			}

			if ($k2->isNegative()) {
				$k2 = $k2->negate();
				$beta = $this->negatePoint($beta);
			}

			$pos = 2 * $i;
			$npoints[$pos] = $p;
			$nscalars[$pos] = $this->factory->newInteger($k1);

			$pos++;
			$npoints[$pos] = $beta;
			$nscalars[$pos] = $this->factory->newInteger($k2);
		}

		return parent::multiplyAddPoints($npoints, $nscalars);
	}

	protected function doublePointHelper(array $p)
	{
		$numerator = $this->three->multiply($p[0])->multiply($p[0]);
		$denominator = $this->two->multiply($p[1]);
		return [$numerator, $denominator];
	}

	protected function jacobianDoublePoint(array $p)
	{
		list($x1, $y1, $z1) = $p;
		$a = $x1->multiply($x1);
		$b = $y1->multiply($y1);
		$c = $b->multiply($b);
		$d = $x1->add($b);
		$d = $d->multiply($d)->subtract($a)->subtract($c)->multiply($this->two);
		$e = $this->three->multiply($a);
		$f = $e->multiply($e);
		$x3 = $f->subtract($this->two->multiply($d));
		$y3 = $e->multiply($d->subtract($x3))->subtract(
			$this->eight->multiply($c)
		);
		$z3 = $this->two->multiply($y1)->multiply($z1);
		return [$x3, $y3, $z3];
	}

	protected function jacobianDoublePointMixed(array $p)
	{
		list($x1, $y1) = $p;
		$xx = $x1->multiply($x1);
		$yy = $y1->multiply($y1);
		$yyyy = $yy->multiply($yy);
		$s = $x1->add($yy);
		$s = $s->multiply($s)->subtract($xx)->subtract($yyyy)->multiply($this->two);
		$m = $this->three->multiply($xx);
		$t = $m->multiply($m)->subtract($this->two->multiply($s));
		$x3 = $t;
		$y3 = $s->subtract($t);
		$y3 = $m->multiply($y3)->subtract($this->eight->multiply($yyyy));
		$z3 = $this->two->multiply($y1);
		return [$x3, $y3, $z3];
	}

	public function verifyPoint(array $p)
	{
		list($x, $y) = $p;
		$lhs = $y->multiply($y);
		$temp = $x->multiply($x)->multiply($x);
		$rhs = $temp->add($this->b);

		return $lhs->equals($rhs);
	}

	protected static function extendedGCD(BigInteger $u, BigInteger $v)
	{
		$one = new BigInteger(1);
		$zero = new BigInteger();

		$a = clone $one;
		$b = clone $zero;
		$c = clone $zero;
		$d = clone $one;

		$stop = $v->bitwise_rightShift($v->getLength() >> 1);

		$a1 = clone $zero;
		$b1 = clone $zero;
		$a2 = clone $zero;
		$b2 = clone $zero;

		$postGreatestIndex = 0;

		while (!$v->equals($zero)) {
			list($q) = $u->divide($v);

			$temp = $u;
			$u = $v;
			$v = $temp->subtract($v->multiply($q));

			$temp = $a;
			$a = $c;
			$c = $temp->subtract($a->multiply($q));

			$temp = $b;
			$b = $d;
			$d = $temp->subtract($b->multiply($q));

			if ($v->compare($stop) > 0) {
				$a0 = $v;
				$b0 = $c;
			} else {
				$postGreatestIndex++;
			}

			if ($postGreatestIndex == 1) {
				$a1 = $v;
				$b1 = $c->negate();
			}

			if ($postGreatestIndex == 2) {
				$rhs = $a0->multiply($a0)->add($b0->multiply($b0));
				$lhs = $v->multiply($v)->add($b->multiply($b));
				if ($lhs->compare($rhs) <= 0) {
					$a2 = $a0;
					$b2 = $b0->negate();
				} else {
					$a2 = $v;
					$b2 = $c->negate();
				}

				break;
			}
		}

		return [
			['a' => $a1, 'b' => $b1],
			['a' => $a2, 'b' => $b2]
		];
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;
use phpseclib3\Math\PrimeField\Integer as PrimeInteger;

class Montgomery extends Base
{

	protected $factory;

	protected $a;

	protected $a24;

	protected $zero;

	protected $one;

	protected $p;

	protected $modulo;

	protected $order;

	public function setModulo(BigInteger $modulo)
	{
		$this->modulo = $modulo;
		$this->factory = new PrimeField($modulo);
		$this->zero = $this->factory->newInteger(new BigInteger());
		$this->one = $this->factory->newInteger(new BigInteger(1));
	}

	public function setCoefficients(BigInteger $a)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->a = $this->factory->newInteger($a);
		$two = $this->factory->newInteger(new BigInteger(2));
		$four = $this->factory->newInteger(new BigInteger(4));
		$this->a24 = $this->a->subtract($two)->divide($four);
	}

	public function setBasePoint($x, $y)
	{
		switch (true) {
			case !$x instanceof BigInteger && !$x instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 1 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
			case !$y instanceof BigInteger && !$y instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 2 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
		}
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->p = [
			$x instanceof BigInteger ? $this->factory->newInteger($x) : $x,
			$y instanceof BigInteger ? $this->factory->newInteger($y) : $y
		];
	}

	public function getBasePoint()
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		return $this->p;
	}

	private function doubleAndAddPoint(array $p, array $q, PrimeInteger $x1)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p) || !count($q)) {
			return [];
		}

		if (!isset($p[1])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to XZ coordinates');
		}

		list($x2, $z2) = $p;
		list($x3, $z3) = $q;

		$a = $x2->add($z2);
		$aa = $a->multiply($a);
		$b = $x2->subtract($z2);
		$bb = $b->multiply($b);
		$e = $aa->subtract($bb);
		$c = $x3->add($z3);
		$d = $x3->subtract($z3);
		$da = $d->multiply($a);
		$cb = $c->multiply($b);
		$temp = $da->add($cb);
		$x5 = $temp->multiply($temp);
		$temp = $da->subtract($cb);
		$z5 = $x1->multiply($temp->multiply($temp));
		$x4 = $aa->multiply($bb);
		$temp = static::class == Curve25519::class ? $bb : $aa;
		$z4 = $e->multiply($temp->add($this->a24->multiply($e)));

		return [
			[$x4, $z4],
			[$x5, $z5]
		];
	}

	public function multiplyPoint(array $p, BigInteger $d)
	{
		$p1 = [$this->one, $this->zero];
		$alreadyInternal = isset($p[1]);
		$p2 = $this->convertToInternal($p);
		$x = $p[0];

		$b = $d->toBits();
		$b = str_pad($b, 256, '0', STR_PAD_LEFT);
		for ($i = 0; $i < strlen($b); $i++) {
			$b_i = (int) $b[$i];
			if ($b_i) {
				list($p2, $p1) = $this->doubleAndAddPoint($p2, $p1, $x);
			} else {
				list($p1, $p2) = $this->doubleAndAddPoint($p1, $p2, $x);
			}
		}

		return $alreadyInternal ? $p1 : $this->convertToAffine($p1);
	}

	public function convertToInternal(array $p)
	{
		if (empty($p)) {
			return [clone $this->zero, clone $this->one];
		}

		if (isset($p[1])) {
			return $p;
		}

		$p[1] = clone $this->one;

		return $p;
	}

	public function convertToAffine(array $p)
	{
		if (!isset($p[1])) {
			return $p;
		}
		list($x, $z) = $p;
		return [$x->divide($z)];
	}
}
}

namespace phpseclib3\Crypt\EC\BaseCurves {

use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;
use phpseclib3\Math\PrimeField\Integer as PrimeInteger;

class TwistedEdwards extends Base
{

	protected $modulo;

	protected $a;

	protected $d;

	protected $p;

	protected $zero;

	protected $one;

	protected $two;

	public function setModulo(BigInteger $modulo)
	{
		$this->modulo = $modulo;
		$this->factory = new PrimeField($modulo);
		$this->zero = $this->factory->newInteger(new BigInteger(0));
		$this->one = $this->factory->newInteger(new BigInteger(1));
		$this->two = $this->factory->newInteger(new BigInteger(2));
	}

	public function setCoefficients(BigInteger $a, BigInteger $d)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->a = $this->factory->newInteger($a);
		$this->d = $this->factory->newInteger($d);
	}

	public function setBasePoint($x, $y)
	{
		switch (true) {
			case !$x instanceof BigInteger && !$x instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 1 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
			case !$y instanceof BigInteger && !$y instanceof PrimeInteger:
				throw new \UnexpectedValueException('Argument 2 passed to Prime::setBasePoint() must be an instance of either BigInteger or PrimeField\Integer');
		}
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}
		$this->p = [
			$x instanceof BigInteger ? $this->factory->newInteger($x) : $x,
			$y instanceof BigInteger ? $this->factory->newInteger($y) : $y
		];
	}

	public function getA()
	{
		return $this->a;
	}

	public function getD()
	{
		return $this->d;
	}

	public function getBasePoint()
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		return $this->p;
	}

	public function convertToAffine(array $p)
	{
		if (!isset($p[2])) {
			return $p;
		}
		list($x, $y, $z) = $p;
		$z = $this->one->divide($z);
		return [
			$x->multiply($z),
			$y->multiply($z)
		];
	}

	public function getModulo()
	{
		return $this->modulo;
	}

	public function verifyPoint(array $p)
	{
		list($x, $y) = $p;
		$x2 = $x->multiply($x);
		$y2 = $y->multiply($y);

		$lhs = $this->a->multiply($x2)->add($y2);
		$rhs = $this->d->multiply($x2)->multiply($y2)->add($this->one);

		return $lhs->equals($rhs);
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP160r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('E95E4A5F737059DC60DFC7AD95B3D8139515620F', 16));
		$this->setCoefficients(
			new BigInteger('340E7BE2A280EB74E2BE61BADA745D97E8F7C300', 16),
			new BigInteger('1E589A8595423412134FAA2DBDEC95C8D8675E58', 16)
		);
		$this->setBasePoint(
			new BigInteger('BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3', 16),
			new BigInteger('1667CB477A1A8EC338F94741669C976316DA6321', 16)
		);
		$this->setOrder(new BigInteger('E95E4A5F737059DC60DF5991D45029409E60FC09', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP160t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('E95E4A5F737059DC60DFC7AD95B3D8139515620F', 16));
		$this->setCoefficients(
			new BigInteger('E95E4A5F737059DC60DFC7AD95B3D8139515620C', 16),
			new BigInteger('7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380', 16)
		);
		$this->setBasePoint(
			new BigInteger('B199B13B9B34EFC1397E64BAEB05ACC265FF2378', 16),
			new BigInteger('ADD6718B7C7C1961F0991B842443772152C9E0AD', 16)
		);
		$this->setOrder(new BigInteger('E95E4A5F737059DC60DF5991D45029409E60FC09', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP192r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297', 16));
		$this->setCoefficients(
			new BigInteger('6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF', 16),
			new BigInteger('469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9', 16)
		);
		$this->setBasePoint(
			new BigInteger('C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6', 16),
			new BigInteger('14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F', 16)
		);
		$this->setOrder(new BigInteger('C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP192t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297', 16));
		$this->setCoefficients(
			new BigInteger('C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294', 16),
			new BigInteger('13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79', 16)
		);
		$this->setBasePoint(
			new BigInteger('3AE9E58C82F63C30282E1FE7BBF43FA72C446AF6F4618129', 16),
			new BigInteger('097E2C5667C2223A902AB5CA449D0084B7E5B3DE7CCC01C9', 16)
		);
		$this->setOrder(new BigInteger('C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP224r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF', 16));
		$this->setCoefficients(
			new BigInteger('68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43', 16),
			new BigInteger('2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B', 16)
		);
		$this->setBasePoint(
			new BigInteger('0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D', 16),
			new BigInteger('58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD', 16)
		);
		$this->setOrder(new BigInteger('D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP224t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF', 16));
		$this->setCoefficients(
			new BigInteger('D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC', 16),
			new BigInteger('4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D', 16)
		);
		$this->setBasePoint(
			new BigInteger('6AB1E344CE25FF3896424E7FFE14762ECB49F8928AC0C76029B4D580', 16),
			new BigInteger('0374E9F5143E568CD23F3F4D7C0D4B1E41C8CC0D1C6ABD5F1A46DB4C', 16)
		);
		$this->setOrder(new BigInteger('D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP256r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16));
		$this->setCoefficients(
			new BigInteger('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9', 16),
			new BigInteger('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', 16)
		);
		$this->setBasePoint(
			new BigInteger('8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262', 16),
			new BigInteger('547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997', 16)
		);
		$this->setOrder(new BigInteger('A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP256t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16));
		$this->setCoefficients(
			new BigInteger('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374', 16),
			new BigInteger('662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04', 16)
		);
		$this->setBasePoint(
			new BigInteger('A3E8EB3CC1CFE7B7732213B23A656149AFA142C47AAFBC2B79A191562E1305F4', 16),
			new BigInteger('2D996C823439C56D7F7B22E14644417E69BCB6DE39D027001DABE8F35B25C9BE', 16)
		);
		$this->setOrder(new BigInteger('A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP320r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F9' .
										'2B9EC7893EC28FCD412B1F1B32E27', 16));
		$this->setCoefficients(
			new BigInteger('3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F4' .
							'92F375A97D860EB4', 16),
			new BigInteger('520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD88453981' .
							'6F5EB4AC8FB1F1A6', 16)
		);
		$this->setBasePoint(
			new BigInteger('43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C7' .
							'10AF8D0D39E20611', 16),
			new BigInteger('14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7' .
							'D35245D1692E8EE1', 16)
		);
		$this->setOrder(new BigInteger('D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D4' .
										'82EC7EE8658E98691555B44C59311', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP320t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F9' .
										'2B9EC7893EC28FCD412B1F1B32E27', 16));
		$this->setCoefficients(
			new BigInteger('D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28' .
							'FCD412B1F1B32E24', 16),
			new BigInteger('A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CE' .
							'B5B4FEF422340353', 16)
		);
		$this->setBasePoint(
			new BigInteger('925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF' .
							'3357F624A21BED52', 16),
			new BigInteger('63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B' .
							'1B9BC0455FB0D2C3', 16)
		);
		$this->setOrder(new BigInteger('D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D4' .
										'82EC7EE8658E98691555B44C59311', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP384r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger(
			'8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A7' .
			'1874700133107EC53',
			16
		));
		$this->setCoefficients(
			new BigInteger(
				'7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503' .
				'AD4EB04A8C7DD22CE2826',
				16
			),
			new BigInteger(
				'4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DB' .
				'C9943AB78696FA504C11',
				16
			)
		);
		$this->setBasePoint(
			new BigInteger(
				'1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D' .
				'646AAEF87B2E247D4AF1E',
				16
			),
			new BigInteger(
				'8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E464621779' .
				'1811142820341263C5315',
				16
			)
		);
		$this->setOrder(new BigInteger(
			'8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC31' .
			'03B883202E9046565',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP384t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger(
			'8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A7' .
			'1874700133107EC53',
			16
		));
		$this->setCoefficients(
			new BigInteger(
				'8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901' .
				'D1A71874700133107EC50',
				16
			),
			new BigInteger(
				'7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B8' .
				'8805CED70355A33B471EE',
				16
			)
		);
		$this->setBasePoint(
			new BigInteger(
				'18DE98B02DB9A306F2AFCD7235F72A819B80AB12EBD653172476FECD462AABFFC4FF191B946' .
				'A5F54D8D0AA2F418808CC',
				16
			),
			new BigInteger(
				'25AB056962D30651A114AFD2755AD336747F93475B7A1FCA3B88F2B6A208CCFE469408584DC' .
				'2B2912675BF5B9E582928',
				16
			)
		);
		$this->setOrder(new BigInteger(
			'8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC31' .
			'03B883202E9046565',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP512r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger(
			'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC' .
			'66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3',
			16
		));
		$this->setCoefficients(
			new BigInteger(
				'7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA82' .
				'53AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA',
				16
			),
			new BigInteger(
				'3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C' .
				'1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723',
				16
			)
		);
		$this->setBasePoint(
			new BigInteger(
				'81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D' .
				'0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822',
				16
			),
			new BigInteger(
				'7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5' .
				'F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892',
				16
			)
		);
		$this->setOrder(new BigInteger(
			'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA' .
			'92619418661197FAC10471DB1D381085DDADDB58796829CA90069',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class brainpoolP512t1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger(
			'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC' .
			'66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3',
			16
		));
		$this->setCoefficients(
			new BigInteger(
				'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC' .
				'66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0',
				16
			),
			new BigInteger(
				'7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA23049' .
				'76540F6450085F2DAE145C22553B465763689180EA2571867423E',
				16
			)
		);
		$this->setBasePoint(
			new BigInteger(
				'640ECE5C12788717B9C1BA06CBC2A6FEBA85842458C56DDE9DB1758D39C0313D82BA51735CD' .
				'B3EA499AA77A7D6943A64F7A3F25FE26F06B51BAA2696FA9035DA',
				16
			),
			new BigInteger(
				'5B534BD595F5AF0FA2C892376C84ACE1BB4E3019B71634C01131159CAE03CEE9D9932184BEE' .
				'F216BD71DF2DADF86A627306ECFF96DBB8BACE198B61E00F8B332',
				16
			)
		);
		$this->setOrder(new BigInteger(
			'AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA' .
			'92619418661197FAC10471DB1D381085DDADDB58796829CA90069',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Montgomery;
use phpseclib3\Math\BigInteger;

class Curve25519 extends Montgomery
{
	public function __construct()
	{

		$this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED', 16));
		$this->a24 = $this->factory->newInteger(new BigInteger('121666'));
		$this->p = [$this->factory->newInteger(new BigInteger(9))];

		$this->setOrder(new BigInteger('1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED', 16));

	}

	public function multiplyPoint(array $p, BigInteger $d)
	{

		$d = $d->toBytes();
		$d &= "\xF8" . str_repeat("\xFF", 30) . "\x7F";
		$d = strrev($d);
		$d |= "\x40";
		$d = new BigInteger($d, -256);

		return parent::multiplyPoint($p, $d);
	}

	public function createRandomMultiplier()
	{
		return BigInteger::random(256);
	}

	public function rangeCheck(BigInteger $x)
	{
		if ($x->getLength() > 256 || $x->isNegative()) {
			throw new \RangeException('x must be a positive integer less than 256 bytes in length');
		}
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Montgomery;
use phpseclib3\Math\BigInteger;

class Curve448 extends Montgomery
{
	public function __construct()
	{

		$this->setModulo(new BigInteger(
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE' .
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
			16
		));
		$this->a24 = $this->factory->newInteger(new BigInteger('39081'));
		$this->p = [$this->factory->newInteger(new BigInteger(5))];

		$this->setOrder(new BigInteger(
			'3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
			'7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3',
			16
		));

	}

	public function multiplyPoint(array $p, BigInteger $d)
	{

		$d = $d->toBytes();
		$d[0] = $d[0] & "\xFC";
		$d = strrev($d);
		$d |= "\x80";
		$d = new BigInteger($d, 256);

		return parent::multiplyPoint($p, $d);
	}

	public function createRandomMultiplier()
	{
		return BigInteger::random(446);
	}

	public function rangeCheck(BigInteger $x)
	{
		if ($x->getLength() > 448 || $x->isNegative()) {
			throw new \RangeException('x must be a positive integer less than 446 bytes in length');
		}
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;

class Ed25519 extends TwistedEdwards
{
	const HASH = 'sha512';

	const SIZE = 32;

	public function __construct()
	{

		$this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED', 16));
		$this->setCoefficients(

			new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC', 16),

			new BigInteger('52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3', 16)
		);
		$this->setBasePoint(
			new BigInteger('216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A', 16),
			new BigInteger('6666666666666666666666666666666666666666666666666666666666666658', 16)
		);
		$this->setOrder(new BigInteger('1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED', 16));

	}

	public function recoverX(BigInteger $y, $sign)
	{
		$y = $this->factory->newInteger($y);

		$y2 = $y->multiply($y);
		$u = $y2->subtract($this->one);
		$v = $this->d->multiply($y2)->add($this->one);
		$x2 = $u->divide($v);
		if ($x2->equals($this->zero)) {
			if ($sign) {
				throw new \RuntimeException('Unable to recover X coordinate (x2 = 0)');
			}
			return clone $this->zero;
		}

		$exp = $this->getModulo()->add(new BigInteger(3));
		$exp = $exp->bitwise_rightShift(3);
		$x = $x2->pow($exp);

		if (!$x->multiply($x)->subtract($x2)->equals($this->zero)) {
			$temp = $this->getModulo()->subtract(new BigInteger(1));
			$temp = $temp->bitwise_rightShift(2);
			$temp = $this->two->pow($temp);
			$x = $x->multiply($temp);
			if (!$x->multiply($x)->subtract($x2)->equals($this->zero)) {
				throw new \RuntimeException('Unable to recover X coordinate');
			}
		}
		if ($x->isOdd() != $sign) {
			$x = $x->negate();
		}

		return [$x, $y];
	}

	public function extractSecret($str)
	{
		if (strlen($str) != 32) {
			throw new \LengthException('Private Key should be 32-bytes long');
		}

		$hash = new Hash('sha512');
		$h = $hash->hash($str);
		$h = substr($h, 0, 32);

		$h[0] = $h[0] & chr(0xF8);
		$h = strrev($h);
		$h[0] = ($h[0] & chr(0x3F)) | chr(0x40);

		$dA = new BigInteger($h, 256);

		return [
			'dA' => $dA,
			'secret' => $str
		];
	}

	public function encodePoint($point)
	{
		list($x, $y) = $point;
		$y = $y->toBytes();
		$y[0] = $y[0] & chr(0x7F);
		if ($x->isOdd()) {
			$y[0] = $y[0] | chr(0x80);
		}
		$y = strrev($y);

		return $y;
	}

	public function createRandomMultiplier()
	{
		return $this->extractSecret(Random::string(32))['dA'];
	}

	public function convertToInternal(array $p)
	{
		if (empty($p)) {
			return [clone $this->zero, clone $this->one, clone $this->one, clone $this->zero];
		}

		if (isset($p[2])) {
			return $p;
		}

		$p[2] = clone $this->one;
		$p[3] = $p[0]->multiply($p[1]);

		return $p;
	}

	public function doublePoint(array $p)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p)) {
			return [];
		}

		if (!isset($p[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		list($x1, $y1, $z1, $t1) = $p;

		$a = $x1->multiply($x1);
		$b = $y1->multiply($y1);
		$c = $this->two->multiply($z1)->multiply($z1);
		$h = $a->add($b);
		$temp = $x1->add($y1);
		$e = $h->subtract($temp->multiply($temp));
		$g = $a->subtract($b);
		$f = $c->add($g);

		$x3 = $e->multiply($f);
		$y3 = $g->multiply($h);
		$t3 = $e->multiply($h);
		$z3 = $f->multiply($g);

		return [$x3, $y3, $z3, $t3];
	}

	public function addPoint(array $p, array $q)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p) || !count($q)) {
			if (count($q)) {
				return $q;
			}
			if (count($p)) {
				return $p;
			}
			return [];
		}

		if (!isset($p[2]) || !isset($q[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		if ($p[0]->equals($q[0])) {
			return !$p[1]->equals($q[1]) ? [] : $this->doublePoint($p);
		}

		list($x1, $y1, $z1, $t1) = $p;
		list($x2, $y2, $z2, $t2) = $q;

		$a = $y1->subtract($x1)->multiply($y2->subtract($x2));
		$b = $y1->add($x1)->multiply($y2->add($x2));
		$c = $t1->multiply($this->two)->multiply($this->d)->multiply($t2);
		$d = $z1->multiply($this->two)->multiply($z2);
		$e = $b->subtract($a);
		$f = $d->subtract($c);
		$g = $d->add($c);
		$h = $b->add($a);

		$x3 = $e->multiply($f);
		$y3 = $g->multiply($h);
		$t3 = $e->multiply($h);
		$z3 = $f->multiply($g);

		return [$x3, $y3, $z3, $t3];
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\Random;
use phpseclib3\Math\BigInteger;

class Ed448 extends TwistedEdwards
{
	const HASH = 'shake256-912';
	const SIZE = 57;

	public function __construct()
	{

		$this->setModulo(new BigInteger(
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE' .
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
			16
		));
		$this->setCoefficients(
			new BigInteger(1),

			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE' .
							'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756', 16)
		);
		$this->setBasePoint(
			new BigInteger('4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324' .
							'A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E', 16),
			new BigInteger('693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E' .
							'05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14', 16)
		);
		$this->setOrder(new BigInteger(
			'3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
			'7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3',
			16
		));
	}

	public function recoverX(BigInteger $y, $sign)
	{
		$y = $this->factory->newInteger($y);

		$y2 = $y->multiply($y);
		$u = $y2->subtract($this->one);
		$v = $this->d->multiply($y2)->subtract($this->one);
		$x2 = $u->divide($v);
		if ($x2->equals($this->zero)) {
			if ($sign) {
				throw new \RuntimeException('Unable to recover X coordinate (x2 = 0)');
			}
			return clone $this->zero;
		}

		$exp = $this->getModulo()->add(new BigInteger(1));
		$exp = $exp->bitwise_rightShift(2);
		$x = $x2->pow($exp);

		if (!$x->multiply($x)->subtract($x2)->equals($this->zero)) {
			throw new \RuntimeException('Unable to recover X coordinate');
		}
		if ($x->isOdd() != $sign) {
			$x = $x->negate();
		}

		return [$x, $y];
	}

	public function extractSecret($str)
	{
		if (strlen($str) != 57) {
			throw new \LengthException('Private Key should be 57-bytes long');
		}

		$hash = new Hash('shake256-912');
		$h = $hash->hash($str);
		$h = substr($h, 0, 57);

		$h[0] = $h[0] & chr(0xFC);
		$h = strrev($h);
		$h[0] = "\0";
		$h[1] = $h[1] | chr(0x80);

		$dA = new BigInteger($h, 256);

		return [
			'dA' => $dA,
			'secret' => $str
		];

		$dA->secret = $str;
		return $dA;
	}

	public function encodePoint($point)
	{
		list($x, $y) = $point;
		$y = "\0" . $y->toBytes();
		if ($x->isOdd()) {
			$y[0] = $y[0] | chr(0x80);
		}
		$y = strrev($y);

		return $y;
	}

	public function createRandomMultiplier()
	{
		return $this->extractSecret(Random::string(57))['dA'];
	}

	public function convertToInternal(array $p)
	{
		if (empty($p)) {
			return [clone $this->zero, clone $this->one, clone $this->one];
		}

		if (isset($p[2])) {
			return $p;
		}

		$p[2] = clone $this->one;

		return $p;
	}

	public function doublePoint(array $p)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p)) {
			return [];
		}

		if (!isset($p[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		list($x1, $y1, $z1) = $p;

		$b = $x1->add($y1);
		$b = $b->multiply($b);
		$c = $x1->multiply($x1);
		$d = $y1->multiply($y1);
		$e = $c->add($d);
		$h = $z1->multiply($z1);
		$j = $e->subtract($this->two->multiply($h));

		$x3 = $b->subtract($e)->multiply($j);
		$y3 = $c->subtract($d)->multiply($e);
		$z3 = $e->multiply($j);

		return [$x3, $y3, $z3];
	}

	public function addPoint(array $p, array $q)
	{
		if (!isset($this->factory)) {
			throw new \RuntimeException('setModulo needs to be called before this method');
		}

		if (!count($p) || !count($q)) {
			if (count($q)) {
				return $q;
			}
			if (count($p)) {
				return $p;
			}
			return [];
		}

		if (!isset($p[2]) || !isset($q[2])) {
			throw new \RuntimeException('Affine coordinates need to be manually converted to "Jacobi" coordinates or vice versa');
		}

		if ($p[0]->equals($q[0])) {
			return !$p[1]->equals($q[1]) ? [] : $this->doublePoint($p);
		}

		list($x1, $y1, $z1) = $p;
		list($x2, $y2, $z2) = $q;

		$a = $z1->multiply($z2);
		$b = $a->multiply($a);
		$c = $x1->multiply($x2);
		$d = $y1->multiply($y2);
		$e = $this->d->multiply($c)->multiply($d);
		$f = $b->subtract($e);
		$g = $b->add($e);
		$h = $x1->add($y1)->multiply($x2->add($y2));

		$x3 = $a->multiply($f)->multiply($h->subtract($c)->subtract($d));
		$y3 = $a->multiply($g)->multiply($d->subtract($c));
		$z3 = $f->multiply($g);

		return [$x3, $y3, $z3];
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect233r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(233, 74, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000001',
			'0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD'
		);
		$this->setBasePoint(
			'00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B',
			'01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052'
		);
		$this->setOrder(new BigInteger('01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistb233 extends sect233r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect409r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(409, 87, 0);
		$this->setCoefficients(
			'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001',
			'0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F'
		);
		$this->setBasePoint(
			'015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7',
			'0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706'
		);
		$this->setOrder(new BigInteger(
			'010000000000000000000000000000000000000000000000000001E2' .
			'AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistb409 extends sect409r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect163k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(163, 7, 6, 3, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000001',
			'000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8',
			'0289070FB05D38FF58321F2E800536D538CCDAA3D9'
		);
		$this->setOrder(new BigInteger('04000000000000000000020108A2E0CC0D99F8A5EF', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistk163 extends sect163k1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect233k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(233, 74, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000',
			'000000000000000000000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126',
			'01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3'
		);
		$this->setOrder(new BigInteger('8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistk233 extends sect233k1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect283k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(283, 12, 7, 5, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000000000000000',
			'000000000000000000000000000000000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836',
			'01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259'
		);
		$this->setOrder(new BigInteger('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistk283 extends sect283k1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect409k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(409, 87, 0);
		$this->setCoefficients(
			'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
			'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746',
			'01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B'
		);
		$this->setOrder(new BigInteger(
			'7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F' .
			'83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistk409 extends sect409k1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp192r1 extends Prime
{
	public function __construct()
	{
		$modulo = new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF', 16);
		$this->setModulo($modulo);

		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC', 16),
			new BigInteger('64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1', 16)
		);
		$this->setBasePoint(
			new BigInteger('188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012', 16),
			new BigInteger('07192B95FFC8DA78631011ED6B24CDD573F977A11E794811', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistp192 extends secp192r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp224r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE', 16),
			new BigInteger('B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4', 16)
		);
		$this->setBasePoint(
			new BigInteger('B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21', 16),
			new BigInteger('BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistp224 extends secp224r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp256r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC', 16),
			new BigInteger('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B', 16)
		);
		$this->setBasePoint(
			new BigInteger('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296', 16),
			new BigInteger('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistp256 extends secp256r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp384r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger(
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF',
			16
		));
		$this->setCoefficients(
			new BigInteger(
				'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC',
				16
			),
			new BigInteger(
				'B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF',
				16
			)
		);
		$this->setBasePoint(
			new BigInteger(
				'AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7',
				16
			),
			new BigInteger(
				'3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F',
				16
			)
		);
		$this->setOrder(new BigInteger(
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistp384 extends secp384r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp521r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
										'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
										'FFFF', 16));
		$this->setCoefficients(
			new BigInteger('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
							'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
							'FFFC', 16),
			new BigInteger('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1' .
							'09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50' .
							'3F00', 16)
		);
		$this->setBasePoint(
			new BigInteger('00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D' .
							'3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5' .
							'BD66', 16),
			new BigInteger('011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E' .
							'662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1' .
							'6650', 16)
		);
		$this->setOrder(new BigInteger('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
										'FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E9138' .
										'6409', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistp521 extends secp521r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect571k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(571, 10, 5, 2, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000000000000000' .
			'000000000000000000000000000000000000000000000000000000000000000000000000',
			'000000000000000000000000000000000000000000000000000000000000000000000000' .
			'000000000000000000000000000000000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA443709584' .
			'93B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972',
			'0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0' .
			'AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3'
		);
		$this->setOrder(new BigInteger(
			'020000000000000000000000000000000000000000000000000000000000000000000000' .
			'131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001',
			16
		));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class nistt571 extends sect571k1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class prime192v1 extends secp192r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class prime192v2 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC', 16),
			new BigInteger('CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953', 16)
		);
		$this->setBasePoint(
			new BigInteger('EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A', 16),
			new BigInteger('6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class prime192v3 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC', 16),
			new BigInteger('22123DC2395A05CAA7423DAECCC94760A7D462256BD56916', 16)
		);
		$this->setBasePoint(
			new BigInteger('7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896', 16),
			new BigInteger('38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class prime239v1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC', 16),
			new BigInteger('6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A', 16)
		);
		$this->setBasePoint(
			new BigInteger('0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF', 16),
			new BigInteger('7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE', 16)
		);
		$this->setOrder(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class prime239v2 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC', 16),
			new BigInteger('617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C', 16)
		);
		$this->setBasePoint(
			new BigInteger('38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7', 16),
			new BigInteger('5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA', 16)
		);
		$this->setOrder(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class prime239v3 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC', 16),
			new BigInteger('255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E', 16)
		);
		$this->setBasePoint(
			new BigInteger('6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A', 16),
			new BigInteger('1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3', 16)
		);
		$this->setOrder(new BigInteger('7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

final class prime256v1 extends secp256r1
{
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp112r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('DB7C2ABF62E35E668076BEAD208B', 16));
		$this->setCoefficients(
			new BigInteger('DB7C2ABF62E35E668076BEAD2088', 16),
			new BigInteger('659EF8BA043916EEDE8911702B22', 16)
		);
		$this->setBasePoint(
			new BigInteger('09487239995A5EE76B55F9C2F098', 16),
			new BigInteger('A89CE5AF8724C0A23E0E0FF77500', 16)
		);
		$this->setOrder(new BigInteger('DB7C2ABF62E35E7628DFAC6561C5', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp112r2 extends Prime
{
	public function __construct()
	{

		$this->setModulo(new BigInteger('DB7C2ABF62E35E668076BEAD208B', 16));
		$this->setCoefficients(
			new BigInteger('6127C24C05F38A0AAAF65C0EF02C', 16),
			new BigInteger('51DEF1815DB5ED74FCC34C85D709', 16)
		);
		$this->setBasePoint(
			new BigInteger('4BA30AB5E892B4E1649DD0928643', 16),
			new BigInteger('ADCD46F5882E3747DEF36E956E97', 16)
		);
		$this->setOrder(new BigInteger('36DF0AAFD8B8D7597CA10520D04B', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp128r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC', 16),
			new BigInteger('E87579C11079F43DD824993C2CEE5ED3', 16)
		);
		$this->setBasePoint(
			new BigInteger('161FF7528B899B2D0C28607CA52C5B86', 16),
			new BigInteger('CF5AC8395BAFEB13C02DA292DDED7A83', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFE0000000075A30D1B9038A115', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp128r2 extends Prime
{
	public function __construct()
	{

		$this->setModulo(new BigInteger('FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('D6031998D1B3BBFEBF59CC9BBFF9AEE1', 16),
			new BigInteger('5EEEFCA380D02919DC2C6558BB6D8A5D', 16)
		);
		$this->setBasePoint(
			new BigInteger('7B6AA5D85E572983E6FB32A7CDEBC140', 16),
			new BigInteger('27B6916A894D3AEE7106FE805FC34B44', 16)
		);
		$this->setOrder(new BigInteger('3FFFFFFF7FFFFFFFBE0024720613B5A3', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\KoblitzPrime;
use phpseclib3\Math\BigInteger;

class secp160k1 extends KoblitzPrime
{
	public function __construct()
	{

		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73', 16));
		$this->setCoefficients(
			new BigInteger('0000000000000000000000000000000000000000', 16),
			new BigInteger('0000000000000000000000000000000000000007', 16)
		);
		$this->setBasePoint(
			new BigInteger('3B4C382CE37AA192A4019E763036F4F5DD4D7EBB', 16),
			new BigInteger('938CF935318FDCED6BC28286531733C3F03C4FEE', 16)
		);
		$this->setOrder(new BigInteger('0100000000000000000001B8FA16DFAB9ACA16B6B3', 16));

		$this->basis = [];
		$this->basis[] = [
			'a' => new BigInteger('0096341F1138933BC2F505', -16),
			'b' => new BigInteger('FF6E9D0418C67BB8D5F562', -16)
		];
		$this->basis[] = [
			'a' => new BigInteger('01BDCB3A09AAAABEAFF4A8', -16),
			'b' => new BigInteger('04D12329FF0EF498EA67', -16)
		];
		$this->beta = $this->factory->newInteger(new BigInteger('645B7345A143464942CC46D7CF4D5D1E1E6CBB68', -16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp160r1 extends Prime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC', 16),
			new BigInteger('1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45', 16)
		);
		$this->setBasePoint(
			new BigInteger('4A96B5688EF573284664698968C38BB913CBFC82', 16),
			new BigInteger('23A628553168947D59DCC912042351377AC5FB32', 16)
		);
		$this->setOrder(new BigInteger('0100000000000000000001F4C8F927AED3CA752257', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Prime;
use phpseclib3\Math\BigInteger;

class secp160r2 extends Prime
{
	public function __construct()
	{

		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73', 16));
		$this->setCoefficients(
			new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70', 16),
			new BigInteger('B4E134D3FB59EB8BAB57274904664D5AF50388BA', 16)
		);
		$this->setBasePoint(
			new BigInteger('52DCB034293A117E1F4FF11B30F7199D3144CE6D', 16),
			new BigInteger('FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E', 16)
		);
		$this->setOrder(new BigInteger('0100000000000000000000351EE786A818F3A1A16B', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\KoblitzPrime;
use phpseclib3\Math\BigInteger;

class secp192k1 extends KoblitzPrime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37', 16));
		$this->setCoefficients(
			new BigInteger('000000000000000000000000000000000000000000000000', 16),
			new BigInteger('000000000000000000000000000000000000000000000003', 16)
		);
		$this->setBasePoint(
			new BigInteger('DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D', 16),
			new BigInteger('9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D', 16));

		$this->basis = [];
		$this->basis[] = [
			'a' => new BigInteger('00B3FB3400DEC5C4ADCEB8655C', -16),
			'b' => new BigInteger('8EE96418CCF4CFC7124FDA0F', -16)
		];
		$this->basis[] = [
			'a' => new BigInteger('01D90D03E8F096B9948B20F0A9', -16),
			'b' => new BigInteger('42E49819ABBA9474E1083F6B', -16)
		];
		$this->beta = $this->factory->newInteger(new BigInteger('447A96E6C647963E2F7809FEAAB46947F34B0AA3CA0BBA74', -16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\KoblitzPrime;
use phpseclib3\Math\BigInteger;

class secp224k1 extends KoblitzPrime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D', 16));
		$this->setCoefficients(
			new BigInteger('00000000000000000000000000000000000000000000000000000000', 16),
			new BigInteger('00000000000000000000000000000000000000000000000000000005', 16)
		);
		$this->setBasePoint(
			new BigInteger('A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C', 16),
			new BigInteger('7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5', 16)
		);
		$this->setOrder(new BigInteger('010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7', 16));

		$this->basis = [];
		$this->basis[] = [
			'a' => new BigInteger('00B8ADF1378A6EB73409FA6C9C637D', -16),
			'b' => new BigInteger('94730F82B358A3776A826298FA6F', -16)
		];
		$this->basis[] = [
			'a' => new BigInteger('01DCE8D2EC6184CAF0A972769FCC8B', -16),
			'b' => new BigInteger('4D2100BA3DC75AAB747CCF355DEC', -16)
		];
		$this->beta = $this->factory->newInteger(new BigInteger('01F178FFA4B17C89E6F73AECE2AAD57AF4C0A748B63C830947B27E04', -16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\KoblitzPrime;
use phpseclib3\Math\BigInteger;

class secp256k1 extends KoblitzPrime
{
	public function __construct()
	{
		$this->setModulo(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16));
		$this->setCoefficients(
			new BigInteger('0000000000000000000000000000000000000000000000000000000000000000', 16),
			new BigInteger('0000000000000000000000000000000000000000000000000000000000000007', 16)
		);
		$this->setOrder(new BigInteger('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16));
		$this->setBasePoint(
			new BigInteger('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
			new BigInteger('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16)
		);

		$this->basis = [];
		$this->basis[] = [
			'a' => new BigInteger('3086D221A7D46BCDE86C90E49284EB15', -16),
			'b' => new BigInteger('FF1BBC8129FEF177D790AB8056F5401B3D', -16)
		];
		$this->basis[] = [
			'a' => new BigInteger('114CA50F7A8E2F3F657C1108D9D44CFD8', -16),
			'b' => new BigInteger('3086D221A7D46BCDE86C90E49284EB15', -16)
		];
		$this->beta = $this->factory->newInteger(new BigInteger('7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE', -16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect113r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(113, 9, 0);
		$this->setCoefficients(
			'003088250CA6E7C7FE649CE85820F7',
			'00E8BEE4D3E2260744188BE0E9C723'
		);
		$this->setBasePoint(
			'009D73616F35F4AB1407D73562C10F',
			'00A52830277958EE84D1315ED31886'
		);
		$this->setOrder(new BigInteger('0100000000000000D9CCEC8A39E56F', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect113r2 extends Binary
{
	public function __construct()
	{
		$this->setModulo(113, 9, 0);
		$this->setCoefficients(
			'00689918DBEC7E5A0DD6DFC0AA55C7',
			'0095E9A9EC9B297BD4BF36E059184F'
		);
		$this->setBasePoint(
			'01A57A6A7B26CA5EF52FCDB8164797',
			'00B3ADC94ED1FE674C06E695BABA1D'
		);
		$this->setOrder(new BigInteger('010000000000000108789B2496AF93', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect131r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(131, 8, 3, 2, 0);
		$this->setCoefficients(
			'07A11B09A76B562144418FF3FF8C2570B8',
			'0217C05610884B63B9C6C7291678F9D341'
		);
		$this->setBasePoint(
			'0081BAF91FDF9833C40F9C181343638399',
			'078C6E7EA38C001F73C8134B1B4EF9E150'
		);
		$this->setOrder(new BigInteger('0400000000000000023123953A9464B54D', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect131r2 extends Binary
{
	public function __construct()
	{
		$this->setModulo(131, 8, 3, 2, 0);
		$this->setCoefficients(
			'03E5A88919D7CAFCBF415F07C2176573B2',
			'04B8266A46C55657AC734CE38F018F2192'
		);
		$this->setBasePoint(
			'0356DCD8F2F95031AD652D23951BB366A8',
			'0648F06D867940A5366D9E265DE9EB240F'
		);
		$this->setOrder(new BigInteger('0400000000000000016954A233049BA98F', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect163r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(163, 7, 6, 3, 0);
		$this->setCoefficients(
			'07B6882CAAEFA84F9554FF8428BD88E246D2782AE2',
			'0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9'
		);
		$this->setBasePoint(
			'0369979697AB43897789566789567F787A7876A654',
			'00435EDB42EFAFB2989D51FEFCE3C80988F41FF883'
		);
		$this->setOrder(new BigInteger('03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect163r2 extends Binary
{
	public function __construct()
	{
		$this->setModulo(163, 7, 6, 3, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000001',
			'020A601907B8C953CA1481EB10512F78744A3205FD'
		);
		$this->setBasePoint(
			'03F0EBA16286A2D57EA0991168D4994637E8343E36',
			'00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1'
		);
		$this->setOrder(new BigInteger('040000000000000000000292FE77E70C12A4234C33', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect193r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(193, 15, 0);
		$this->setCoefficients(
			'0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01',
			'00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814'
		);
		$this->setBasePoint(
			'01F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E1',
			'0025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05'
		);
		$this->setOrder(new BigInteger('01000000000000000000000000C7F34A778F443ACC920EBA49', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect193r2 extends Binary
{
	public function __construct()
	{
		$this->setModulo(193, 15, 0);
		$this->setCoefficients(
			'0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B',
			'00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE'
		);
		$this->setBasePoint(
			'00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F',
			'01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C'
		);
		$this->setOrder(new BigInteger('010000000000000000000000015AAB561B005413CCD4EE99D5', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect239k1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(239, 158, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000',
			'000000000000000000000000000000000000000000000000000000000001'
		);
		$this->setBasePoint(
			'29A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC',
			'76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA'
		);
		$this->setOrder(new BigInteger('2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect283r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(283, 12, 7, 5, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000000000000001',
			'027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5'
		);
		$this->setBasePoint(
			'05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053',
			'03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4'
		);
		$this->setOrder(new BigInteger('03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307', 16));
	}
}
}

namespace phpseclib3\Crypt\EC\Curves {

use phpseclib3\Crypt\EC\BaseCurves\Binary;
use phpseclib3\Math\BigInteger;

class sect571r1 extends Binary
{
	public function __construct()
	{
		$this->setModulo(571, 10, 5, 2, 0);
		$this->setCoefficients(
			'000000000000000000000000000000000000000000000000000000000000000000000000' .
			'000000000000000000000000000000000000000000000000000000000000000000000001',
			'02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD' .
			'8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A'
		);
		$this->setBasePoint(
			'0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950' .
			'F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19',
			'037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43' .
			'BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B'
		);
		$this->setOrder(new BigInteger(
			'03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' .
			'E661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47',
			16
		));
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Curves\Ed448;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS1;
use phpseclib3\Crypt\EC\Parameters;
use phpseclib3\Crypt\EC\PrivateKey;
use phpseclib3\Crypt\EC\PublicKey;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Exception\UnsupportedCurveException;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\ECParameters;
use phpseclib3\Math\BigInteger;

abstract class EC extends AsymmetricKey
{

	const ALGORITHM = 'EC';

	protected $QA;

	protected $curve;

	protected $format;

	protected $shortFormat;

	private $curveName;

	protected $q;

	protected $x;

	protected $context;

	protected $sigFormat;

	public static function createKey($curve)
	{
		self::initialize_static_variables();

		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
		}

		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}

		$curve = strtolower($curve);
		if (self::$engines['libsodium'] && $curve == 'ed25519' && function_exists('sodium_crypto_sign_keypair')) {
			$kp = sodium_crypto_sign_keypair();

			$privatekey = EC::loadFormat('libsodium', sodium_crypto_sign_secretkey($kp));

			$privatekey->curveName = 'Ed25519';

			return $privatekey;
		}

		$privatekey = new PrivateKey();

		$curveName = $curve;
		if (preg_match('#(?:^curve|^ed)\d+$#', $curveName)) {
			$curveName = ucfirst($curveName);
		} elseif (substr($curveName, 0, 10) == 'brainpoolp') {
			$curveName = 'brainpoolP' . substr($curveName, 10);
		}
		$curve = '\phpseclib3\Crypt\EC\Curves\\' . $curveName;

		if (!class_exists($curve)) {
			throw new UnsupportedCurveException('Named Curve of ' . $curveName . ' is not supported');
		}

		$reflect = new \ReflectionClass($curve);
		$curveName = $reflect->isFinal() ?
			$reflect->getParentClass()->getShortName() :
			$reflect->getShortName();

		$curve = new $curve();
		if ($curve instanceof TwistedEdwardsCurve) {
			$arr = $curve->extractSecret(Random::string($curve instanceof Ed448 ? 57 : 32));
			$privatekey->dA = $dA = $arr['dA'];
			$privatekey->secret = $arr['secret'];
		} else {
			$privatekey->dA = $dA = $curve->createRandomMultiplier();
		}
		if ($curve instanceof Curve25519 && self::$engines['libsodium']) {

			$QA = sodium_crypto_box_publickey_from_secretkey($dA->toBytes());
			$privatekey->QA = [$curve->convertInteger(new BigInteger(strrev($QA), 256))];
		} else {
			$privatekey->QA = $curve->multiplyPoint($curve->getBasePoint(), $dA);
		}
		$privatekey->curve = $curve;

		$privatekey->curveName = $curveName;

		if ($privatekey->curve instanceof TwistedEdwardsCurve) {
			return $privatekey->withHash($curve::HASH);
		}

		return $privatekey;
	}

	protected static function onLoad(array $components)
	{
		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}

		if (!isset($components['dA']) && !isset($components['QA'])) {
			$new = new Parameters();
			$new->curve = $components['curve'];
			return $new;
		}

		$new = isset($components['dA']) ?
			new PrivateKey() :
			new PublicKey();
		$new->curve = $components['curve'];
		$new->QA = $components['QA'];

		if (isset($components['dA'])) {
			$new->dA = $components['dA'];
			$new->secret = $components['secret'];
		}

		if ($new->curve instanceof TwistedEdwardsCurve) {
			return $new->withHash($components['curve']::HASH);
		}

		return $new;
	}

	protected function __construct()
	{
		$this->sigFormat = self::validatePlugin('Signature', 'ASN1');
		$this->shortFormat = 'ASN1';

		parent::__construct();
	}

	public function getCurve()
	{
		if ($this->curveName) {
			return $this->curveName;
		}

		if ($this->curve instanceof MontgomeryCurve) {
			$this->curveName = $this->curve instanceof Curve25519 ? 'Curve25519' : 'Curve448';
			return $this->curveName;
		}

		if ($this->curve instanceof TwistedEdwardsCurve) {
			$this->curveName = $this->curve instanceof Ed25519 ? 'Ed25519' : 'Ed448';
			return $this->curveName;
		}

		$params = $this->getParameters()->toString('PKCS8', ['namedCurve' => true]);
		$decoded = ASN1::extractBER($params);
		$decoded = ASN1::decodeBER($decoded);
		$decoded = ASN1::asn1map($decoded[0], ECParameters::MAP);
		if (isset($decoded['namedCurve'])) {
			$this->curveName = $decoded['namedCurve'];
			return $decoded['namedCurve'];
		}

		if (!$namedCurves) {
			PKCS1::useSpecifiedCurve();
		}

		return $decoded;
	}

	public function getLength()
	{
		return $this->curve->getLength();
	}

	public function getEngine()
	{
		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}
		if ($this->curve instanceof TwistedEdwardsCurve) {
			return $this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context) ?
				'libsodium' : 'PHP';
		}

		return self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods()) ?
			'OpenSSL' : 'PHP';
	}

	public function getEncodedCoordinates()
	{
		if ($this->curve instanceof MontgomeryCurve) {
			return strrev($this->QA[0]->toBytes(true));
		}
		if ($this->curve instanceof TwistedEdwardsCurve) {
			return $this->curve->encodePoint($this->QA);
		}
		return "\4" . $this->QA[0]->toBytes(true) . $this->QA[1]->toBytes(true);
	}

	public function getParameters($type = 'PKCS1')
	{
		$type = self::validatePlugin('Keys', $type, 'saveParameters');

		$key = $type::saveParameters($this->curve);

		return EC::load($key, 'PKCS1')
			->withHash($this->hash->getHash())
			->withSignatureFormat($this->shortFormat);
	}

	public function withSignatureFormat($format)
	{
		if ($this->curve instanceof MontgomeryCurve) {
			throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
		}

		$new = clone $this;
		$new->shortFormat = $format;
		$new->sigFormat = self::validatePlugin('Signature', $format);
		return $new;
	}

	public function getSignatureFormat()
	{
		return $this->shortFormat;
	}

	public function withContext($context = null)
	{
		if (!$this->curve instanceof TwistedEdwardsCurve) {
			throw new UnsupportedCurveException('Only Ed25519 and Ed448 support contexts');
		}

		$new = clone $this;
		if (!isset($context)) {
			$new->context = null;
			return $new;
		}
		if (!is_string($context)) {
			throw new \InvalidArgumentException('setContext expects a string');
		}
		if (strlen($context) > 255) {
			throw new \LengthException('The context is supposed to be, at most, 255 bytes long');
		}
		$new->context = $context;
		return $new;
	}

	public function getContext()
	{
		return $this->context;
	}

	public function withHash($hash)
	{
		if ($this->curve instanceof MontgomeryCurve) {
			throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
		}
		if ($this->curve instanceof Ed25519 && $hash != 'sha512') {
			throw new UnsupportedAlgorithmException('Ed25519 only supports sha512 as a hash');
		}
		if ($this->curve instanceof Ed448 && $hash != 'shake256-912') {
			throw new UnsupportedAlgorithmException('Ed448 only supports shake256 with a length of 114 bytes');
		}

		return parent::withHash($hash);
	}

	public function __toString()
	{
		if ($this->curve instanceof MontgomeryCurve) {
			return '';
		}

		return parent::__toString();
	}
}
}

namespace phpseclib3\Crypt\EC {

use phpseclib3\Crypt\EC;

final class Parameters extends EC
{

	public function toString($type = 'PKCS1', array $options = [])
	{
		$type = self::validatePlugin('Keys', 'PKCS1', 'saveParameters');

		return $type::saveParameters($this->curve, $options);
	}
}
}

namespace phpseclib3\Crypt\EC {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Curve25519;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS1;
use phpseclib3\Crypt\EC\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib3\Crypt\Hash;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\Math\BigInteger;

final class PrivateKey extends EC implements Common\PrivateKey
{
	use Common\Traits\PasswordProtected;

	protected $dA;

	protected $secret;

	public function multiply($coordinates)
	{
		if ($this->curve instanceof MontgomeryCurve) {
			if ($this->curve instanceof Curve25519 && self::$engines['libsodium']) {
				return sodium_crypto_scalarmult($this->dA->toBytes(), $coordinates);
			}

			$point = [$this->curve->convertInteger(new BigInteger(strrev($coordinates), 256))];
			$point = $this->curve->multiplyPoint($point, $this->dA);
			return strrev($point[0]->toBytes(true));
		}
		if (!$this->curve instanceof TwistedEdwardsCurve) {
			$coordinates = "\0$coordinates";
		}
		$point = PKCS1::extractPoint($coordinates, $this->curve);
		$point = $this->curve->multiplyPoint($point, $this->dA);
		if ($this->curve instanceof TwistedEdwardsCurve) {
			return $this->curve->encodePoint($point);
		}
		if (empty($point)) {
			throw new \RuntimeException('The infinity point is invalid');
		}
		return "\4" . $point[0]->toBytes(true) . $point[1]->toBytes(true);
	}

	public function sign($message)
	{
		if ($this->curve instanceof MontgomeryCurve) {
			throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
		}

		$dA = $this->dA;
		$order = $this->curve->getOrder();

		$shortFormat = $this->shortFormat;
		$format = $this->sigFormat;
		if ($format === false) {
			return false;
		}

		if ($this->curve instanceof TwistedEdwardsCurve) {
			if ($this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context)) {
				$result = sodium_crypto_sign_detached($message, $this->withPassword()->toString('libsodium'));
				return $shortFormat == 'SSH2' ? Strings::packSSH2('ss', 'ssh-' . strtolower($this->getCurve()), $result) : $result;
			}

			$A = $this->curve->encodePoint($this->QA);
			$curve = $this->curve;
			$hash = new Hash($curve::HASH);

			$secret = substr($hash->hash($this->secret), $curve::SIZE);

			if ($curve instanceof Ed25519) {
				$dom = !isset($this->context) ? '' :
					'SigEd25519 no Ed25519 collisions' . "\0" . chr(strlen($this->context)) . $this->context;
			} else {
				$context = isset($this->context) ? $this->context : '';
				$dom = 'SigEd448' . "\0" . chr(strlen($context)) . $context;
			}

			$r = $hash->hash($dom . $secret . $message);
			$r = strrev($r);
			$r = new BigInteger($r, 256);
			list(, $r) = $r->divide($order);
			$R = $curve->multiplyPoint($curve->getBasePoint(), $r);
			$R = $curve->encodePoint($R);
			$k = $hash->hash($dom . $R . $A . $message);
			$k = strrev($k);
			$k = new BigInteger($k, 256);
			list(, $k) = $k->divide($order);
			$S = $k->multiply($dA)->add($r);
			list(, $S) = $S->divide($order);
			$S = str_pad(strrev($S->toBytes()), $curve::SIZE, "\0");
			return $shortFormat == 'SSH2' ? Strings::packSSH2('ss', 'ssh-' . strtolower($this->getCurve()), $R . $S) : $R . $S;
		}

		if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
			$signature = '';

			$result = openssl_sign($message, $signature, $this->withPassword()->toString('PKCS8', ['namedCurve' => false]), $this->hash->getHash());

			if ($result) {
				if ($shortFormat == 'ASN1') {
					return $signature;
				}

				extract(ASN1Signature::load($signature));

				return $this->formatSignature($r, $s);
			}
		}

		$e = $this->hash->hash($message);
		$e = new BigInteger($e, 256);

		$Ln = $this->hash->getLength() - $order->getLength();
		$z = $Ln > 0 ? $e->bitwise_rightShift($Ln) : $e;

		while (true) {
			$k = BigInteger::randomRange(self::$one, $order->subtract(self::$one));
			list($x, $y) = $this->curve->multiplyPoint($this->curve->getBasePoint(), $k);
			$x = $x->toBigInteger();
			list(, $r) = $x->divide($order);
			if ($r->equals(self::$zero)) {
				continue;
			}
			$kinv = $k->modInverse($order);
			$temp = $z->add($dA->multiply($r));
			$temp = $kinv->multiply($temp);
			list(, $s) = $temp->divide($order);
			if (!$s->equals(self::$zero)) {
				break;
			}
		}

		return $this->formatSignature($r, $s);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePrivateKey');

		return $type::savePrivateKey($this->dA, $this->curve, $this->QA, $this->secret, $this->password, $options);
	}

	public function getPublicKey()
	{
		$format = 'PKCS8';
		if ($this->curve instanceof MontgomeryCurve) {
			$format = 'MontgomeryPublic';
		}

		$type = self::validatePlugin('Keys', $format, 'savePublicKey');

		$key = $type::savePublicKey($this->curve, $this->QA);
		$key = EC::loadFormat($format, $key);
		if ($this->curve instanceof MontgomeryCurve) {
			return $key;
		}
		$key = $key
			->withHash($this->hash->getHash())
			->withSignatureFormat($this->shortFormat);
		if ($this->curve instanceof TwistedEdwardsCurve) {
			$key = $key->withContext($this->context);
		}
		return $key;
	}

	private function formatSignature(BigInteger $r, BigInteger $s)
	{
		$format = $this->sigFormat;

		$temp = new \ReflectionMethod($format, 'save');
		$paramCount = $temp->getNumberOfRequiredParameters();

		switch ($paramCount) {
			case 2: return $format::save($r, $s);
			case 3: return $format::save($r, $s, $this->getCurve());
			case 4: return $format::save($r, $s, $this->getCurve(), $this->getLength());
		}

		throw new UnsupportedOperationException("$format::save() has $paramCount parameters - the only valid parameter counts are 2 or 3");
	}
}
}

namespace phpseclib3\Crypt\EC {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\EC\BaseCurves\Montgomery as MontgomeryCurve;
use phpseclib3\Crypt\EC\BaseCurves\TwistedEdwards as TwistedEdwardsCurve;
use phpseclib3\Crypt\EC\Curves\Ed25519;
use phpseclib3\Crypt\EC\Formats\Keys\PKCS1;
use phpseclib3\Crypt\EC\Formats\Signature\ASN1 as ASN1Signature;
use phpseclib3\Crypt\Hash;
use phpseclib3\Exception\UnsupportedOperationException;
use phpseclib3\Math\BigInteger;

final class PublicKey extends EC implements Common\PublicKey
{
	use Common\Traits\Fingerprint;

	public function verify($message, $signature)
	{
		if ($this->curve instanceof MontgomeryCurve) {
			throw new UnsupportedOperationException('Montgomery Curves cannot be used to create signatures');
		}

		$shortFormat = $this->shortFormat;
		$format = $this->sigFormat;
		if ($format === false) {
			return false;
		}

		$order = $this->curve->getOrder();

		if ($this->curve instanceof TwistedEdwardsCurve) {
			if ($shortFormat == 'SSH2') {
				list(, $signature) = Strings::unpackSSH2('ss', $signature);
			}

			if ($this->curve instanceof Ed25519 && self::$engines['libsodium'] && !isset($this->context)) {
				return sodium_crypto_sign_verify_detached($signature, $message, $this->toString('libsodium'));
			}

			$curve = $this->curve;
			if (strlen($signature) != 2 * $curve::SIZE) {
				return false;
			}

			$R = substr($signature, 0, $curve::SIZE);
			$S = substr($signature, $curve::SIZE);

			try {
				$R = PKCS1::extractPoint($R, $curve);
				$R = $this->curve->convertToInternal($R);
			} catch (\Exception $e) {
				return false;
			}

			$S = strrev($S);
			$S = new BigInteger($S, 256);

			if ($S->compare($order) >= 0) {
				return false;
			}

			$A = $curve->encodePoint($this->QA);

			if ($curve instanceof Ed25519) {
				$dom2 = !isset($this->context) ? '' :
					'SigEd25519 no Ed25519 collisions' . "\0" . chr(strlen($this->context)) . $this->context;
			} else {
				$context = isset($this->context) ? $this->context : '';
				$dom2 = 'SigEd448' . "\0" . chr(strlen($context)) . $context;
			}

			$hash = new Hash($curve::HASH);
			$k = $hash->hash($dom2 . substr($signature, 0, $curve::SIZE) . $A . $message);
			$k = strrev($k);
			$k = new BigInteger($k, 256);
			list(, $k) = $k->divide($order);

			$qa = $curve->convertToInternal($this->QA);

			$lhs = $curve->multiplyPoint($curve->getBasePoint(), $S);
			$rhs = $curve->multiplyPoint($qa, $k);
			$rhs = $curve->addPoint($rhs, $R);
			$rhs = $curve->convertToAffine($rhs);

			return $lhs[0]->equals($rhs[0]) && $lhs[1]->equals($rhs[1]);
		}

		$params = $format::load($signature);
		if ($params === false || count($params) != 2) {
			return false;
		}
		extract($params);

		if (self::$engines['OpenSSL'] && in_array($this->hash->getHash(), openssl_get_md_methods())) {
			$sig = $format != 'ASN1' ? ASN1Signature::save($r, $s) : $signature;

			$result = openssl_verify($message, $sig, $this->toString('PKCS8', ['namedCurve' => false]), $this->hash->getHash());

			if ($result != -1) {
				return (bool) $result;
			}
		}

		$n_1 = $order->subtract(self::$one);
		if (!$r->between(self::$one, $n_1) || !$s->between(self::$one, $n_1)) {
			return false;
		}

		$e = $this->hash->hash($message);
		$e = new BigInteger($e, 256);

		$Ln = $this->hash->getLength() - $order->getLength();
		$z = $Ln > 0 ? $e->bitwise_rightShift($Ln) : $e;

		$w = $s->modInverse($order);
		list(, $u1) = $z->multiply($w)->divide($order);
		list(, $u2) = $r->multiply($w)->divide($order);

		$u1 = $this->curve->convertInteger($u1);
		$u2 = $this->curve->convertInteger($u2);

		list($x1, $y1) = $this->curve->multiplyAddPoints(
			[$this->curve->getBasePoint(), $this->QA],
			[$u1, $u2]
		);

		$x1 = $x1->toBigInteger();
		list(, $x1) = $x1->divide($order);

		return $x1->equals($r);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePublicKey');

		return $type::savePublicKey($this->curve, $this->QA, $options);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\InsufficientSetupException;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\PrimeField;

class Hash
{

	const PADDING_KECCAK = 1;

	const PADDING_SHA3 = 2;

	const PADDING_SHAKE = 3;

	private $paddingType = 0;

	private $hashParam;

	private $length;

	private $algo;

	private $key = false;

	private $nonce = false;

	private $parameters = [];

	private $computedKey = false;

	private $opad;

	private $ipad;

	private $recomputeAESKey;

	private $c;

	private $pad;

	private $blockSize;

	private static $factory36;
	private static $factory64;
	private static $factory128;
	private static $offset64;
	private static $offset128;
	private static $marker64;
	private static $marker128;
	private static $maxwordrange64;
	private static $maxwordrange128;

	public function __construct($hash = 'sha256')
	{
		$this->setHash($hash);
	}

	public function setKey($key = false)
	{
		$this->key = $key;
		$this->computeKey();
		$this->recomputeAESKey = true;
	}

	public function setNonce($nonce = false)
	{
		switch (true) {
			case !is_string($nonce):
			case strlen($nonce) > 0 && strlen($nonce) <= 16:
				$this->recomputeAESKey = true;
				$this->nonce = $nonce;
				return;
		}

		throw new \LengthException('The nonce length must be between 1 and 16 bytes, inclusive');
	}

	private function computeKey()
	{
		if ($this->key === false) {
			$this->computedKey = false;
			return;
		}

		if (strlen($this->key) <= $this->getBlockLengthInBytes()) {
			$this->computedKey = $this->key;
			return;
		}

		$this->computedKey = is_array($this->algo) ?
			call_user_func($this->algo, $this->key) :
			hash($this->algo, $this->key, true);
	}

	public function getHash()
	{
		return $this->hashParam;
	}

	public function setHash($hash)
	{
		$oldHash = $this->hashParam;
		$this->hashParam = $hash = strtolower($hash);
		switch ($hash) {
			case 'umac-32':
			case 'umac-64':
			case 'umac-96':
			case 'umac-128':
				if ($oldHash != $this->hashParam) {
					$this->recomputeAESKey = true;
				}
				$this->blockSize = 128;
				$this->length = abs(substr($hash, -3)) >> 3;
				$this->algo = 'umac';
				return;
			case 'md2-96':
			case 'md5-96':
			case 'sha1-96':
			case 'sha224-96':
			case 'sha256-96':
			case 'sha384-96':
			case 'sha512-96':
			case 'sha512/224-96':
			case 'sha512/256-96':
				$hash = substr($hash, 0, -3);
				$this->length = 12;
				break;
			case 'md2':
			case 'md5':
				$this->length = 16;
				break;
			case 'sha1':
				$this->length = 20;
				break;
			case 'sha224':
			case 'sha512/224':
			case 'sha3-224':
				$this->length = 28;
				break;
			case 'keccak256':
				$this->paddingType = self::PADDING_KECCAK;

			case 'sha256':
			case 'sha512/256':
			case 'sha3-256':
				$this->length = 32;
				break;
			case 'sha384':
			case 'sha3-384':
				$this->length = 48;
				break;
			case 'sha512':
			case 'sha3-512':
				$this->length = 64;
				break;
			default:
				if (preg_match('#^(shake(?:128|256))-(\d+)$#', $hash, $matches)) {
					$this->paddingType = self::PADDING_SHAKE;
					$hash = $matches[1];
					$this->length = $matches[2] >> 3;
				} else {
					throw new UnsupportedAlgorithmException(
						"$hash is not a supported algorithm"
					);
				}
		}

		switch ($hash) {
			case 'md2':
			case 'md2-96':
				$this->blockSize = 128;
				break;
			case 'md5-96':
			case 'sha1-96':
			case 'sha224-96':
			case 'sha256-96':
			case 'md5':
			case 'sha1':
			case 'sha224':
			case 'sha256':
				$this->blockSize = 512;
				break;
			case 'sha3-224':
				$this->blockSize = 1152;
				break;
			case 'sha3-256':
			case 'shake256':
			case 'keccak256':
				$this->blockSize = 1088;
				break;
			case 'sha3-384':
				$this->blockSize = 832;
				break;
			case 'sha3-512':
				$this->blockSize = 576;
				break;
			case 'shake128':
				$this->blockSize = 1344;
				break;
			default:
				$this->blockSize = 1024;
		}

		if (in_array(substr($hash, 0, 5), ['sha3-', 'shake', 'kecca'])) {

			if (version_compare(PHP_VERSION, '7.1.0') < 0 || substr($hash, 0, 5) != 'sha3-') {

				if (!$this->paddingType) {
					$this->paddingType = self::PADDING_SHA3;
				}
				$this->parameters = [
					'capacity' => 1600 - $this->blockSize,
					'rate' => $this->blockSize,
					'length' => $this->length,
					'padding' => $this->paddingType
				];
				$hash = ['phpseclib3\Crypt\Hash', PHP_INT_SIZE == 8 ? 'sha3_64' : 'sha3_32'];
			}
		}

		if ($hash == 'sha512/224' || $hash == 'sha512/256') {

			if (version_compare(PHP_VERSION, '7.1.0') < 0) {

				$initial = $hash == 'sha512/256' ?
					[
						'22312194FC2BF72C', '9F555FA3C84C64C2', '2393B86B6F53B151', '963877195940EABD',
						'96283EE2A88EFFE3', 'BE5E1E2553863992', '2B0199FC2C85B8AA', '0EB72DDC81C52CA2'
					] :
					[
						'8C3D37C819544DA2', '73E1996689DCD4D6', '1DFAB7AE32FF9C82', '679DD514582F9FCF',
						'0F6D2B697BD44DA8', '77E36F7304C48942', '3F9D85A86A1D36C8', '1112E6AD91D692A1'
					];
				for ($i = 0; $i < 8; $i++) {
					if (PHP_INT_SIZE == 8) {
						list(, $initial[$i]) = unpack('J', pack('H*', $initial[$i]));
					} else {
						$initial[$i] = new BigInteger($initial[$i], 16);
						$initial[$i]->setPrecision(64);
					}
				}

				$this->parameters = compact('initial');

				$hash = ['phpseclib3\Crypt\Hash', PHP_INT_SIZE == 8 ? 'sha512_64' : 'sha512'];
			}
		}

		if (is_array($hash)) {
			$b = $this->blockSize >> 3;
			$this->ipad = str_repeat(chr(0x36), $b);
			$this->opad = str_repeat(chr(0x5C), $b);
		}

		$this->algo = $hash;

		$this->computeKey();
	}

	private function kdf($index, $numbytes)
	{
		$this->c->setIV(pack('N4', 0, $index, 0, 1));

		return $this->c->encrypt(str_repeat("\0", $numbytes));
	}

	private function pdf()
	{
		$k = $this->key;
		$nonce = $this->nonce;
		$taglen = $this->length;

		if ($taglen <= 8) {
			$last = strlen($nonce) - 1;
			$mask = $taglen == 4 ? "\3" : "\1";
			$index = $nonce[$last] & $mask;
			$nonce[$last] = $nonce[$last] ^ $index;
		}

		$nonce = str_pad($nonce, 16, "\0");

		$kp = $this->kdf(0, 16);
		$c = new AES('ctr');
		$c->disablePadding();
		$c->setKey($kp);
		$c->setIV($nonce);
		$t = $c->encrypt("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

		return $taglen <= 8 ?
			substr($t, unpack('C', $index)[1] * $taglen, $taglen) :
			substr($t, 0, $taglen);
	}

	private function uhash($m, $taglen)
	{

		$iters = $taglen >> 2;

		$L1Key	= $this->kdf(1, (1024 + ($iters - 1)) * 16);
		$L2Key	= $this->kdf(2, $iters * 24);
		$L3Key1 = $this->kdf(3, $iters * 64);
		$L3Key2 = $this->kdf(4, $iters * 4);

		$y = '';
		for ($i = 0; $i < $iters; $i++) {
			$L1Key_i	= substr($L1Key, $i * 16, 1024);
			$L2Key_i	= substr($L2Key, $i * 24, 24);
			$L3Key1_i = substr($L3Key1, $i * 64, 64);
			$L3Key2_i = substr($L3Key2, $i * 4, 4);

			$a = self::L1Hash($L1Key_i, $m);
			$b = strlen($m) <= 1024 ? "\0\0\0\0\0\0\0\0$a" : self::L2Hash($L2Key_i, $a);
			$c = self::L3Hash($L3Key1_i, $L3Key2_i, $b);
			$y .= $c;
		}

		return $y;
	}

	private static function L1Hash($k, $m)
	{

		$m = str_split($m, 1024);

		$length = 1024 * 8;
		$y = '';

		for ($i = 0; $i < count($m) - 1; $i++) {
			$m[$i] = pack('N*', ...unpack('V*', $m[$i]));
			$y .= PHP_INT_SIZE == 8 ?
				static::nh64($k, $m[$i], $length) :
				static::nh32($k, $m[$i], $length);
		}

		$length = count($m) ? strlen($m[$i]) : 0;
		$pad = 32 - ($length % 32);
		$pad = max(32, $length + $pad % 32);
		$m[$i] = str_pad(isset($m[$i]) ? $m[$i] : '', $pad, "\0");
		$m[$i] = pack('N*', ...unpack('V*', $m[$i]));

		$y .= PHP_INT_SIZE == 8 ?
			static::nh64($k, $m[$i], $length * 8) :
			static::nh32($k, $m[$i], $length * 8);

		return $y;
	}

	private static function mul32_64($x, $y)
	{

		$x1 = ($x >> 16) & 0xFFFF;
		$x0 = $x & 0xFFFF;

		$y1 = ($y >> 16) & 0xFFFF;
		$y0 = $y & 0xFFFF;

		$z2 = $x1 * $y1;
		$z0 = $x0 * $y0;
		$z1 = $x1 * $y0 + $x0 * $y1;

		$a = intval(fmod($z0, 65536));
		$b = intval($z0 / 65536) + intval(fmod($z1, 65536));
		$c = intval($z1 / 65536) + intval(fmod($z2, 65536)) + intval($b / 65536);
		$b = intval(fmod($b, 65536));
		$d = intval($z2 / 65536) + intval($c / 65536);
		$c = intval(fmod($c, 65536));
		$d = intval(fmod($d, 65536));

		return pack('n4', $d, $c, $b, $a);
	}

	private static function add32_64($x, $y)
	{
		list(, $x1, $x2, $x3, $x4) = unpack('n4', $x);
		list(, $y1, $y2, $y3, $y4) = unpack('n4', $y);
		$a = $x4 + $y4;
		$b = $x3 + $y3 + ($a >> 16);
		$c = $x2 + $y2 + ($b >> 16);
		$d = $x1 + $y1 + ($c >> 16);
		return pack('n4', $d, $c, $b, $a);
	}

	private static function add32($x, $y)
	{

		$x1 = $x & 0xFFFF;
		$x2 = ($x >> 16) & 0xFFFF;
		$y1 = $y & 0xFFFF;
		$y2 = ($y >> 16) & 0xFFFF;

		$a = $x1 + $y1;
		$b = ($x2 + $y2 + ($a >> 16)) << 16;
		$a &= 0xFFFF;

		return $a | $b;
	}

	private static function nh32($k, $m, $length)
	{

		$k = unpack('N*', $k);
		$m = unpack('N*', $m);
		$t = count($m);

		$i = 1;
		$y = "\0\0\0\0\0\0\0\0";
		while ($i <= $t) {
			$temp	= self::add32($m[$i], $k[$i]);
			$temp2 = self::add32($m[$i + 4], $k[$i + 4]);
			$y = self::add32_64($y, self::mul32_64($temp, $temp2));

			$temp	= self::add32($m[$i + 1], $k[$i + 1]);
			$temp2 = self::add32($m[$i + 5], $k[$i + 5]);
			$y = self::add32_64($y, self::mul32_64($temp, $temp2));

			$temp	= self::add32($m[$i + 2], $k[$i + 2]);
			$temp2 = self::add32($m[$i + 6], $k[$i + 6]);
			$y = self::add32_64($y, self::mul32_64($temp, $temp2));

			$temp	= self::add32($m[$i + 3], $k[$i + 3]);
			$temp2 = self::add32($m[$i + 7], $k[$i + 7]);
			$y = self::add32_64($y, self::mul32_64($temp, $temp2));

			$i += 8;
		}

		return self::add32_64($y, pack('N2', 0, $length));
	}

	private static function mul64($x, $y)
	{

		$x1 = $x >> 16;
		$x0 = $x & 0xFFFF;

		$y1 = $y >> 16;
		$y0 = $y & 0xFFFF;

		$z2 = $x1 * $y1;
		$z0 = $x0 * $y0;
		$z1 = $x1 * $y0 + $x0 * $y1;

		$a = $z0 & 0xFFFF;
		$b = ($z0 >> 16) + ($z1 & 0xFFFF);
		$c = ($z1 >> 16) + ($z2 & 0xFFFF) + ($b >> 16);
		$b = ($b & 0xFFFF) << 16;
		$d = ($z2 >> 16) + ($c >> 16);
		$c = ($c & 0xFFFF) << 32;
		$d = ($d & 0xFFFF) << 48;

		return $a | $b | $c | $d;
	}

	private static function add64($x, $y)
	{

		$x1 = $x & 0xFFFFFFFF;
		$x2 = ($x >> 32) & 0xFFFFFFFF;
		$y1 = $y & 0xFFFFFFFF;
		$y2 = ($y >> 32) & 0xFFFFFFFF;

		$a = $x1 + $y1;
		$b = ($x2 + $y2 + ($a >> 32)) << 32;
		$a &= 0xFFFFFFFF;

		return $a | $b;
	}

	private static function nh64($k, $m, $length)
	{

		$k = unpack('N*', $k);
		$m = unpack('N*', $m);
		$t = count($m);

		$i = 1;
		$y = 0;
		while ($i <= $t) {
			$temp	= ($m[$i] + $k[$i]) & 0xFFFFFFFF;
			$temp2 = ($m[$i + 4] + $k[$i + 4]) & 0xFFFFFFFF;
			$y = self::add64($y, self::mul64($temp, $temp2));

			$temp	= ($m[$i + 1] + $k[$i + 1]) & 0xFFFFFFFF;
			$temp2 = ($m[$i + 5] + $k[$i + 5]) & 0xFFFFFFFF;
			$y = self::add64($y, self::mul64($temp, $temp2));

			$temp	= ($m[$i + 2] + $k[$i + 2]) & 0xFFFFFFFF;
			$temp2 = ($m[$i + 6] + $k[$i + 6]) & 0xFFFFFFFF;
			$y = self::add64($y, self::mul64($temp, $temp2));

			$temp	= ($m[$i + 3] + $k[$i + 3]) & 0xFFFFFFFF;
			$temp2 = ($m[$i + 7] + $k[$i + 7]) & 0xFFFFFFFF;
			$y = self::add64($y, self::mul64($temp, $temp2));

			$i += 8;
		}

		return pack('J', self::add64($y, $length));
	}

	private static function L2Hash($k, $m)
	{

		$k64 = $k & "\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF";
		$k64 = new BigInteger($k64, 256);
		$k128 = substr($k, 8) & "\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF";
		$k128 = new BigInteger($k128, 256);

		if (strlen($m) <= 0x20000) {
			$y = self::poly(64, self::$maxwordrange64, $k64, $m);
		} else {
			$m_1 = substr($m, 0, 0x20000);
			$m_2 = substr($m, 0x20000) . "\x80";
			$length = strlen($m_2);
			$pad = 16 - ($length % 16);
			$pad %= 16;
			$m_2 = str_pad($m_2, $length + $pad, "\0");
			$y = self::poly(64, self::$maxwordrange64, $k64, $m_1);
			$y = str_pad($y, 16, "\0", STR_PAD_LEFT);
			$y = self::poly(128, self::$maxwordrange128, $k128, $y . $m_2);
		}

		return str_pad($y, 16, "\0", STR_PAD_LEFT);
	}

	private static function poly($wordbits, $maxwordrange, $k, $m)
	{

		$wordbytes = $wordbits >> 3;
		if ($wordbits == 128) {
			$factory = self::$factory128;
			$offset = self::$offset128;
			$marker = self::$marker128;
		} else {
			$factory = self::$factory64;
			$offset = self::$offset64;
			$marker = self::$marker64;
		}

		$k = $factory->newInteger($k);

		$m_i = str_split($m, $wordbytes);

		$y = $factory->newInteger(new BigInteger(1));
		foreach ($m_i as $m) {
			$m = $factory->newInteger(new BigInteger($m, 256));
			if ($m->compare($maxwordrange) >= 0) {
				$y = $k->multiply($y)->add($marker);
				$y = $k->multiply($y)->add($m->subtract($offset));
			} else {
				$y = $k->multiply($y)->add($m);
			}
		}

		return $y->toBytes();
	}

	private static function L3Hash($k1, $k2, $m)
	{
		$factory = self::$factory36;

		$y = $factory->newInteger(new BigInteger());
		for ($i = 0; $i < 8; $i++) {
			$m_i = $factory->newInteger(new BigInteger(substr($m, 2 * $i, 2), 256));
			$k_i = $factory->newInteger(new BigInteger(substr($k1, 8 * $i, 8), 256));
			$y = $y->add($m_i->multiply($k_i));
		}
		$y = str_pad(substr($y->toBytes(), -4), 4, "\0", STR_PAD_LEFT);
		$y = $y ^ $k2;

		return $y;
	}

	public function hash($text)
	{
		$algo = $this->algo;
		if ($algo == 'umac') {
			if ($this->recomputeAESKey) {
				if (!is_string($this->nonce)) {
					throw new InsufficientSetupException('No nonce has been set');
				}
				if (!is_string($this->key)) {
					throw new InsufficientSetupException('No key has been set');
				}
				if (strlen($this->key) != 16) {
					throw new \LengthException('Key must be 16 bytes long');
				}

				if (!isset(self::$maxwordrange64)) {
					$one = new BigInteger(1);

					$prime36 = new BigInteger("\x00\x00\x00\x0F\xFF\xFF\xFF\xFB", 256);
					self::$factory36 = new PrimeField($prime36);

					$prime64 = new BigInteger("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC5", 256);
					self::$factory64 = new PrimeField($prime64);

					$prime128 = new BigInteger("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x61", 256);
					self::$factory128 = new PrimeField($prime128);

					self::$offset64 = new BigInteger("\1\0\0\0\0\0\0\0\0", 256);
					self::$offset64 = self::$factory64->newInteger(self::$offset64->subtract($prime64));
					self::$offset128 = new BigInteger("\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 256);
					self::$offset128 = self::$factory128->newInteger(self::$offset128->subtract($prime128));

					self::$marker64 = self::$factory64->newInteger($prime64->subtract($one));
					self::$marker128 = self::$factory128->newInteger($prime128->subtract($one));

					$maxwordrange64 = $one->bitwise_leftShift(64)->subtract($one->bitwise_leftShift(32));
					self::$maxwordrange64 = self::$factory64->newInteger($maxwordrange64);

					$maxwordrange128 = $one->bitwise_leftShift(128)->subtract($one->bitwise_leftShift(96));
					self::$maxwordrange128 = self::$factory128->newInteger($maxwordrange128);
				}

				$this->c = new AES('ctr');
				$this->c->disablePadding();
				$this->c->setKey($this->key);

				$this->pad = $this->pdf();

				$this->recomputeAESKey = false;
			}

			$hashedmessage = $this->uhash($text, $this->length);
			return $hashedmessage ^ $this->pad;
		}

		if (is_array($algo)) {
			if (empty($this->key) || !is_string($this->key)) {
				return substr($algo($text, ...array_values($this->parameters)), 0, $this->length);
			}

			$key	= str_pad($this->computedKey, $b, chr(0));
			$temp	= $this->ipad ^ $key;
			$temp	.= $text;
			$temp	= substr($algo($temp, ...array_values($this->parameters)), 0, $this->length);
			$output = $this->opad ^ $key;
			$output .= $temp;
			$output = $algo($output, ...array_values($this->parameters));

			return substr($output, 0, $this->length);
		}

		$output = !empty($this->key) || is_string($this->key) ?
			hash_hmac($algo, $text, $this->computedKey, true) :
			hash($algo, $text, true);

		return strlen($output) > $this->length
			? substr($output, 0, $this->length)
			: $output;
	}

	public function getLength()
	{
		return $this->length << 3;
	}

	public function getLengthInBytes()
	{
		return $this->length;
	}

	public function getBlockLength()
	{
		return $this->blockSize;
	}

	public function getBlockLengthInBytes()
	{
		return $this->blockSize >> 3;
	}

	private static function sha3_pad($padLength, $padType)
	{
		switch ($padType) {
			case self::PADDING_KECCAK:
				$temp = chr(0x01) . str_repeat("\0", $padLength - 1);
				$temp[$padLength - 1] = $temp[$padLength - 1] | chr(0x80);
				return $temp;
			case self::PADDING_SHAKE:
				$temp = chr(0x1F) . str_repeat("\0", $padLength - 1);
				$temp[$padLength - 1] = $temp[$padLength - 1] | chr(0x80);
				return $temp;

			default:

				return $padLength == 1 ? chr(0x86) : chr(0x06) . str_repeat("\0", $padLength - 2) . chr(0x80);
		}
	}

	private static function sha3_32($p, $c, $r, $d, $padType)
	{
		$block_size = $r >> 3;
		$padLength = $block_size - (strlen($p) % $block_size);
		$num_ints = $block_size >> 2;

		$p .= static::sha3_pad($padLength, $padType);

		$n = strlen($p) / $r;

		$s = [
			[[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
			[[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
			[[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
			[[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
			[[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]
		];

		$p = str_split($p, $block_size);

		foreach ($p as $pi) {
			$pi = unpack('V*', $pi);
			$x = $y = 0;
			for ($i = 1; $i <= $num_ints; $i += 2) {
				$s[$x][$y][0] ^= $pi[$i + 1];
				$s[$x][$y][1] ^= $pi[$i];
				if (++$y == 5) {
					$y = 0;
					$x++;
				}
			}
			static::processSHA3Block32($s);
		}

		$z = '';
		$i = $j = 0;
		while (strlen($z) < $d) {
			$z .= pack('V2', $s[$i][$j][1], $s[$i][$j++][0]);
			if ($j == 5) {
				$j = 0;
				$i++;
				if ($i == 5) {
					$i = 0;
					static::processSHA3Block32($s);
				}
			}
		}

		return $z;
	}

	private static function processSHA3Block32(&$s)
	{
		static $rotationOffsets = [
			[ 0,	1, 62, 28, 27],
			[36, 44,	6, 55, 20],
			[ 3, 10, 43, 25, 39],
			[41, 45, 15, 21,	8],
			[18,	2, 61, 56, 14]
		];

		static $roundConstants = [
			[0, 1],
			[0, 32898],
			[-2147483648, 32906],
			[-2147483648, -2147450880],
			[0, 32907],
			[0, -2147483647],
			[-2147483648, -2147450751],
			[-2147483648, 32777],
			[0, 138],
			[0, 136],
			[0, -2147450871],
			[0, -2147483638],
			[0, -2147450741],
			[-2147483648, 139],
			[-2147483648, 32905],
			[-2147483648, 32771],
			[-2147483648, 32770],
			[-2147483648, 128],
			[0, 32778],
			[-2147483648, -2147483638],
			[-2147483648, -2147450751],
			[-2147483648, 32896],
			[0, -2147483647],
			[-2147483648, -2147450872]
		];

		for ($round = 0; $round < 24; $round++) {

			$parity = $rotated = [];
			for ($i = 0; $i < 5; $i++) {
				$parity[] = [
					$s[0][$i][0] ^ $s[1][$i][0] ^ $s[2][$i][0] ^ $s[3][$i][0] ^ $s[4][$i][0],
					$s[0][$i][1] ^ $s[1][$i][1] ^ $s[2][$i][1] ^ $s[3][$i][1] ^ $s[4][$i][1]
				];
				$rotated[] = static::rotateLeft32($parity[$i], 1);
			}

			$temp = [
				[$parity[4][0] ^ $rotated[1][0], $parity[4][1] ^ $rotated[1][1]],
				[$parity[0][0] ^ $rotated[2][0], $parity[0][1] ^ $rotated[2][1]],
				[$parity[1][0] ^ $rotated[3][0], $parity[1][1] ^ $rotated[3][1]],
				[$parity[2][0] ^ $rotated[4][0], $parity[2][1] ^ $rotated[4][1]],
				[$parity[3][0] ^ $rotated[0][0], $parity[3][1] ^ $rotated[0][1]]
			];
			for ($i = 0; $i < 5; $i++) {
				for ($j = 0; $j < 5; $j++) {
					$s[$i][$j][0] ^= $temp[$j][0];
					$s[$i][$j][1] ^= $temp[$j][1];
				}
			}

			$st = $s;

			for ($i = 0; $i < 5; $i++) {
				for ($j = 0; $j < 5; $j++) {
					$st[(2 * $i + 3 * $j) % 5][$j] = static::rotateLeft32($s[$j][$i], $rotationOffsets[$j][$i]);
				}
			}

			for ($i = 0; $i < 5; $i++) {
				$s[$i][0] = [
					$st[$i][0][0] ^ (~$st[$i][1][0] & $st[$i][2][0]),
					$st[$i][0][1] ^ (~$st[$i][1][1] & $st[$i][2][1])
				];
				$s[$i][1] = [
					$st[$i][1][0] ^ (~$st[$i][2][0] & $st[$i][3][0]),
					$st[$i][1][1] ^ (~$st[$i][2][1] & $st[$i][3][1])
				];
				$s[$i][2] = [
					$st[$i][2][0] ^ (~$st[$i][3][0] & $st[$i][4][0]),
					$st[$i][2][1] ^ (~$st[$i][3][1] & $st[$i][4][1])
				];
				$s[$i][3] = [
					$st[$i][3][0] ^ (~$st[$i][4][0] & $st[$i][0][0]),
					$st[$i][3][1] ^ (~$st[$i][4][1] & $st[$i][0][1])
				];
				$s[$i][4] = [
					$st[$i][4][0] ^ (~$st[$i][0][0] & $st[$i][1][0]),
					$st[$i][4][1] ^ (~$st[$i][0][1] & $st[$i][1][1])
				];
			}

			$s[0][0][0] ^= $roundConstants[$round][0];
			$s[0][0][1] ^= $roundConstants[$round][1];
		}
	}

	private static function rotateLeft32($x, $shift)
	{
		if ($shift < 32) {
			list($hi, $lo) = $x;
		} else {
			$shift -= 32;
			list($lo, $hi) = $x;
		}

		$mask = -1 ^ (-1 << $shift);
		return [
			($hi << $shift) | (($lo >> (32 - $shift)) & $mask),
			($lo << $shift) | (($hi >> (32 - $shift)) & $mask)
		];
	}

	private static function sha3_64($p, $c, $r, $d, $padType)
	{
		$block_size = $r >> 3;
		$padLength = $block_size - (strlen($p) % $block_size);
		$num_ints = $block_size >> 2;

		$p .= static::sha3_pad($padLength, $padType);

		$n = strlen($p) / $r;

		$s = [
			[0, 0, 0, 0, 0],
			[0, 0, 0, 0, 0],
			[0, 0, 0, 0, 0],
			[0, 0, 0, 0, 0],
			[0, 0, 0, 0, 0]
		];

		$p = str_split($p, $block_size);

		foreach ($p as $pi) {
			$pi = unpack('P*', $pi);
			$x = $y = 0;
			foreach ($pi as $subpi) {
				$s[$x][$y++] ^= $subpi;
				if ($y == 5) {
					$y = 0;
					$x++;
				}
			}
			static::processSHA3Block64($s);
		}

		$z = '';
		$i = $j = 0;
		while (strlen($z) < $d) {
			$z .= pack('P', $s[$i][$j++]);
			if ($j == 5) {
				$j = 0;
				$i++;
				if ($i == 5) {
					$i = 0;
					static::processSHA3Block64($s);
				}
			}
		}

		return $z;
	}

	private static function processSHA3Block64(&$s)
	{
		static $rotationOffsets = [
			[ 0,	1, 62, 28, 27],
			[36, 44,	6, 55, 20],
			[ 3, 10, 43, 25, 39],
			[41, 45, 15, 21,	8],
			[18,	2, 61, 56, 14]
		];

		static $roundConstants = [
			1,
			32898,
			-9223372036854742902,
			-9223372034707259392,
			32907,
			2147483649,
			-9223372034707259263,
			-9223372036854743031,
			138,
			136,
			2147516425,
			2147483658,
			2147516555,
			-9223372036854775669,
			-9223372036854742903,
			-9223372036854743037,
			-9223372036854743038,
			-9223372036854775680,
			32778,
			-9223372034707292150,
			-9223372034707259263,
			-9223372036854742912,
			2147483649,
			-9223372034707259384
		];

		for ($round = 0; $round < 24; $round++) {

			$parity = [];
			for ($i = 0; $i < 5; $i++) {
				$parity[] = $s[0][$i] ^ $s[1][$i] ^ $s[2][$i] ^ $s[3][$i] ^ $s[4][$i];
			}
			$temp = [
				$parity[4] ^ static::rotateLeft64($parity[1], 1),
				$parity[0] ^ static::rotateLeft64($parity[2], 1),
				$parity[1] ^ static::rotateLeft64($parity[3], 1),
				$parity[2] ^ static::rotateLeft64($parity[4], 1),
				$parity[3] ^ static::rotateLeft64($parity[0], 1)
			];
			for ($i = 0; $i < 5; $i++) {
				for ($j = 0; $j < 5; $j++) {
					$s[$i][$j] ^= $temp[$j];
				}
			}

			$st = $s;

			for ($i = 0; $i < 5; $i++) {
				for ($j = 0; $j < 5; $j++) {
					$st[(2 * $i + 3 * $j) % 5][$j] = static::rotateLeft64($s[$j][$i], $rotationOffsets[$j][$i]);
				}
			}

			for ($i = 0; $i < 5; $i++) {
				$s[$i] = [
					$st[$i][0] ^ (~$st[$i][1] & $st[$i][2]),
					$st[$i][1] ^ (~$st[$i][2] & $st[$i][3]),
					$st[$i][2] ^ (~$st[$i][3] & $st[$i][4]),
					$st[$i][3] ^ (~$st[$i][4] & $st[$i][0]),
					$st[$i][4] ^ (~$st[$i][0] & $st[$i][1])
				];
			}

			$s[0][0] ^= $roundConstants[$round];
		}
	}

	private static function rotateLeft64($x, $shift)
	{
		$mask = -1 ^ (-1 << $shift);
		return ($x << $shift) | (($x >> (64 - $shift)) & $mask);
	}

	private static function rotateRight64($x, $shift)
	{
		$mask = -1 ^ (-1 << (64 - $shift));
		return (($x >> $shift) & $mask) | ($x << (64 - $shift));
	}

	private static function sha512($m, $hash)
	{
		static $k;

		if (!isset($k)) {

			$k = [
				'428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
				'3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
				'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
				'72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
				'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
				'2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
				'983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
				'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
				'27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
				'650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
				'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
				'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
				'19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
				'391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
				'748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
				'90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
				'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
				'06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
				'28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
				'4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
			];

			for ($i = 0; $i < 80; $i++) {
				$k[$i] = new BigInteger($k[$i], 16);
			}
		}

		$length = strlen($m);

		$m .= str_repeat(chr(0), 128 - (($length + 16) & 0x7F));
		$m[$length] = chr(0x80);

		$m .= pack('N4', 0, 0, 0, $length << 3);

		$chunks = str_split($m, 128);
		foreach ($chunks as $chunk) {
			$w = [];
			for ($i = 0; $i < 16; $i++) {
				$temp = new BigInteger(Strings::shift($chunk, 8), 256);
				$temp->setPrecision(64);
				$w[] = $temp;
			}

			for ($i = 16; $i < 80; $i++) {
				$temp = [
							$w[$i - 15]->bitwise_rightRotate(1),
							$w[$i - 15]->bitwise_rightRotate(8),
							$w[$i - 15]->bitwise_rightShift(7)
				];
				$s0 = $temp[0]->bitwise_xor($temp[1]);
				$s0 = $s0->bitwise_xor($temp[2]);
				$temp = [
							$w[$i - 2]->bitwise_rightRotate(19),
							$w[$i - 2]->bitwise_rightRotate(61),
							$w[$i - 2]->bitwise_rightShift(6)
				];
				$s1 = $temp[0]->bitwise_xor($temp[1]);
				$s1 = $s1->bitwise_xor($temp[2]);
				$w[$i] = clone $w[$i - 16];
				$w[$i] = $w[$i]->add($s0);
				$w[$i] = $w[$i]->add($w[$i - 7]);
				$w[$i] = $w[$i]->add($s1);
			}

			$a = clone $hash[0];
			$b = clone $hash[1];
			$c = clone $hash[2];
			$d = clone $hash[3];
			$e = clone $hash[4];
			$f = clone $hash[5];
			$g = clone $hash[6];
			$h = clone $hash[7];

			for ($i = 0; $i < 80; $i++) {
				$temp = [
					$a->bitwise_rightRotate(28),
					$a->bitwise_rightRotate(34),
					$a->bitwise_rightRotate(39)
				];
				$s0 = $temp[0]->bitwise_xor($temp[1]);
				$s0 = $s0->bitwise_xor($temp[2]);
				$temp = [
					$a->bitwise_and($b),
					$a->bitwise_and($c),
					$b->bitwise_and($c)
				];
				$maj = $temp[0]->bitwise_xor($temp[1]);
				$maj = $maj->bitwise_xor($temp[2]);
				$t2 = $s0->add($maj);

				$temp = [
					$e->bitwise_rightRotate(14),
					$e->bitwise_rightRotate(18),
					$e->bitwise_rightRotate(41)
				];
				$s1 = $temp[0]->bitwise_xor($temp[1]);
				$s1 = $s1->bitwise_xor($temp[2]);
				$temp = [
					$e->bitwise_and($f),
					$g->bitwise_and($e->bitwise_not())
				];
				$ch = $temp[0]->bitwise_xor($temp[1]);
				$t1 = $h->add($s1);
				$t1 = $t1->add($ch);
				$t1 = $t1->add($k[$i]);
				$t1 = $t1->add($w[$i]);

				$h = clone $g;
				$g = clone $f;
				$f = clone $e;
				$e = $d->add($t1);
				$d = clone $c;
				$c = clone $b;
				$b = clone $a;
				$a = $t1->add($t2);
			}

			$hash = [
				$hash[0]->add($a),
				$hash[1]->add($b),
				$hash[2]->add($c),
				$hash[3]->add($d),
				$hash[4]->add($e),
				$hash[5]->add($f),
				$hash[6]->add($g),
				$hash[7]->add($h)
			];
		}

		$temp = $hash[0]->toBytes() . $hash[1]->toBytes() . $hash[2]->toBytes() . $hash[3]->toBytes() .
				$hash[4]->toBytes() . $hash[5]->toBytes() . $hash[6]->toBytes() . $hash[7]->toBytes();

		return $temp;
	}

	private static function sha512_64($m, $hash)
	{
		static $k;

		if (!isset($k)) {

			$k = [
				'428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
				'3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
				'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
				'72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
				'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
				'2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
				'983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
				'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
				'27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
				'650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
				'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
				'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
				'19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
				'391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
				'748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
				'90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
				'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
				'06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
				'28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
				'4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
			];

			for ($i = 0; $i < 80; $i++) {
				list(, $k[$i]) = unpack('J', pack('H*', $k[$i]));
			}
		}

		$length = strlen($m);

		$m .= str_repeat(chr(0), 128 - (($length + 16) & 0x7F));
		$m[$length] = chr(0x80);

		$m .= pack('N4', 0, 0, 0, $length << 3);

		$chunks = str_split($m, 128);
		foreach ($chunks as $chunk) {
			$w = [];
			for ($i = 0; $i < 16; $i++) {
				list(, $w[]) = unpack('J', Strings::shift($chunk, 8));
			}

			for ($i = 16; $i < 80; $i++) {
				$temp = [
					self::rotateRight64($w[$i - 15], 1),
					self::rotateRight64($w[$i - 15], 8),
					($w[$i - 15] >> 7) & 0x01FFFFFFFFFFFFFF,
				];
				$s0 = $temp[0] ^ $temp[1] ^ $temp[2];
				$temp = [
					self::rotateRight64($w[$i - 2], 19),
					self::rotateRight64($w[$i - 2], 61),
					($w[$i - 2] >> 6) & 0x03FFFFFFFFFFFFFF,
				];
				$s1 = $temp[0] ^ $temp[1] ^ $temp[2];

				$w[$i] = $w[$i - 16];
				$w[$i] = self::add64($w[$i], $s0);
				$w[$i] = self::add64($w[$i], $w[$i - 7]);
				$w[$i] = self::add64($w[$i], $s1);
			}

			list($a, $b, $c, $d, $e, $f, $g, $h) = $hash;

			for ($i = 0; $i < 80; $i++) {
				$temp = [
					self::rotateRight64($a, 28),
					self::rotateRight64($a, 34),
					self::rotateRight64($a, 39),
				];
				$s0 = $temp[0] ^ $temp[1] ^ $temp[2];
				$temp = [$a & $b, $a & $c, $b & $c];
				$maj = $temp[0] ^ $temp[1] ^ $temp[2];
				$t2 = self::add64($s0, $maj);

				$temp = [
					self::rotateRight64($e, 14),
					self::rotateRight64($e, 18),
					self::rotateRight64($e, 41),
				];
				$s1 = $temp[0] ^ $temp[1] ^ $temp[2];
				$ch = ($e & $f) ^ ($g & ~$e);
				$t1 = self::add64($h, $s1);
				$t1 = self::add64($t1, $ch);
				$t1 = self::add64($t1, $k[$i]);
				$t1 = self::add64($t1, $w[$i]);

				$h = $g;
				$g = $f;
				$f = $e;
				$e = self::add64($d, $t1);
				$d = $c;
				$c = $b;
				$b = $a;
				$a = self::add64($t1, $t2);
			}

			$hash = [
				self::add64($hash[0], $a),
				self::add64($hash[1], $b),
				self::add64($hash[2], $c),
				self::add64($hash[3], $d),
				self::add64($hash[4], $e),
				self::add64($hash[5], $f),
				self::add64($hash[6], $g),
				self::add64($hash[7], $h),
			];
		}

		return pack('J*', ...$hash);
	}

	public function __toString()
	{
		return $this->getHash();
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Exception\NoKeyLoadedException;
use phpseclib3\File\X509;

abstract class PublicKeyLoader
{

	public static function load($key, $password = false)
	{
		try {
			return EC::load($key, $password);
		} catch (NoKeyLoadedException $e) {
		}

		try {
			return RSA::load($key, $password);
		} catch (NoKeyLoadedException $e) {
		}

		try {
			return DSA::load($key, $password);
		} catch (NoKeyLoadedException $e) {
		}

		try {
			$x509 = new X509();
			$x509->loadX509($key);
			$key = $x509->getPublicKey();
			if ($key) {
				return $key;
			}
		} catch (\Exception $e) {
		}

		throw new NoKeyLoadedException('Unable to read key');
	}

	public static function loadPrivateKey($key, $password = false)
	{
		$key = self::load($key, $password);
		if (!$key instanceof PrivateKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a private key');
		}
		return $key;
	}

	public static function loadPublicKey($key)
	{
		$key = self::load($key);
		if (!$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a public key');
		}
		return $key;
	}

	public static function loadParameters($key)
	{
		$key = self::load($key);
		if (!$key instanceof PrivateKey && !$key instanceof PublicKey) {
			throw new NoKeyLoadedException('The key that was loaded was not a parameter');
		}
		return $key;
	}
}
}

namespace phpseclib3\Crypt {

abstract class Random
{

	public static function string($length)
	{
		if (!$length) {
			return '';
		}

		try {
			return random_bytes($length);
		} catch (\Exception $e) {

		} catch (\Throwable $e) {

		}

		static $crypto = false, $v;
		if ($crypto === false) {

			$old_session_id = session_id();
			$old_use_cookies = ini_get('session.use_cookies');
			$old_session_cache_limiter = session_cache_limiter();
			$_OLD_SESSION = isset($_SESSION) ? $_SESSION : false;
			if ($old_session_id != '') {
				session_write_close();
			}

			session_id(1);
			ini_set('session.use_cookies', 0);
			session_cache_limiter('');
			session_start();

			$v = (isset($_SERVER) ? self::safe_serialize($_SERVER) : '') .
				 (isset($_POST) ? self::safe_serialize($_POST) : '') .
				 (isset($_GET) ? self::safe_serialize($_GET) : '') .
				 (isset($_COOKIE) ? self::safe_serialize($_COOKIE) : '') .

				 (version_compare(PHP_VERSION, '8.1.0', '>=') ? serialize($GLOBALS) : self::safe_serialize($GLOBALS)) .
				 self::safe_serialize($_SESSION) .
				 self::safe_serialize($_OLD_SESSION);
			$v = $seed = $_SESSION['seed'] = sha1($v, true);
			if (!isset($_SESSION['count'])) {
				$_SESSION['count'] = 0;
			}
			$_SESSION['count']++;

			session_write_close();

			if ($old_session_id != '') {
				session_id($old_session_id);
				session_start();
				ini_set('session.use_cookies', $old_use_cookies);
				session_cache_limiter($old_session_cache_limiter);
			} else {
				if ($_OLD_SESSION !== false) {
					$_SESSION = $_OLD_SESSION;
					unset($_OLD_SESSION);
				} else {
					unset($_SESSION);
				}
			}

			$key = sha1($seed . 'A', true);
			$iv = sha1($seed . 'C', true);

			switch (true) {
				case class_exists('\phpseclib3\Crypt\AES'):
					$crypto = new AES('ctr');
					break;
				case class_exists('\phpseclib3\Crypt\Twofish'):
					$crypto = new Twofish('ctr');
					break;
				case class_exists('\phpseclib3\Crypt\Blowfish'):
					$crypto = new Blowfish('ctr');
					break;
				case class_exists('\phpseclib3\Crypt\TripleDES'):
					$crypto = new TripleDES('ctr');
					break;
				case class_exists('\phpseclib3\Crypt\DES'):
					$crypto = new DES('ctr');
					break;
				case class_exists('\phpseclib3\Crypt\RC4'):
					$crypto = new RC4();
					break;
				default:
					throw new \RuntimeException(__CLASS__ . ' requires at least one symmetric cipher be loaded');
			}

			$crypto->setKey(substr($key, 0, $crypto->getKeyLength() >> 3));
			$crypto->setIV(substr($iv, 0, $crypto->getBlockLength() >> 3));
			$crypto->enableContinuousBuffer();
		}

		$result = '';
		while (strlen($result) < $length) {
			$i = $crypto->encrypt(microtime());
			$r = $crypto->encrypt($i ^ $v);
			$v = $crypto->encrypt($r ^ $i);
			$result .= $r;
		}

		return substr($result, 0, $length);
	}

	private static function safe_serialize(&$arr)
	{
		if (is_object($arr)) {
			return '';
		}
		if (!is_array($arr)) {
			return serialize($arr);
		}

		if (isset($arr['__phpseclib_marker'])) {
			return '';
		}
		$safearr = [];
		$arr['__phpseclib_marker'] = true;
		foreach (array_keys($arr) as $key) {

			if ($key !== '__phpseclib_marker') {
				$safearr[$key] = self::safe_serialize($arr[$key]);
			}
		}
		unset($arr['__phpseclib_marker']);
		return serialize($safearr);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadModeException;

class RC2 extends BlockCipher
{

	protected $block_size = 8;

	protected $key;

	private $orig_key;

	protected $key_length = 16;

	protected $cipher_name_mcrypt = 'rc2';

	protected $cfb_init_len = 500;

	private $default_key_length = 1024;

	private $current_key_length;

	private $keys;

	private static $pitable = [
		0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED,
		0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
		0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
		0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
		0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13,
		0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
		0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B,
		0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
		0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
		0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
		0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1,
		0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
		0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57,
		0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
		0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
		0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
		0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7,
		0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
		0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74,
		0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
		0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
		0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
		0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A,
		0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
		0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE,
		0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
		0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
		0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
		0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0,
		0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
		0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77,
		0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD,
		0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED,
		0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
		0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
		0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
		0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13,
		0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
		0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B,
		0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
		0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
		0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
		0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1,
		0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
		0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57,
		0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
		0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
		0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
		0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7,
		0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
		0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74,
		0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
		0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
		0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
		0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A,
		0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
		0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE,
		0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
		0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
		0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
		0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0,
		0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
		0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77,
		0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD
	];

	private static $invpitable = [
		0xD1, 0xDA, 0xB9, 0x6F, 0x9C, 0xC8, 0x78, 0x66,
		0x80, 0x2C, 0xF8, 0x37, 0xEA, 0xE0, 0x62, 0xA4,
		0xCB, 0x71, 0x50, 0x27, 0x4B, 0x95, 0xD9, 0x20,
		0x9D, 0x04, 0x91, 0xE3, 0x47, 0x6A, 0x7E, 0x53,
		0xFA, 0x3A, 0x3B, 0xB4, 0xA8, 0xBC, 0x5F, 0x68,
		0x08, 0xCA, 0x8F, 0x14, 0xD7, 0xC0, 0xEF, 0x7B,
		0x5B, 0xBF, 0x2F, 0xE5, 0xE2, 0x8C, 0xBA, 0x12,
		0xE1, 0xAF, 0xB2, 0x54, 0x5D, 0x59, 0x76, 0xDB,
		0x32, 0xA2, 0x58, 0x6E, 0x1C, 0x29, 0x64, 0xF3,
		0xE9, 0x96, 0x0C, 0x98, 0x19, 0x8D, 0x3E, 0x26,
		0xAB, 0xA5, 0x85, 0x16, 0x40, 0xBD, 0x49, 0x67,
		0xDC, 0x22, 0x94, 0xBB, 0x3C, 0xC1, 0x9B, 0xEB,
		0x45, 0x28, 0x18, 0xD8, 0x1A, 0x42, 0x7D, 0xCC,
		0xFB, 0x65, 0x8E, 0x3D, 0xCD, 0x2A, 0xA3, 0x60,
		0xAE, 0x93, 0x8A, 0x48, 0x97, 0x51, 0x15, 0xF7,
		0x01, 0x0B, 0xB7, 0x36, 0xB1, 0x2E, 0x11, 0xFD,
		0x84, 0x2D, 0x3F, 0x13, 0x88, 0xB3, 0x34, 0x24,
		0x1B, 0xDE, 0xC5, 0x1D, 0x4D, 0x2B, 0x17, 0x31,
		0x74, 0xA9, 0xC6, 0x43, 0x6D, 0x39, 0x90, 0xBE,
		0xC3, 0xB0, 0x21, 0x6B, 0xF6, 0x0F, 0xD5, 0x99,
		0x0D, 0xAC, 0x1F, 0x5C, 0x9E, 0xF5, 0xF9, 0x4C,
		0xD6, 0xDF, 0x89, 0xE4, 0x8B, 0xFF, 0xC7, 0xAA,
		0xE7, 0xED, 0x46, 0x25, 0xB6, 0x06, 0x5E, 0x35,
		0xB5, 0xEC, 0xCE, 0xE8, 0x6C, 0x30, 0x55, 0x61,
		0x4A, 0xFE, 0xA0, 0x79, 0x03, 0xF0, 0x10, 0x72,
		0x7C, 0xCF, 0x52, 0xA6, 0xA7, 0xEE, 0x44, 0xD3,
		0x9A, 0x57, 0x92, 0xD0, 0x5A, 0x7A, 0x41, 0x7F,
		0x0E, 0x00, 0x63, 0xF2, 0x4F, 0x05, 0x83, 0xC9,
		0xA1, 0xD4, 0xDD, 0xC4, 0x56, 0xF4, 0xD2, 0x77,
		0x81, 0x09, 0x82, 0x33, 0x9F, 0x07, 0x86, 0x75,
		0x38, 0x4E, 0x69, 0xF1, 0xAD, 0x23, 0x73, 0x87,
		0x70, 0x02, 0xC2, 0x1E, 0xB8, 0x0A, 0xFC, 0xE6
	];

	public function __construct($mode)
	{
		parent::__construct($mode);

		if ($this->mode == self::MODE_STREAM) {
			throw new BadModeException('Block ciphers cannot be ran in stream mode');
		}
	}

	protected function isValidEngineHelper($engine)
	{
		switch ($engine) {
			case self::ENGINE_OPENSSL:
				if ($this->current_key_length != 128 || strlen($this->orig_key) < 16) {
					return false;
				}

				if (defined('OPENSSL_VERSION_TEXT') && version_compare(preg_replace('#OpenSSL (\d+\.\d+\.\d+) .*#', '$1', OPENSSL_VERSION_TEXT), '3.0.1', '>=')) {
					return false;
				}
				$this->cipher_name_openssl_ecb = 'rc2-ecb';
				$this->cipher_name_openssl = 'rc2-' . $this->openssl_translate_mode();
		}

		return parent::isValidEngineHelper($engine);
	}

	public function setKeyLength($length)
	{
		if ($length < 8 || $length > 1024) {
			throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys between 1 and 1024 bits, inclusive, are supported');
		}

		$this->default_key_length = $this->current_key_length = $length;
		$this->explicit_key_length = $length >> 3;
	}

	public function getKeyLength()
	{
		return $this->current_key_length;
	}

	public function setKey($key, $t1 = false)
	{
		$this->orig_key = $key;

		if ($t1 === false) {
			$t1 = $this->default_key_length;
		}

		if ($t1 < 1 || $t1 > 1024) {
			throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys between 1 and 1024 bits, inclusive, are supported');
		}

		$this->current_key_length = $t1;
		if (strlen($key) < 1 || strlen($key) > 128) {
			throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes between 8 and 1024 bits, inclusive, are supported');
		}

		$t = strlen($key);

		$l = array_values(unpack('C*', $key));
		$t8 = ($t1 + 7) >> 3;
		$tm = 0xFF >> (8 * $t8 - $t1);

		$pitable = self::$pitable;
		for ($i = $t; $i < 128; $i++) {
			$l[$i] = $pitable[$l[$i - 1] + $l[$i - $t]];
		}
		$i = 128 - $t8;
		$l[$i] = $pitable[$l[$i] & $tm];
		while ($i--) {
			$l[$i] = $pitable[$l[$i + 1] ^ $l[$i + $t8]];
		}

		$l[0] = self::$invpitable[$l[0]];
		array_unshift($l, 'C*');

		$this->key = pack(...$l);
		$this->key_length = strlen($this->key);
		$this->changed = $this->nonIVChanged = true;
		$this->setEngine();
	}

	public function encrypt($plaintext)
	{
		if ($this->engine == self::ENGINE_OPENSSL) {
			$temp = $this->key;
			$this->key = $this->orig_key;
			$result = parent::encrypt($plaintext);
			$this->key = $temp;
			return $result;
		}

		return parent::encrypt($plaintext);
	}

	public function decrypt($ciphertext)
	{
		if ($this->engine == self::ENGINE_OPENSSL) {
			$temp = $this->key;
			$this->key = $this->orig_key;
			$result = parent::decrypt($ciphertext);
			$this->key = $temp;
			return $result;
		}

		return parent::decrypt($ciphertext);
	}

	protected function encryptBlock($in)
	{
		list($r0, $r1, $r2, $r3) = array_values(unpack('v*', $in));
		$keys = $this->keys;
		$limit = 20;
		$actions = [$limit => 44, 44 => 64];
		$j = 0;

		for (;;) {

			$r0 = (($r0 + $keys[$j++] + ((($r1 ^ $r2) & $r3) ^ $r1)) & 0xFFFF) << 1;
			$r0 |= $r0 >> 16;
			$r1 = (($r1 + $keys[$j++] + ((($r2 ^ $r3) & $r0) ^ $r2)) & 0xFFFF) << 2;
			$r1 |= $r1 >> 16;
			$r2 = (($r2 + $keys[$j++] + ((($r3 ^ $r0) & $r1) ^ $r3)) & 0xFFFF) << 3;
			$r2 |= $r2 >> 16;
			$r3 = (($r3 + $keys[$j++] + ((($r0 ^ $r1) & $r2) ^ $r0)) & 0xFFFF) << 5;
			$r3 |= $r3 >> 16;

			if ($j === $limit) {
				if ($limit === 64) {
					break;
				}

				$r0 += $keys[$r3 & 0x3F];
				$r1 += $keys[$r0 & 0x3F];
				$r2 += $keys[$r1 & 0x3F];
				$r3 += $keys[$r2 & 0x3F];
				$limit = $actions[$limit];
			}
		}

		return pack('vvvv', $r0, $r1, $r2, $r3);
	}

	protected function decryptBlock($in)
	{
		list($r0, $r1, $r2, $r3) = array_values(unpack('v*', $in));
		$keys = $this->keys;
		$limit = 44;
		$actions = [$limit => 20, 20 => 0];
		$j = 64;

		for (;;) {

			$r3 = ($r3 | ($r3 << 16)) >> 5;
			$r3 = ($r3 - $keys[--$j] - ((($r0 ^ $r1) & $r2) ^ $r0)) & 0xFFFF;
			$r2 = ($r2 | ($r2 << 16)) >> 3;
			$r2 = ($r2 - $keys[--$j] - ((($r3 ^ $r0) & $r1) ^ $r3)) & 0xFFFF;
			$r1 = ($r1 | ($r1 << 16)) >> 2;
			$r1 = ($r1 - $keys[--$j] - ((($r2 ^ $r3) & $r0) ^ $r2)) & 0xFFFF;
			$r0 = ($r0 | ($r0 << 16)) >> 1;
			$r0 = ($r0 - $keys[--$j] - ((($r1 ^ $r2) & $r3) ^ $r1)) & 0xFFFF;

			if ($j === $limit) {
				if ($limit === 0) {
					break;
				}

				$r3 = ($r3 - $keys[$r2 & 0x3F]) & 0xFFFF;
				$r2 = ($r2 - $keys[$r1 & 0x3F]) & 0xFFFF;
				$r1 = ($r1 - $keys[$r0 & 0x3F]) & 0xFFFF;
				$r0 = ($r0 - $keys[$r3 & 0x3F]) & 0xFFFF;
				$limit = $actions[$limit];
			}
		}

		return pack('vvvv', $r0, $r1, $r2, $r3);
	}

	protected function setupKey()
	{
		if (!isset($this->key)) {
			$this->setKey('');
		}

		$l = unpack('Ca/Cb/v*', $this->key);
		array_unshift($l, self::$pitable[$l['a']] | ($l['b'] << 8));
		unset($l['a']);
		unset($l['b']);
		$this->keys = $l;
	}

	protected function setupInlineCrypt()
	{

		$init_crypt = '$keys = $this->keys;';

		$keys = $this->keys;

		$encrypt_block = $decrypt_block = '
            $in = unpack("v4", $in);
            $r0 = $in[1];
            $r1 = $in[2];
            $r2 = $in[3];
            $r3 = $in[4];
        ';

		$limit = 20;
		$actions = [$limit => 44, 44 => 64];
		$j = 0;

		for (;;) {

			$encrypt_block .= '
                $r0 = (($r0 + ' . $keys[$j++] . ' +
                       ((($r1 ^ $r2) & $r3) ^ $r1)) & 0xFFFF) << 1;
                $r0 |= $r0 >> 16;
                $r1 = (($r1 + ' . $keys[$j++] . ' +
                       ((($r2 ^ $r3) & $r0) ^ $r2)) & 0xFFFF) << 2;
                $r1 |= $r1 >> 16;
                $r2 = (($r2 + ' . $keys[$j++] . ' +
                       ((($r3 ^ $r0) & $r1) ^ $r3)) & 0xFFFF) << 3;
                $r2 |= $r2 >> 16;
                $r3 = (($r3 + ' . $keys[$j++] . ' +
                       ((($r0 ^ $r1) & $r2) ^ $r0)) & 0xFFFF) << 5;
                $r3 |= $r3 >> 16;';

			if ($j === $limit) {
				if ($limit === 64) {
					break;
				}

				$encrypt_block .= '
                    $r0 += $keys[$r3 & 0x3F];
                    $r1 += $keys[$r0 & 0x3F];
                    $r2 += $keys[$r1 & 0x3F];
                    $r3 += $keys[$r2 & 0x3F];';
				$limit = $actions[$limit];
			}
		}

		$encrypt_block .= '$in = pack("v4", $r0, $r1, $r2, $r3);';

		$limit = 44;
		$actions = [$limit => 20, 20 => 0];
		$j = 64;

		for (;;) {

			$decrypt_block .= '
                $r3 = ($r3 | ($r3 << 16)) >> 5;
                $r3 = ($r3 - ' . $keys[--$j] . ' -
                       ((($r0 ^ $r1) & $r2) ^ $r0)) & 0xFFFF;
                $r2 = ($r2 | ($r2 << 16)) >> 3;
                $r2 = ($r2 - ' . $keys[--$j] . ' -
                       ((($r3 ^ $r0) & $r1) ^ $r3)) & 0xFFFF;
                $r1 = ($r1 | ($r1 << 16)) >> 2;
                $r1 = ($r1 - ' . $keys[--$j] . ' -
                       ((($r2 ^ $r3) & $r0) ^ $r2)) & 0xFFFF;
                $r0 = ($r0 | ($r0 << 16)) >> 1;
                $r0 = ($r0 - ' . $keys[--$j] . ' -
                       ((($r1 ^ $r2) & $r3) ^ $r1)) & 0xFFFF;';

			if ($j === $limit) {
				if ($limit === 0) {
					break;
				}

				$decrypt_block .= '
                    $r3 = ($r3 - $keys[$r2 & 0x3F]) & 0xFFFF;
                    $r2 = ($r2 - $keys[$r1 & 0x3F]) & 0xFFFF;
                    $r1 = ($r1 - $keys[$r0 & 0x3F]) & 0xFFFF;
                    $r0 = ($r0 - $keys[$r3 & 0x3F]) & 0xFFFF;';
				$limit = $actions[$limit];
			}
		}

		$decrypt_block .= '$in = pack("v4", $r0, $r1, $r2, $r3);';

		$this->inline_crypt = $this->createInlineCryptFunction(
			[
				'init_crypt'	=> $init_crypt,
				'encrypt_block' => $encrypt_block,
				'decrypt_block' => $decrypt_block
			]
		);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\StreamCipher;

class RC4 extends StreamCipher
{

	const ENCRYPT = 0;

	const DECRYPT = 1;

	protected $key_length = 128;

	protected $cipher_name_mcrypt = 'arcfour';

	protected $key;

	private $stream;

	protected function isValidEngineHelper($engine)
	{
		if ($engine == self::ENGINE_OPENSSL) {
			if ($this->continuousBuffer) {
				return false;
			}

			if (defined('OPENSSL_VERSION_TEXT') && version_compare(preg_replace('#OpenSSL (\d+\.\d+\.\d+) .*#', '$1', OPENSSL_VERSION_TEXT), '3.0.1', '>=')) {
				return false;
			}
			$this->cipher_name_openssl = 'rc4-40';
		}

		return parent::isValidEngineHelper($engine);
	}

	public function setKeyLength($length)
	{
		if ($length < 8 || $length > 2048) {
			throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys between 1 and 256 bytes are supported');
		}

		$this->key_length = $length >> 3;

		parent::setKeyLength($length);
	}

	public function setKey($key)
	{
		$length = strlen($key);
		if ($length < 1 || $length > 256) {
			throw new \LengthException('Key size of ' . $length . ' bytes is not supported by RC4. Keys must be between 1 and 256 bytes long');
		}

		parent::setKey($key);
	}

	public function encrypt($plaintext)
	{
		if ($this->engine != self::ENGINE_INTERNAL) {
			return parent::encrypt($plaintext);
		}
		return $this->crypt($plaintext, self::ENCRYPT);
	}

	public function decrypt($ciphertext)
	{
		if ($this->engine != self::ENGINE_INTERNAL) {
			return parent::decrypt($ciphertext);
		}
		return $this->crypt($ciphertext, self::DECRYPT);
	}

	protected function encryptBlock($in)
	{

	}

	protected function decryptBlock($in)
	{

	}

	protected function setupKey()
	{
		$key = $this->key;
		$keyLength = strlen($key);
		$keyStream = range(0, 255);
		$j = 0;
		for ($i = 0; $i < 256; $i++) {
			$j = ($j + $keyStream[$i] + ord($key[$i % $keyLength])) & 255;
			$temp = $keyStream[$i];
			$keyStream[$i] = $keyStream[$j];
			$keyStream[$j] = $temp;
		}

		$this->stream = [];
		$this->stream[self::DECRYPT] = $this->stream[self::ENCRYPT] = [
			0,
			0,
			$keyStream
		];
	}

	private function crypt($text, $mode)
	{
		if ($this->changed) {
			$this->setup();
		}

		$stream = &$this->stream[$mode];
		if ($this->continuousBuffer) {
			$i = &$stream[0];
			$j = &$stream[1];
			$keyStream = &$stream[2];
		} else {
			$i = $stream[0];
			$j = $stream[1];
			$keyStream = $stream[2];
		}

		$len = strlen($text);
		for ($k = 0; $k < $len; ++$k) {
			$i = ($i + 1) & 255;
			$ksi = $keyStream[$i];
			$j = ($j + $ksi) & 255;
			$ksj = $keyStream[$j];

			$keyStream[$i] = $ksj;
			$keyStream[$j] = $ksi;
			$text[$k] = $text[$k] ^ chr($keyStream[($ksj + $ksi) & 255]);
		}

		return $text;
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\AsymmetricKey;
use phpseclib3\Crypt\RSA\Formats\Keys\PSS;
use phpseclib3\Crypt\RSA\PrivateKey;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Exception\InconsistentSetupException;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Math\BigInteger;

abstract class RSA extends AsymmetricKey
{

	const ALGORITHM = 'RSA';

	const ENCRYPTION_OAEP = 1;

	const ENCRYPTION_PKCS1 = 2;

	const ENCRYPTION_NONE = 4;

	const SIGNATURE_PSS = 16;

	const SIGNATURE_RELAXED_PKCS1 = 32;

	const SIGNATURE_PKCS1 = 64;

	protected $encryptionPadding = self::ENCRYPTION_OAEP;

	protected $signaturePadding = self::SIGNATURE_PSS;

	protected $hLen;

	protected $sLen;

	protected $label = '';

	protected $mgfHash;

	protected $mgfHLen;

	protected $modulus;

	protected $k;

	protected $exponent;

	private static $defaultExponent = 65537;

	protected static $enableBlinding = true;

	protected static $configFile;

	private static $smallestPrime = 4096;

	protected $publicExponent;

	public static function setExponent($val)
	{
		self::$defaultExponent = $val;
	}

	public static function setSmallestPrime($val)
	{
		self::$smallestPrime = $val;
	}

	public static function setOpenSSLConfigPath($val)
	{
		self::$configFile = $val;
	}

	public static function createKey($bits = 2048)
	{
		self::initialize_static_variables();

		$class = new \ReflectionClass(static::class);
		if ($class->isFinal()) {
			throw new \RuntimeException('createKey() should not be called from final classes (' . static::class . ')');
		}

		$regSize = $bits >> 1;
		if ($regSize > self::$smallestPrime) {
			$num_primes = floor($bits / self::$smallestPrime);
			$regSize = self::$smallestPrime;
		} else {
			$num_primes = 2;
		}

		if ($num_primes == 2 && $bits >= 384 && self::$defaultExponent == 65537) {
			if (!isset(self::$engines['PHP'])) {
				self::useBestEngine();
			}

			if (self::$engines['OpenSSL']) {
				$config = [];
				if (self::$configFile) {
					$config['config'] = self::$configFile;
				}
				$rsa = openssl_pkey_new(['private_key_bits' => $bits] + $config);
				openssl_pkey_export($rsa, $privatekeystr, null, $config);

				while (openssl_error_string() !== false) {
				}

				return RSA::load($privatekeystr);
			}
		}

		static $e;
		if (!isset($e)) {
			$e = new BigInteger(self::$defaultExponent);
		}

		$n = clone self::$one;
		$exponents = $coefficients = $primes = [];
		$lcm = [
			'top' => clone self::$one,
			'bottom' => false
		];

		do {
			for ($i = 1; $i <= $num_primes; $i++) {
				if ($i != $num_primes) {
					$primes[$i] = BigInteger::randomPrime($regSize);
				} else {
					extract(BigInteger::minMaxBits($bits));

					list($min) = $min->divide($n);
					$min = $min->add(self::$one);
					list($max) = $max->divide($n);
					$primes[$i] = BigInteger::randomRangePrime($min, $max);
				}

				if ($i > 2) {
					$coefficients[$i] = $n->modInverse($primes[$i]);
				}

				$n = $n->multiply($primes[$i]);

				$temp = $primes[$i]->subtract(self::$one);

				$lcm['top'] = $lcm['top']->multiply($temp);
				$lcm['bottom'] = $lcm['bottom'] === false ? $temp : $lcm['bottom']->gcd($temp);
			}

			list($temp) = $lcm['top']->divide($lcm['bottom']);
			$gcd = $temp->gcd($e);
			$i0 = 1;
		} while (!$gcd->equals(self::$one));

		$coefficients[2] = $primes[2]->modInverse($primes[1]);

		$d = $e->modInverse($temp);

		foreach ($primes as $i => $prime) {
			$temp = $prime->subtract(self::$one);
			$exponents[$i] = $e->modInverse($temp);
		}

		$privatekey = new PrivateKey();
		$privatekey->modulus = $n;
		$privatekey->k = $bits >> 3;
		$privatekey->publicExponent = $e;
		$privatekey->exponent = $d;
		$privatekey->primes = $primes;
		$privatekey->exponents = $exponents;
		$privatekey->coefficients = $coefficients;

		return $privatekey;
	}

	protected static function onLoad(array $components)
	{
		$key = $components['isPublicKey'] ?
			new PublicKey() :
			new PrivateKey();

		$key->modulus = $components['modulus'];
		$key->publicExponent = $components['publicExponent'];
		$key->k = $key->modulus->getLengthInBytes();

		if ($components['isPublicKey'] || !isset($components['privateExponent'])) {
			$key->exponent = $key->publicExponent;
		} else {
			$key->privateExponent = $components['privateExponent'];
			$key->exponent = $key->privateExponent;
			$key->primes = $components['primes'];
			$key->exponents = $components['exponents'];
			$key->coefficients = $components['coefficients'];
		}

		if ($components['format'] == PSS::class) {

			if (isset($components['hash'])) {
				$key = $key->withHash($components['hash']);
			}
			if (isset($components['MGFHash'])) {
				$key = $key->withMGFHash($components['MGFHash']);
			}
			if (isset($components['saltLength'])) {
				$key = $key->withSaltLength($components['saltLength']);
			}
		}

		return $key;
	}

	protected static function initialize_static_variables()
	{
		if (!isset(self::$configFile)) {
			self::$configFile = dirname(__FILE__) . '/openssl.cnf';
		}

		parent::initialize_static_variables();
	}

	protected function __construct()
	{
		parent::__construct();

		$this->hLen = $this->hash->getLengthInBytes();
		$this->mgfHash = new Hash('sha256');
		$this->mgfHLen = $this->mgfHash->getLengthInBytes();
	}

	protected function i2osp($x, $xLen)
	{
		if ($x === false) {
			return false;
		}
		$x = $x->toBytes();
		if (strlen($x) > $xLen) {
			throw new \OutOfRangeException('Resultant string length out of range');
		}
		return str_pad($x, $xLen, chr(0), STR_PAD_LEFT);
	}

	protected function os2ip($x)
	{
		return new BigInteger($x, 256);
	}

	protected function emsa_pkcs1_v1_5_encode($m, $emLen)
	{
		$h = $this->hash->hash($m);

		switch ($this->hash->getHash()) {
			case 'md2':
				$t = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x02\x05\x00\x04\x10";
				break;
			case 'md5':
				$t = "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10";
				break;
			case 'sha1':
				$t = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
				break;
			case 'sha256':
				$t = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
				break;
			case 'sha384':
				$t = "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
				break;
			case 'sha512':
				$t = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
				break;

			case 'sha224':
				$t = "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c";
				break;
			case 'sha512/224':
				$t = "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00\x04\x1c";
				break;
			case 'sha512/256':
				$t = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00\x04\x20";
		}
		$t .= $h;
		$tLen = strlen($t);

		if ($emLen < $tLen + 11) {
			throw new \LengthException('Intended encoded message length too short');
		}

		$ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

		$em = "\0\1$ps\0$t";

		return $em;
	}

	protected function emsa_pkcs1_v1_5_encode_without_null($m, $emLen)
	{
		$h = $this->hash->hash($m);

		switch ($this->hash->getHash()) {
			case 'sha1':
				$t = "\x30\x1f\x30\x07\x06\x05\x2b\x0e\x03\x02\x1a\x04\x14";
				break;
			case 'sha256':
				$t = "\x30\x2f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x04\x20";
				break;
			case 'sha384':
				$t = "\x30\x3f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x04\x30";
				break;
			case 'sha512':
				$t = "\x30\x4f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x04\x40";
				break;

			case 'sha224':
				$t = "\x30\x2b\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x04\x1c";
				break;
			case 'sha512/224':
				$t = "\x30\x2b\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x04\x1c";
				break;
			case 'sha512/256':
				$t = "\x30\x2f\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x04\x20";
				break;
			default:
				throw new UnsupportedAlgorithmException('md2 and md5 require NULLs');
		}
		$t .= $h;
		$tLen = strlen($t);

		if ($emLen < $tLen + 11) {
			throw new \LengthException('Intended encoded message length too short');
		}

		$ps = str_repeat(chr(0xFF), $emLen - $tLen - 3);

		$em = "\0\1$ps\0$t";

		return $em;
	}

	protected function mgf1($mgfSeed, $maskLen)
	{

		$t = '';
		$count = ceil($maskLen / $this->mgfHLen);
		for ($i = 0; $i < $count; $i++) {
			$c = pack('N', $i);
			$t .= $this->mgfHash->hash($mgfSeed . $c);
		}

		return substr($t, 0, $maskLen);
	}

	public function getLength()
	{
		return !isset($this->modulus) ? 0 : $this->modulus->getLength();
	}

	public function withHash($hash)
	{
		$new = clone $this;

		switch (strtolower($hash)) {
			case 'md2':
			case 'md5':
			case 'sha1':
			case 'sha256':
			case 'sha384':
			case 'sha512':
			case 'sha224':
			case 'sha512/224':
			case 'sha512/256':
				$new->hash = new Hash($hash);
				break;
			default:
				throw new UnsupportedAlgorithmException(
					'The only supported hash algorithms are: md2, md5, sha1, sha256, sha384, sha512, sha224, sha512/224, sha512/256'
				);
		}
		$new->hLen = $new->hash->getLengthInBytes();

		return $new;
	}

	public function withMGFHash($hash)
	{
		$new = clone $this;

		switch (strtolower($hash)) {
			case 'md2':
			case 'md5':
			case 'sha1':
			case 'sha256':
			case 'sha384':
			case 'sha512':
			case 'sha224':
			case 'sha512/224':
			case 'sha512/256':
				$new->mgfHash = new Hash($hash);
				break;
			default:
				throw new UnsupportedAlgorithmException(
					'The only supported hash algorithms are: md2, md5, sha1, sha256, sha384, sha512, sha224, sha512/224, sha512/256'
				);
		}
		$new->mgfHLen = $new->mgfHash->getLengthInBytes();

		return $new;
	}

	public function getMGFHash()
	{
		return clone $this->mgfHash;
	}

	public function withSaltLength($sLen)
	{
		$new = clone $this;
		$new->sLen = $sLen;
		return $new;
	}

	public function getSaltLength()
	{
		return $this->sLen !== null ? $this->sLen : $this->hLen;
	}

	public function withLabel($label)
	{
		$new = clone $this;
		$new->label = $label;
		return $new;
	}

	public function getLabel()
	{
		return $this->label;
	}

	public function withPadding($padding)
	{
		$masks = [
			self::ENCRYPTION_OAEP,
			self::ENCRYPTION_PKCS1,
			self::ENCRYPTION_NONE
		];
		$encryptedCount = 0;
		$selected = 0;
		foreach ($masks as $mask) {
			if ($padding & $mask) {
				$selected = $mask;
				$encryptedCount++;
			}
		}
		if ($encryptedCount > 1) {
			throw new InconsistentSetupException('Multiple encryption padding modes have been selected; at most only one should be selected');
		}
		$encryptionPadding = $selected;

		$masks = [
			self::SIGNATURE_PSS,
			self::SIGNATURE_RELAXED_PKCS1,
			self::SIGNATURE_PKCS1
		];
		$signatureCount = 0;
		$selected = 0;
		foreach ($masks as $mask) {
			if ($padding & $mask) {
				$selected = $mask;
				$signatureCount++;
			}
		}
		if ($signatureCount > 1) {
			throw new InconsistentSetupException('Multiple signature padding modes have been selected; at most only one should be selected');
		}
		$signaturePadding = $selected;

		$new = clone $this;
		if ($encryptedCount) {
			$new->encryptionPadding = $encryptionPadding;
		}
		if ($signatureCount) {
			$new->signaturePadding = $signaturePadding;
		}
		return $new;
	}

	public function getPadding()
	{
		return $this->signaturePadding | $this->encryptionPadding;
	}

	public function getEngine()
	{
		if (!isset(self::$engines['PHP'])) {
			self::useBestEngine();
		}
		return self::$engines['OpenSSL'] && self::$defaultExponent == 65537 ?
			'OpenSSL' :
			'PHP';
	}

	public static function enableBlinding()
	{
		static::$enableBlinding = true;
	}

	public static function disableBlinding()
	{
		static::$enableBlinding = false;
	}
}
}

namespace phpseclib3\Crypt\RSA {

use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\Formats\Keys\PSS;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\Math\BigInteger;

final class PrivateKey extends RSA implements Common\PrivateKey
{
	use Common\Traits\PasswordProtected;

	protected $primes;

	protected $exponents;

	protected $coefficients;

	protected $privateExponent;

	private function rsadp(BigInteger $c)
	{
		if ($c->compare(self::$zero) < 0 || $c->compare($this->modulus) > 0) {
			throw new \OutOfRangeException('Ciphertext representative out of range');
		}
		return $this->exponentiate($c);
	}

	private function rsasp1(BigInteger $m)
	{
		if ($m->compare(self::$zero) < 0 || $m->compare($this->modulus) > 0) {
			throw new \OutOfRangeException('Signature representative out of range');
		}
		return $this->exponentiate($m);
	}

	protected function exponentiate(BigInteger $x)
	{
		switch (true) {
			case empty($this->primes):
			case $this->primes[1]->equals(self::$zero):
			case empty($this->coefficients):
			case $this->coefficients[2]->equals(self::$zero):
			case empty($this->exponents):
			case $this->exponents[1]->equals(self::$zero):
				return $x->modPow($this->exponent, $this->modulus);
		}

		$num_primes = count($this->primes);

		if (!static::$enableBlinding) {
			$m_i = [
				1 => $x->modPow($this->exponents[1], $this->primes[1]),
				2 => $x->modPow($this->exponents[2], $this->primes[2])
			];
			$h = $m_i[1]->subtract($m_i[2]);
			$h = $h->multiply($this->coefficients[2]);
			list(, $h) = $h->divide($this->primes[1]);
			$m = $m_i[2]->add($h->multiply($this->primes[2]));

			$r = $this->primes[1];
			for ($i = 3; $i <= $num_primes; $i++) {
				$m_i = $x->modPow($this->exponents[$i], $this->primes[$i]);

				$r = $r->multiply($this->primes[$i - 1]);

				$h = $m_i->subtract($m);
				$h = $h->multiply($this->coefficients[$i]);
				list(, $h) = $h->divide($this->primes[$i]);

				$m = $m->add($r->multiply($h));
			}
		} else {
			$smallest = $this->primes[1];
			for ($i = 2; $i <= $num_primes; $i++) {
				if ($smallest->compare($this->primes[$i]) > 0) {
					$smallest = $this->primes[$i];
				}
			}

			$r = BigInteger::randomRange(self::$one, $smallest->subtract(self::$one));

			$m_i = [
				1 => $this->blind($x, $r, 1),
				2 => $this->blind($x, $r, 2)
			];
			$h = $m_i[1]->subtract($m_i[2]);
			$h = $h->multiply($this->coefficients[2]);
			list(, $h) = $h->divide($this->primes[1]);
			$m = $m_i[2]->add($h->multiply($this->primes[2]));

			$r = $this->primes[1];
			for ($i = 3; $i <= $num_primes; $i++) {
				$m_i = $this->blind($x, $r, $i);

				$r = $r->multiply($this->primes[$i - 1]);

				$h = $m_i->subtract($m);
				$h = $h->multiply($this->coefficients[$i]);
				list(, $h) = $h->divide($this->primes[$i]);

				$m = $m->add($r->multiply($h));
			}
		}

		return $m;
	}

	private function blind(BigInteger $x, BigInteger $r, $i)
	{
		$x = $x->multiply($r->modPow($this->publicExponent, $this->primes[$i]));
		$x = $x->modPow($this->exponents[$i], $this->primes[$i]);

		$r = $r->modInverse($this->primes[$i]);
		$x = $x->multiply($r);
		list(, $x) = $x->divide($this->primes[$i]);

		return $x;
	}

	private function emsa_pss_encode($m, $emBits)
	{

		$emLen = ($emBits + 1) >> 3;
		$sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

		$mHash = $this->hash->hash($m);
		if ($emLen < $this->hLen + $sLen + 2) {
			throw new \LengthException('RSA modulus too short');
		}

		$salt = Random::string($sLen);
		$m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
		$h = $this->hash->hash($m2);
		$ps = str_repeat(chr(0), $emLen - $sLen - $this->hLen - 2);
		$db = $ps . chr(1) . $salt;
		$dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
		$maskedDB = $db ^ $dbMask;
		$maskedDB[0] = ~chr(0xFF << ($emBits & 7)) & $maskedDB[0];
		$em = $maskedDB . $h . chr(0xBC);

		return $em;
	}

	private function rsassa_pss_sign($m)
	{

		$em = $this->emsa_pss_encode($m, 8 * $this->k - 1);

		$m = $this->os2ip($em);
		$s = $this->rsasp1($m);
		$s = $this->i2osp($s, $this->k);

		return $s;
	}

	private function rsassa_pkcs1_v1_5_sign($m)
	{

		try {
			$em = $this->emsa_pkcs1_v1_5_encode($m, $this->k);
		} catch (\LengthException $e) {
			throw new \LengthException('RSA modulus too short');
		}

		$m = $this->os2ip($em);
		$s = $this->rsasp1($m);
		$s = $this->i2osp($s, $this->k);

		return $s;
	}

	public function sign($message)
	{
		switch ($this->signaturePadding) {
			case self::SIGNATURE_PKCS1:
			case self::SIGNATURE_RELAXED_PKCS1:
				return $this->rsassa_pkcs1_v1_5_sign($message);

			default:
				return $this->rsassa_pss_sign($message);
		}
	}

	private function rsaes_pkcs1_v1_5_decrypt($c)
	{

		if (strlen($c) != $this->k) {
			throw new \LengthException('Ciphertext representative too long');
		}

		$c = $this->os2ip($c);
		$m = $this->rsadp($c);
		$em = $this->i2osp($m, $this->k);

		if (ord($em[0]) != 0 || ord($em[1]) > 2) {
			throw new \RuntimeException('Decryption error');
		}

		$ps = substr($em, 2, strpos($em, chr(0), 2) - 2);
		$m = substr($em, strlen($ps) + 3);

		if (strlen($ps) < 8) {
			throw new \RuntimeException('Decryption error');
		}

		return $m;
	}

	private function rsaes_oaep_decrypt($c)
	{

		if (strlen($c) != $this->k || $this->k < 2 * $this->hLen + 2) {
			throw new \LengthException('Ciphertext representative too long');
		}

		$c = $this->os2ip($c);
		$m = $this->rsadp($c);
		$em = $this->i2osp($m, $this->k);

		$lHash = $this->hash->hash($this->label);
		$y = ord($em[0]);
		$maskedSeed = substr($em, 1, $this->hLen);
		$maskedDB = substr($em, $this->hLen + 1);
		$seedMask = $this->mgf1($maskedDB, $this->hLen);
		$seed = $maskedSeed ^ $seedMask;
		$dbMask = $this->mgf1($seed, $this->k - $this->hLen - 1);
		$db = $maskedDB ^ $dbMask;
		$lHash2 = substr($db, 0, $this->hLen);
		$m = substr($db, $this->hLen);
		$hashesMatch = hash_equals($lHash, $lHash2);
		$leadingZeros = 1;
		$patternMatch = 0;
		$offset = 0;
		for ($i = 0; $i < strlen($m); $i++) {
			$patternMatch |= $leadingZeros & ($m[$i] === "\1");
			$leadingZeros &= $m[$i] === "\0";
			$offset += $patternMatch ? 0 : 1;
		}

		if (!$hashesMatch | !$patternMatch) {
			throw new \RuntimeException('Decryption error');
		}

		return substr($m, $offset + 1);
	}

	private function raw_encrypt($m)
	{
		if (strlen($m) > $this->k) {
			throw new \LengthException('Ciphertext representative too long');
		}

		$temp = $this->os2ip($m);
		$temp = $this->rsadp($temp);
		return	$this->i2osp($temp, $this->k);
	}

	public function decrypt($ciphertext)
	{
		switch ($this->encryptionPadding) {
			case self::ENCRYPTION_NONE:
				return $this->raw_encrypt($ciphertext);
			case self::ENCRYPTION_PKCS1:
				return $this->rsaes_pkcs1_v1_5_decrypt($ciphertext);

			default:
				return $this->rsaes_oaep_decrypt($ciphertext);
		}
	}

	public function getPublicKey()
	{
		$type = self::validatePlugin('Keys', 'PKCS8', 'savePublicKey');
		if (empty($this->modulus) || empty($this->publicExponent)) {
			throw new \RuntimeException('Public key components not found');
		}

		$key = $type::savePublicKey($this->modulus, $this->publicExponent);
		return RSA::loadFormat('PKCS8', $key)
			->withHash($this->hash->getHash())
			->withMGFHash($this->mgfHash->getHash())
			->withSaltLength($this->sLen)
			->withLabel($this->label)
			->withPadding($this->signaturePadding | $this->encryptionPadding);
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin(
			'Keys',
			$type,
			empty($this->primes) ? 'savePublicKey' : 'savePrivateKey'
		);

		if ($type == PSS::class) {
			if ($this->signaturePadding == self::SIGNATURE_PSS) {
				$options += [
					'hash' => $this->hash->getHash(),
					'MGFHash' => $this->mgfHash->getHash(),
					'saltLength' => $this->getSaltLength()
				];
			} else {
				throw new UnsupportedFormatException('The PSS format can only be used when the signature method has been explicitly set to PSS');
			}
		}

		if (empty($this->primes)) {
			return $type::savePublicKey($this->modulus, $this->exponent, $options);
		}

		return $type::savePrivateKey($this->modulus, $this->publicExponent, $this->exponent, $this->primes, $this->exponents, $this->coefficients, $this->password, $options);

	}
}
}

namespace phpseclib3\Crypt\RSA {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\Formats\Keys\PSS;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\Exception\UnsupportedFormatException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\DigestInfo;
use phpseclib3\Math\BigInteger;

final class PublicKey extends RSA implements Common\PublicKey
{
	use Common\Traits\Fingerprint;

	private function exponentiate(BigInteger $x)
	{
		return $x->modPow($this->exponent, $this->modulus);
	}

	private function rsavp1($s)
	{
		if ($s->compare(self::$zero) < 0 || $s->compare($this->modulus) > 0) {
			return false;
		}
		return $this->exponentiate($s);
	}

	private function rsassa_pkcs1_v1_5_verify($m, $s)
	{

		if (strlen($s) != $this->k) {
			return false;
		}

		$s = $this->os2ip($s);
		$m2 = $this->rsavp1($s);
		if ($m2 === false) {
			return false;
		}
		$em = $this->i2osp($m2, $this->k);
		if ($em === false) {
			return false;
		}

		$exception = false;

		try {
			$em2 = $this->emsa_pkcs1_v1_5_encode($m, $this->k);
			$r1 = hash_equals($em, $em2);
		} catch (\LengthException $e) {
			$exception = true;
		}

		try {
			$em3 = $this->emsa_pkcs1_v1_5_encode_without_null($m, $this->k);
			$r2 = hash_equals($em, $em3);
		} catch (\LengthException $e) {
			$exception = true;
		} catch (UnsupportedAlgorithmException $e) {
			$r2 = false;
		}

		if ($exception) {
			throw new \LengthException('RSA modulus too short');
		}

		return $r1 || $r2;
	}

	private function rsassa_pkcs1_v1_5_relaxed_verify($m, $s)
	{

		if (strlen($s) != $this->k) {
			return false;
		}

		$s = $this->os2ip($s);
		$m2 = $this->rsavp1($s);
		if ($m2 === false) {
			return false;
		}
		$em = $this->i2osp($m2, $this->k);
		if ($em === false) {
			return false;
		}

		if (Strings::shift($em, 2) != "\0\1") {
			return false;
		}

		$em = ltrim($em, "\xFF");
		if (Strings::shift($em) != "\0") {
			return false;
		}

		$decoded = ASN1::decodeBER($em);
		if (!is_array($decoded) || empty($decoded[0]) || strlen($em) > $decoded[0]['length']) {
			return false;
		}

		static $oids;
		if (!isset($oids)) {
			$oids = [
				'md2' => '1.2.840.113549.2.2',
				'md4' => '1.2.840.113549.2.4',
				'md5' => '1.2.840.113549.2.5',
				'id-sha1' => '1.3.14.3.2.26',
				'id-sha256' => '2.16.840.1.101.3.4.2.1',
				'id-sha384' => '2.16.840.1.101.3.4.2.2',
				'id-sha512' => '2.16.840.1.101.3.4.2.3',

				'id-sha224' => '2.16.840.1.101.3.4.2.4',
				'id-sha512/224' => '2.16.840.1.101.3.4.2.5',
				'id-sha512/256' => '2.16.840.1.101.3.4.2.6',
			];
			ASN1::loadOIDs($oids);
		}

		$decoded = ASN1::asn1map($decoded[0], DigestInfo::MAP);
		if (!isset($decoded) || $decoded === false) {
			return false;
		}

		if (!isset($oids[$decoded['digestAlgorithm']['algorithm']])) {
			return false;
		}

		if (isset($decoded['digestAlgorithm']['parameters']) && $decoded['digestAlgorithm']['parameters'] !== ['null' => '']) {
			return false;
		}

		$hash = $decoded['digestAlgorithm']['algorithm'];
		$hash = substr($hash, 0, 3) == 'id-' ?
			substr($hash, 3) :
			$hash;
		$hash = new Hash($hash);
		$em = $hash->hash($m);
		$em2 = $decoded['digest'];

		return hash_equals($em, $em2);
	}

	private function emsa_pss_verify($m, $em, $emBits)
	{

		$emLen = ($emBits + 7) >> 3;
		$sLen = $this->sLen !== null ? $this->sLen : $this->hLen;

		$mHash = $this->hash->hash($m);
		if ($emLen < $this->hLen + $sLen + 2) {
			return false;
		}

		if ($em[strlen($em) - 1] != chr(0xBC)) {
			return false;
		}

		$maskedDB = substr($em, 0, -$this->hLen - 1);
		$h = substr($em, -$this->hLen - 1, $this->hLen);
		$temp = chr(0xFF << ($emBits & 7));
		if ((~$maskedDB[0] & $temp) != $temp) {
			return false;
		}
		$dbMask = $this->mgf1($h, $emLen - $this->hLen - 1);
		$db = $maskedDB ^ $dbMask;
		$db[0] = ~chr(0xFF << ($emBits & 7)) & $db[0];
		$temp = $emLen - $this->hLen - $sLen - 2;
		if (substr($db, 0, $temp) != str_repeat(chr(0), $temp) || ord($db[$temp]) != 1) {
			return false;
		}
		$salt = substr($db, $temp + 1);
		$m2 = "\0\0\0\0\0\0\0\0" . $mHash . $salt;
		$h2 = $this->hash->hash($m2);
		return hash_equals($h, $h2);
	}

	private function rsassa_pss_verify($m, $s)
	{

		if (strlen($s) != $this->k) {
			return false;
		}

		$modBits = strlen($this->modulus->toBits());

		$s2 = $this->os2ip($s);
		$m2 = $this->rsavp1($s2);
		$em = $this->i2osp($m2, $this->k);
		if ($em === false) {
			return false;
		}

		return $this->emsa_pss_verify($m, $em, $modBits - 1);
	}

	public function verify($message, $signature)
	{
		switch ($this->signaturePadding) {
			case self::SIGNATURE_RELAXED_PKCS1:
				return $this->rsassa_pkcs1_v1_5_relaxed_verify($message, $signature);
			case self::SIGNATURE_PKCS1:
				return $this->rsassa_pkcs1_v1_5_verify($message, $signature);

			default:
				return $this->rsassa_pss_verify($message, $signature);
		}
	}

	private function rsaes_pkcs1_v1_5_encrypt($m, $pkcs15_compat = false)
	{
		$mLen = strlen($m);

		if ($mLen > $this->k - 11) {
			throw new \LengthException('Message too long');
		}

		$psLen = $this->k - $mLen - 3;
		$ps = '';
		while (strlen($ps) != $psLen) {
			$temp = Random::string($psLen - strlen($ps));
			$temp = str_replace("\x00", '', $temp);
			$ps .= $temp;
		}
		$type = 2;
		$em = chr(0) . chr($type) . $ps . chr(0) . $m;

		$m = $this->os2ip($em);
		$c = $this->rsaep($m);
		$c = $this->i2osp($c, $this->k);

		return $c;
	}

	private function rsaes_oaep_encrypt($m)
	{
		$mLen = strlen($m);

		if ($mLen > $this->k - 2 * $this->hLen - 2) {
			throw new \LengthException('Message too long');
		}

		$lHash = $this->hash->hash($this->label);
		$ps = str_repeat(chr(0), $this->k - $mLen - 2 * $this->hLen - 2);
		$db = $lHash . $ps . chr(1) . $m;
		$seed = Random::string($this->hLen);
		$dbMask = $this->mgf1($seed, $this->k - $this->hLen - 1);
		$maskedDB = $db ^ $dbMask;
		$seedMask = $this->mgf1($maskedDB, $this->hLen);
		$maskedSeed = $seed ^ $seedMask;
		$em = chr(0) . $maskedSeed . $maskedDB;

		$m = $this->os2ip($em);
		$c = $this->rsaep($m);
		$c = $this->i2osp($c, $this->k);

		return $c;
	}

	private function rsaep($m)
	{
		if ($m->compare(self::$zero) < 0 || $m->compare($this->modulus) > 0) {
			throw new \OutOfRangeException('Message representative out of range');
		}
		return $this->exponentiate($m);
	}

	private function raw_encrypt($m)
	{
		if (strlen($m) > $this->k) {
			throw new \LengthException('Message too long');
		}

		$temp = $this->os2ip($m);
		$temp = $this->rsaep($temp);
		return	$this->i2osp($temp, $this->k);
	}

	public function encrypt($plaintext)
	{
		switch ($this->encryptionPadding) {
			case self::ENCRYPTION_NONE:
				return $this->raw_encrypt($plaintext);
			case self::ENCRYPTION_PKCS1:
				return $this->rsaes_pkcs1_v1_5_encrypt($plaintext);

			default:
				return $this->rsaes_oaep_encrypt($plaintext);
		}
	}

	public function toString($type, array $options = [])
	{
		$type = self::validatePlugin('Keys', $type, 'savePublicKey');

		if ($type == PSS::class) {
			if ($this->signaturePadding == self::SIGNATURE_PSS) {
				$options += [
					'hash' => $this->hash->getHash(),
					'MGFHash' => $this->mgfHash->getHash(),
					'saltLength' => $this->getSaltLength()
				];
			} else {
				throw new UnsupportedFormatException('The PSS format can only be used when the signature method has been explicitly set to PSS');
			}
		}

		return $type::savePublicKey($this->modulus, $this->publicExponent, $options);
	}

	public function asPrivateKey()
	{
		$new = new PrivateKey();
		$new->exponent = $this->exponent;
		$new->modulus = $this->modulus;
		$new->k = $this->k;
		$new->format = $this->format;
		return $new
			->withHash($this->hash->getHash())
			->withMGFHash($this->mgfHash->getHash())
			->withSaltLength($this->sLen)
			->withLabel($this->label)
			->withPadding($this->signaturePadding | $this->encryptionPadding);
	}
}
}

namespace phpseclib3\Crypt {

class TripleDES extends DES
{

	const MODE_3CBC = -2;

	const MODE_CBC3 = self::MODE_CBC;

	protected $key_length = 24;

	protected $cipher_name_mcrypt = 'tripledes';

	protected $cfb_init_len = 750;

	protected $key_length_max = 24;

	private $mode_3cbc;

	private $des;

	public function __construct($mode)
	{
		switch (strtolower($mode)) {

			case '3cbc':
				parent::__construct('cbc');
				$this->mode_3cbc = true;

				$this->des = [
					new DES('cbc'),
					new DES('cbc'),
					new DES('cbc'),
				];

				$this->des[0]->disablePadding();
				$this->des[1]->disablePadding();
				$this->des[2]->disablePadding();
				break;
			case 'cbc3':
				$mode = 'cbc';

			default:
				parent::__construct($mode);

				if ($this->mode == self::MODE_STREAM) {
					throw new BadModeException('Block ciphers cannot be ran in stream mode');
				}
		}
	}

	protected function isValidEngineHelper($engine)
	{
		if ($engine == self::ENGINE_OPENSSL) {
			$this->cipher_name_openssl_ecb = 'des-ede3';
			$mode = $this->openssl_translate_mode();
			$this->cipher_name_openssl = $mode == 'ecb' ? 'des-ede3' : 'des-ede3-' . $mode;
		}

		return parent::isValidEngineHelper($engine);
	}

	public function setIV($iv)
	{
		parent::setIV($iv);
		if ($this->mode_3cbc) {
			$this->des[0]->setIV($iv);
			$this->des[1]->setIV($iv);
			$this->des[2]->setIV($iv);
		}
	}

	public function setKeyLength($length)
	{
		switch ($length) {
			case 128:
			case 192:
				break;
			default:
				throw new \LengthException('Key size of ' . $length . ' bits is not supported by this algorithm. Only keys of sizes 128 or 192 bits are supported');
		}

		parent::setKeyLength($length);
	}

	public function setKey($key)
	{
		if ($this->explicit_key_length !== false && strlen($key) != $this->explicit_key_length) {
			throw new \LengthException('Key length has already been set to ' . $this->explicit_key_length . ' bytes and this key is ' . strlen($key) . ' bytes');
		}

		switch (strlen($key)) {
			case 16:
				$key .= substr($key, 0, 8);
				break;
			case 24:
				break;
			default:
				throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16 or 24 are supported');
		}

		$this->key = $key;
		$this->key_length = strlen($key);
		$this->changed = $this->nonIVChanged = true;
		$this->setEngine();

		if ($this->mode_3cbc) {
			$this->des[0]->setKey(substr($key, 0, 8));
			$this->des[1]->setKey(substr($key, 8, 8));
			$this->des[2]->setKey(substr($key, 16, 8));
		}
	}

	public function encrypt($plaintext)
	{

		if ($this->mode_3cbc && strlen($this->key) > 8) {
			return $this->des[2]->encrypt(
				$this->des[1]->decrypt(
					$this->des[0]->encrypt(
						$this->pad($plaintext)
					)
				)
			);
		}

		return parent::encrypt($plaintext);
	}

	public function decrypt($ciphertext)
	{
		if ($this->mode_3cbc && strlen($this->key) > 8) {
			return $this->unpad(
				$this->des[0]->decrypt(
					$this->des[1]->encrypt(
						$this->des[2]->decrypt(
							str_pad($ciphertext, (strlen($ciphertext) + 7) & 0xFFFFFFF8, "\0")
						)
					)
				)
			);
		}

		return parent::decrypt($ciphertext);
	}

	public function enableContinuousBuffer()
	{
		parent::enableContinuousBuffer();
		if ($this->mode_3cbc) {
			$this->des[0]->enableContinuousBuffer();
			$this->des[1]->enableContinuousBuffer();
			$this->des[2]->enableContinuousBuffer();
		}
	}

	public function disableContinuousBuffer()
	{
		parent::disableContinuousBuffer();
		if ($this->mode_3cbc) {
			$this->des[0]->disableContinuousBuffer();
			$this->des[1]->disableContinuousBuffer();
			$this->des[2]->disableContinuousBuffer();
		}
	}

	protected function setupKey()
	{
		switch (true) {

			case strlen($this->key) <= 8:
				$this->des_rounds = 1;
				break;

			default:
				$this->des_rounds = 3;

				if ($this->mode_3cbc) {
					$this->des[0]->setupKey();
					$this->des[1]->setupKey();
					$this->des[2]->setupKey();

					return;
				}
		}

		parent::setupKey();
	}

	public function setPreferredEngine($engine)
	{
		if ($this->mode_3cbc) {
			$this->des[0]->setPreferredEngine($engine);
			$this->des[1]->setPreferredEngine($engine);
			$this->des[2]->setPreferredEngine($engine);
		}

		parent::setPreferredEngine($engine);
	}
}
}

namespace phpseclib3\Crypt {

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadModeException;

class Twofish extends BlockCipher
{

	protected $cipher_name_mcrypt = 'twofish';

	protected $cfb_init_len = 800;

	private static $q0 = [
		0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76,
		0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
		0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C,
		0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
		0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23,
		0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
		0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C,
		0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
		0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B,
		0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
		0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66,
		0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
		0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA,
		0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
		0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8,
		0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
		0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2,
		0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
		0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB,
		0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
		0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B,
		0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
		0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A,
		0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
		0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02,
		0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
		0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72,
		0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
		0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8,
		0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
		0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00,
		0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
	];

	private static $q1 = [
		0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8,
		0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
		0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1,
		0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
		0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D,
		0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
		0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3,
		0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
		0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96,
		0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
		0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70,
		0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
		0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC,
		0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
		0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9,
		0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
		0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3,
		0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
		0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49,
		0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
		0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01,
		0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
		0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19,
		0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
		0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5,
		0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
		0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E,
		0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
		0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB,
		0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
		0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2,
		0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
	];

	private static $m0 = [
		0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4, 0xDADA03DB, 0x02028B7B, 0xE2E22BFB, 0x9E9EFAC8,
		0xC9C9EC4A, 0xD4D409D3, 0x18186BE6, 0x1E1E9F6B, 0x98980E45, 0xB2B2387D, 0xA6A6D2E8, 0x2626B74B,
		0x3C3C57D6, 0x93938A32, 0x8282EED8, 0x525298FD, 0x7B7BD437, 0xBBBB3771, 0x5B5B97F1, 0x474783E1,
		0x24243C30, 0x5151E20F, 0xBABAC6F8, 0x4A4AF31B, 0xBFBF4887, 0x0D0D70FA, 0xB0B0B306, 0x7575DE3F,
		0xD2D2FD5E, 0x7D7D20BA, 0x666631AE, 0x3A3AA35B, 0x59591C8A, 0x00000000, 0xCDCD93BC, 0x1A1AE09D,
		0xAEAE2C6D, 0x7F7FABC1, 0x2B2BC7B1, 0xBEBEB90E, 0xE0E0A080, 0x8A8A105D, 0x3B3B52D2, 0x6464BAD5,
		0xD8D888A0, 0xE7E7A584, 0x5F5FE807, 0x1B1B1114, 0x2C2CC2B5, 0xFCFCB490, 0x3131272C, 0x808065A3,
		0x73732AB2, 0x0C0C8173, 0x79795F4C, 0x6B6B4154, 0x4B4B0292, 0x53536974, 0x94948F36, 0x83831F51,
		0x2A2A3638, 0xC4C49CB0, 0x2222C8BD, 0xD5D5F85A, 0xBDBDC3FC, 0x48487860, 0xFFFFCE62, 0x4C4C0796,
		0x4141776C, 0xC7C7E642, 0xEBEB24F7, 0x1C1C1410, 0x5D5D637C, 0x36362228, 0x6767C027, 0xE9E9AF8C,
		0x4444F913, 0x1414EA95, 0xF5F5BB9C, 0xCFCF18C7, 0x3F3F2D24, 0xC0C0E346, 0x7272DB3B, 0x54546C70,
		0x29294CCA, 0xF0F035E3, 0x0808FE85, 0xC6C617CB, 0xF3F34F11, 0x8C8CE4D0, 0xA4A45993, 0xCACA96B8,
		0x68683BA6, 0xB8B84D83, 0x38382820, 0xE5E52EFF, 0xADAD569F, 0x0B0B8477, 0xC8C81DC3, 0x9999FFCC,
		0x5858ED03, 0x19199A6F, 0x0E0E0A08, 0x95957EBF, 0x70705040, 0xF7F730E7, 0x6E6ECF2B, 0x1F1F6EE2,
		0xB5B53D79, 0x09090F0C, 0x616134AA, 0x57571682, 0x9F9F0B41, 0x9D9D803A, 0x111164EA, 0x2525CDB9,
		0xAFAFDDE4, 0x4545089A, 0xDFDF8DA4, 0xA3A35C97, 0xEAEAD57E, 0x353558DA, 0xEDEDD07A, 0x4343FC17,
		0xF8F8CB66, 0xFBFBB194, 0x3737D3A1, 0xFAFA401D, 0xC2C2683D, 0xB4B4CCF0, 0x32325DDE, 0x9C9C71B3,
		0x5656E70B, 0xE3E3DA72, 0x878760A7, 0x15151B1C, 0xF9F93AEF, 0x6363BFD1, 0x3434A953, 0x9A9A853E,
		0xB1B1428F, 0x7C7CD133, 0x88889B26, 0x3D3DA65F, 0xA1A1D7EC, 0xE4E4DF76, 0x8181942A, 0x91910149,
		0x0F0FFB81, 0xEEEEAA88, 0x161661EE, 0xD7D77321, 0x9797F5C4, 0xA5A5A81A, 0xFEFE3FEB, 0x6D6DB5D9,
		0x7878AEC5, 0xC5C56D39, 0x1D1DE599, 0x7676A4CD, 0x3E3EDCAD, 0xCBCB6731, 0xB6B6478B, 0xEFEF5B01,
		0x12121E18, 0x6060C523, 0x6A6AB0DD, 0x4D4DF61F, 0xCECEE94E, 0xDEDE7C2D, 0x55559DF9, 0x7E7E5A48,
		0x2121B24F, 0x03037AF2, 0xA0A02665, 0x5E5E198E, 0x5A5A6678, 0x65654B5C, 0x62624E58, 0xFDFD4519,
		0x0606F48D, 0x404086E5, 0xF2F2BE98, 0x3333AC57, 0x17179067, 0x05058E7F, 0xE8E85E05, 0x4F4F7D64,
		0x89896AAF, 0x10109563, 0x74742FB6, 0x0A0A75FE, 0x5C5C92F5, 0x9B9B74B7, 0x2D2D333C, 0x3030D6A5,
		0x2E2E49CE, 0x494989E9, 0x46467268, 0x77775544, 0xA8A8D8E0, 0x9696044D, 0x2828BD43, 0xA9A92969,
		0xD9D97929, 0x8686912E, 0xD1D187AC, 0xF4F44A15, 0x8D8D1559, 0xD6D682A8, 0xB9B9BC0A, 0x42420D9E,
		0xF6F6C16E, 0x2F2FB847, 0xDDDD06DF, 0x23233934, 0xCCCC6235, 0xF1F1C46A, 0xC1C112CF, 0x8585EBDC,
		0x8F8F9E22, 0x7171A1C9, 0x9090F0C0, 0xAAAA539B, 0x0101F189, 0x8B8BE1D4, 0x4E4E8CED, 0x8E8E6FAB,
		0xABABA212, 0x6F6F3EA2, 0xE6E6540D, 0xDBDBF252, 0x92927BBB, 0xB7B7B602, 0x6969CA2F, 0x3939D9A9,
		0xD3D30CD7, 0xA7A72361, 0xA2A2AD1E, 0xC3C399B4, 0x6C6C4450, 0x07070504, 0x04047FF6, 0x272746C2,
		0xACACA716, 0xD0D07625, 0x50501386, 0xDCDCF756, 0x84841A55, 0xE1E15109, 0x7A7A25BE, 0x1313EF91
	];

	private static $m1 = [
		0xA9D93939, 0x67901717, 0xB3719C9C, 0xE8D2A6A6, 0x04050707, 0xFD985252, 0xA3658080, 0x76DFE4E4,
		0x9A084545, 0x92024B4B, 0x80A0E0E0, 0x78665A5A, 0xE4DDAFAF, 0xDDB06A6A, 0xD1BF6363, 0x38362A2A,
		0x0D54E6E6, 0xC6432020, 0x3562CCCC, 0x98BEF2F2, 0x181E1212, 0xF724EBEB, 0xECD7A1A1, 0x6C774141,
		0x43BD2828, 0x7532BCBC, 0x37D47B7B, 0x269B8888, 0xFA700D0D, 0x13F94444, 0x94B1FBFB, 0x485A7E7E,
		0xF27A0303, 0xD0E48C8C, 0x8B47B6B6, 0x303C2424, 0x84A5E7E7, 0x54416B6B, 0xDF06DDDD, 0x23C56060,
		0x1945FDFD, 0x5BA33A3A, 0x3D68C2C2, 0x59158D8D, 0xF321ECEC, 0xAE316666, 0xA23E6F6F, 0x82165757,
		0x63951010, 0x015BEFEF, 0x834DB8B8, 0x2E918686, 0xD9B56D6D, 0x511F8383, 0x9B53AAAA, 0x7C635D5D,
		0xA63B6868, 0xEB3FFEFE, 0xA5D63030, 0xBE257A7A, 0x16A7ACAC, 0x0C0F0909, 0xE335F0F0, 0x6123A7A7,
		0xC0F09090, 0x8CAFE9E9, 0x3A809D9D, 0xF5925C5C, 0x73810C0C, 0x2C273131, 0x2576D0D0, 0x0BE75656,
		0xBB7B9292, 0x4EE9CECE, 0x89F10101, 0x6B9F1E1E, 0x53A93434, 0x6AC4F1F1, 0xB499C3C3, 0xF1975B5B,
		0xE1834747, 0xE66B1818, 0xBDC82222, 0x450E9898, 0xE26E1F1F, 0xF4C9B3B3, 0xB62F7474, 0x66CBF8F8,
		0xCCFF9999, 0x95EA1414, 0x03ED5858, 0x56F7DCDC, 0xD4E18B8B, 0x1C1B1515, 0x1EADA2A2, 0xD70CD3D3,
		0xFB2BE2E2, 0xC31DC8C8, 0x8E195E5E, 0xB5C22C2C, 0xE9894949, 0xCF12C1C1, 0xBF7E9595, 0xBA207D7D,
		0xEA641111, 0x77840B0B, 0x396DC5C5, 0xAF6A8989, 0x33D17C7C, 0xC9A17171, 0x62CEFFFF, 0x7137BBBB,
		0x81FB0F0F, 0x793DB5B5, 0x0951E1E1, 0xADDC3E3E, 0x242D3F3F, 0xCDA47676, 0xF99D5555, 0xD8EE8282,
		0xE5864040, 0xC5AE7878, 0xB9CD2525, 0x4D049696, 0x44557777, 0x080A0E0E, 0x86135050, 0xE730F7F7,
		0xA1D33737, 0x1D40FAFA, 0xAA346161, 0xED8C4E4E, 0x06B3B0B0, 0x706C5454, 0xB22A7373, 0xD2523B3B,
		0x410B9F9F, 0x7B8B0202, 0xA088D8D8, 0x114FF3F3, 0x3167CBCB, 0xC2462727, 0x27C06767, 0x90B4FCFC,
		0x20283838, 0xF67F0404, 0x60784848, 0xFF2EE5E5, 0x96074C4C, 0x5C4B6565, 0xB1C72B2B, 0xAB6F8E8E,
		0x9E0D4242, 0x9CBBF5F5, 0x52F2DBDB, 0x1BF34A4A, 0x5FA63D3D, 0x9359A4A4, 0x0ABCB9B9, 0xEF3AF9F9,
		0x91EF1313, 0x85FE0808, 0x49019191, 0xEE611616, 0x2D7CDEDE, 0x4FB22121, 0x8F42B1B1, 0x3BDB7272,
		0x47B82F2F, 0x8748BFBF, 0x6D2CAEAE, 0x46E3C0C0, 0xD6573C3C, 0x3E859A9A, 0x6929A9A9, 0x647D4F4F,
		0x2A948181, 0xCE492E2E, 0xCB17C6C6, 0x2FCA6969, 0xFCC3BDBD, 0x975CA3A3, 0x055EE8E8, 0x7AD0EDED,
		0xAC87D1D1, 0x7F8E0505, 0xD5BA6464, 0x1AA8A5A5, 0x4BB72626, 0x0EB9BEBE, 0xA7608787, 0x5AF8D5D5,
		0x28223636, 0x14111B1B, 0x3FDE7575, 0x2979D9D9, 0x88AAEEEE, 0x3C332D2D, 0x4C5F7979, 0x02B6B7B7,
		0xB896CACA, 0xDA583535, 0xB09CC4C4, 0x17FC4343, 0x551A8484, 0x1FF64D4D, 0x8A1C5959, 0x7D38B2B2,
		0x57AC3333, 0xC718CFCF, 0x8DF40606, 0x74695353, 0xB7749B9B, 0xC4F59797, 0x9F56ADAD, 0x72DAE3E3,
		0x7ED5EAEA, 0x154AF4F4, 0x229E8F8F, 0x12A2ABAB, 0x584E6262, 0x07E85F5F, 0x99E51D1D, 0x34392323,
		0x6EC1F6F6, 0x50446C6C, 0xDE5D3232, 0x68724646, 0x6526A0A0, 0xBC93CDCD, 0xDB03DADA, 0xF8C6BABA,
		0xC8FA9E9E, 0xA882D6D6, 0x2BCF6E6E, 0x40507070, 0xDCEB8585, 0xFE750A0A, 0x328A9393, 0xA48DDFDF,
		0xCA4C2929, 0x10141C1C, 0x2173D7D7, 0xF0CCB4B4, 0xD309D4D4, 0x5D108A8A, 0x0FE25151, 0x00000000,
		0x6F9A1919, 0x9DE01A1A, 0x368F9494, 0x42E6C7C7, 0x4AECC9C9, 0x5EFDD2D2, 0xC1AB7F7F, 0xE0D8A8A8
	];

	private static $m2 = [
		0xBC75BC32, 0xECF3EC21, 0x20C62043, 0xB3F4B3C9, 0xDADBDA03, 0x027B028B, 0xE2FBE22B, 0x9EC89EFA,
		0xC94AC9EC, 0xD4D3D409, 0x18E6186B, 0x1E6B1E9F, 0x9845980E, 0xB27DB238, 0xA6E8A6D2, 0x264B26B7,
		0x3CD63C57, 0x9332938A, 0x82D882EE, 0x52FD5298, 0x7B377BD4, 0xBB71BB37, 0x5BF15B97, 0x47E14783,
		0x2430243C, 0x510F51E2, 0xBAF8BAC6, 0x4A1B4AF3, 0xBF87BF48, 0x0DFA0D70, 0xB006B0B3, 0x753F75DE,
		0xD25ED2FD, 0x7DBA7D20, 0x66AE6631, 0x3A5B3AA3, 0x598A591C, 0x00000000, 0xCDBCCD93, 0x1A9D1AE0,
		0xAE6DAE2C, 0x7FC17FAB, 0x2BB12BC7, 0xBE0EBEB9, 0xE080E0A0, 0x8A5D8A10, 0x3BD23B52, 0x64D564BA,
		0xD8A0D888, 0xE784E7A5, 0x5F075FE8, 0x1B141B11, 0x2CB52CC2, 0xFC90FCB4, 0x312C3127, 0x80A38065,
		0x73B2732A, 0x0C730C81, 0x794C795F, 0x6B546B41, 0x4B924B02, 0x53745369, 0x9436948F, 0x8351831F,
		0x2A382A36, 0xC4B0C49C, 0x22BD22C8, 0xD55AD5F8, 0xBDFCBDC3, 0x48604878, 0xFF62FFCE, 0x4C964C07,
		0x416C4177, 0xC742C7E6, 0xEBF7EB24, 0x1C101C14, 0x5D7C5D63, 0x36283622, 0x672767C0, 0xE98CE9AF,
		0x441344F9, 0x149514EA, 0xF59CF5BB, 0xCFC7CF18, 0x3F243F2D, 0xC046C0E3, 0x723B72DB, 0x5470546C,
		0x29CA294C, 0xF0E3F035, 0x088508FE, 0xC6CBC617, 0xF311F34F, 0x8CD08CE4, 0xA493A459, 0xCAB8CA96,
		0x68A6683B, 0xB883B84D, 0x38203828, 0xE5FFE52E, 0xAD9FAD56, 0x0B770B84, 0xC8C3C81D, 0x99CC99FF,
		0x580358ED, 0x196F199A, 0x0E080E0A, 0x95BF957E, 0x70407050, 0xF7E7F730, 0x6E2B6ECF, 0x1FE21F6E,
		0xB579B53D, 0x090C090F, 0x61AA6134, 0x57825716, 0x9F419F0B, 0x9D3A9D80, 0x11EA1164, 0x25B925CD,
		0xAFE4AFDD, 0x459A4508, 0xDFA4DF8D, 0xA397A35C, 0xEA7EEAD5, 0x35DA3558, 0xED7AEDD0, 0x431743FC,
		0xF866F8CB, 0xFB94FBB1, 0x37A137D3, 0xFA1DFA40, 0xC23DC268, 0xB4F0B4CC, 0x32DE325D, 0x9CB39C71,
		0x560B56E7, 0xE372E3DA, 0x87A78760, 0x151C151B, 0xF9EFF93A, 0x63D163BF, 0x345334A9, 0x9A3E9A85,
		0xB18FB142, 0x7C337CD1, 0x8826889B, 0x3D5F3DA6, 0xA1ECA1D7, 0xE476E4DF, 0x812A8194, 0x91499101,
		0x0F810FFB, 0xEE88EEAA, 0x16EE1661, 0xD721D773, 0x97C497F5, 0xA51AA5A8, 0xFEEBFE3F, 0x6DD96DB5,
		0x78C578AE, 0xC539C56D, 0x1D991DE5, 0x76CD76A4, 0x3EAD3EDC, 0xCB31CB67, 0xB68BB647, 0xEF01EF5B,
		0x1218121E, 0x602360C5, 0x6ADD6AB0, 0x4D1F4DF6, 0xCE4ECEE9, 0xDE2DDE7C, 0x55F9559D, 0x7E487E5A,
		0x214F21B2, 0x03F2037A, 0xA065A026, 0x5E8E5E19, 0x5A785A66, 0x655C654B, 0x6258624E, 0xFD19FD45,
		0x068D06F4, 0x40E54086, 0xF298F2BE, 0x335733AC, 0x17671790, 0x057F058E, 0xE805E85E, 0x4F644F7D,
		0x89AF896A, 0x10631095, 0x74B6742F, 0x0AFE0A75, 0x5CF55C92, 0x9BB79B74, 0x2D3C2D33, 0x30A530D6,
		0x2ECE2E49, 0x49E94989, 0x46684672, 0x77447755, 0xA8E0A8D8, 0x964D9604, 0x284328BD, 0xA969A929,
		0xD929D979, 0x862E8691, 0xD1ACD187, 0xF415F44A, 0x8D598D15, 0xD6A8D682, 0xB90AB9BC, 0x429E420D,
		0xF66EF6C1, 0x2F472FB8, 0xDDDFDD06, 0x23342339, 0xCC35CC62, 0xF16AF1C4, 0xC1CFC112, 0x85DC85EB,
		0x8F228F9E, 0x71C971A1, 0x90C090F0, 0xAA9BAA53, 0x018901F1, 0x8BD48BE1, 0x4EED4E8C, 0x8EAB8E6F,
		0xAB12ABA2, 0x6FA26F3E, 0xE60DE654, 0xDB52DBF2, 0x92BB927B, 0xB702B7B6, 0x692F69CA, 0x39A939D9,
		0xD3D7D30C, 0xA761A723, 0xA21EA2AD, 0xC3B4C399, 0x6C506C44, 0x07040705, 0x04F6047F, 0x27C22746,
		0xAC16ACA7, 0xD025D076, 0x50865013, 0xDC56DCF7, 0x8455841A, 0xE109E151, 0x7ABE7A25, 0x139113EF
	];

	private static $m3 = [
		0xD939A9D9, 0x90176790, 0x719CB371, 0xD2A6E8D2, 0x05070405, 0x9852FD98, 0x6580A365, 0xDFE476DF,
		0x08459A08, 0x024B9202, 0xA0E080A0, 0x665A7866, 0xDDAFE4DD, 0xB06ADDB0, 0xBF63D1BF, 0x362A3836,
		0x54E60D54, 0x4320C643, 0x62CC3562, 0xBEF298BE, 0x1E12181E, 0x24EBF724, 0xD7A1ECD7, 0x77416C77,
		0xBD2843BD, 0x32BC7532, 0xD47B37D4, 0x9B88269B, 0x700DFA70, 0xF94413F9, 0xB1FB94B1, 0x5A7E485A,
		0x7A03F27A, 0xE48CD0E4, 0x47B68B47, 0x3C24303C, 0xA5E784A5, 0x416B5441, 0x06DDDF06, 0xC56023C5,
		0x45FD1945, 0xA33A5BA3, 0x68C23D68, 0x158D5915, 0x21ECF321, 0x3166AE31, 0x3E6FA23E, 0x16578216,
		0x95106395, 0x5BEF015B, 0x4DB8834D, 0x91862E91, 0xB56DD9B5, 0x1F83511F, 0x53AA9B53, 0x635D7C63,
		0x3B68A63B, 0x3FFEEB3F, 0xD630A5D6, 0x257ABE25, 0xA7AC16A7, 0x0F090C0F, 0x35F0E335, 0x23A76123,
		0xF090C0F0, 0xAFE98CAF, 0x809D3A80, 0x925CF592, 0x810C7381, 0x27312C27, 0x76D02576, 0xE7560BE7,
		0x7B92BB7B, 0xE9CE4EE9, 0xF10189F1, 0x9F1E6B9F, 0xA93453A9, 0xC4F16AC4, 0x99C3B499, 0x975BF197,
		0x8347E183, 0x6B18E66B, 0xC822BDC8, 0x0E98450E, 0x6E1FE26E, 0xC9B3F4C9, 0x2F74B62F, 0xCBF866CB,
		0xFF99CCFF, 0xEA1495EA, 0xED5803ED, 0xF7DC56F7, 0xE18BD4E1, 0x1B151C1B, 0xADA21EAD, 0x0CD3D70C,
		0x2BE2FB2B, 0x1DC8C31D, 0x195E8E19, 0xC22CB5C2, 0x8949E989, 0x12C1CF12, 0x7E95BF7E, 0x207DBA20,
		0x6411EA64, 0x840B7784, 0x6DC5396D, 0x6A89AF6A, 0xD17C33D1, 0xA171C9A1, 0xCEFF62CE, 0x37BB7137,
		0xFB0F81FB, 0x3DB5793D, 0x51E10951, 0xDC3EADDC, 0x2D3F242D, 0xA476CDA4, 0x9D55F99D, 0xEE82D8EE,
		0x8640E586, 0xAE78C5AE, 0xCD25B9CD, 0x04964D04, 0x55774455, 0x0A0E080A, 0x13508613, 0x30F7E730,
		0xD337A1D3, 0x40FA1D40, 0x3461AA34, 0x8C4EED8C, 0xB3B006B3, 0x6C54706C, 0x2A73B22A, 0x523BD252,
		0x0B9F410B, 0x8B027B8B, 0x88D8A088, 0x4FF3114F, 0x67CB3167, 0x4627C246, 0xC06727C0, 0xB4FC90B4,
		0x28382028, 0x7F04F67F, 0x78486078, 0x2EE5FF2E, 0x074C9607, 0x4B655C4B, 0xC72BB1C7, 0x6F8EAB6F,
		0x0D429E0D, 0xBBF59CBB, 0xF2DB52F2, 0xF34A1BF3, 0xA63D5FA6, 0x59A49359, 0xBCB90ABC, 0x3AF9EF3A,
		0xEF1391EF, 0xFE0885FE, 0x01914901, 0x6116EE61, 0x7CDE2D7C, 0xB2214FB2, 0x42B18F42, 0xDB723BDB,
		0xB82F47B8, 0x48BF8748, 0x2CAE6D2C, 0xE3C046E3, 0x573CD657, 0x859A3E85, 0x29A96929, 0x7D4F647D,
		0x94812A94, 0x492ECE49, 0x17C6CB17, 0xCA692FCA, 0xC3BDFCC3, 0x5CA3975C, 0x5EE8055E, 0xD0ED7AD0,
		0x87D1AC87, 0x8E057F8E, 0xBA64D5BA, 0xA8A51AA8, 0xB7264BB7, 0xB9BE0EB9, 0x6087A760, 0xF8D55AF8,
		0x22362822, 0x111B1411, 0xDE753FDE, 0x79D92979, 0xAAEE88AA, 0x332D3C33, 0x5F794C5F, 0xB6B702B6,
		0x96CAB896, 0x5835DA58, 0x9CC4B09C, 0xFC4317FC, 0x1A84551A, 0xF64D1FF6, 0x1C598A1C, 0x38B27D38,
		0xAC3357AC, 0x18CFC718, 0xF4068DF4, 0x69537469, 0x749BB774, 0xF597C4F5, 0x56AD9F56, 0xDAE372DA,
		0xD5EA7ED5, 0x4AF4154A, 0x9E8F229E, 0xA2AB12A2, 0x4E62584E, 0xE85F07E8, 0xE51D99E5, 0x39233439,
		0xC1F66EC1, 0x446C5044, 0x5D32DE5D, 0x72466872, 0x26A06526, 0x93CDBC93, 0x03DADB03, 0xC6BAF8C6,
		0xFA9EC8FA, 0x82D6A882, 0xCF6E2BCF, 0x50704050, 0xEB85DCEB, 0x750AFE75, 0x8A93328A, 0x8DDFA48D,
		0x4C29CA4C, 0x141C1014, 0x73D72173, 0xCCB4F0CC, 0x09D4D309, 0x108A5D10, 0xE2510FE2, 0x00000000,
		0x9A196F9A, 0xE01A9DE0, 0x8F94368F, 0xE6C742E6, 0xECC94AEC, 0xFDD25EFD, 0xAB7FC1AB, 0xD8A8E0D8
	];

	private $K = [];

	private $S0 = [];

	private $S1 = [];

	private $S2 = [];

	private $S3 = [];

	private $kl;

	protected $key_length = 16;

	public function __construct($mode)
	{
		parent::__construct($mode);

		if ($this->mode == self::MODE_STREAM) {
			throw new BadModeException('Block ciphers cannot be ran in stream mode');
		}
	}

	protected static function initialize_static_variables()
	{
		if (is_float(self::$m3[0])) {
			self::$m0 = array_map('intval', self::$m0);
			self::$m1 = array_map('intval', self::$m1);
			self::$m2 = array_map('intval', self::$m2);
			self::$m3 = array_map('intval', self::$m3);
			self::$q0 = array_map('intval', self::$q0);
			self::$q1 = array_map('intval', self::$q1);
		}

		parent::initialize_static_variables();
	}

	public function setKeyLength($length)
	{
		switch ($length) {
			case 128:
			case 192:
			case 256:
				break;
			default:
				throw new \LengthException('Key of size ' . $length . ' not supported by this algorithm. Only keys of sizes 16, 24 or 32 supported');
		}

		parent::setKeyLength($length);
	}

	public function setKey($key)
	{
		switch (strlen($key)) {
			case 16:
			case 24:
			case 32:
				break;
			default:
				throw new \LengthException('Key of size ' . strlen($key) . ' not supported by this algorithm. Only keys of sizes 16, 24 or 32 supported');
		}

		parent::setKey($key);
	}

	protected function setupKey()
	{
		if (isset($this->kl['key']) && $this->key === $this->kl['key']) {

			return;
		}
		$this->kl = ['key' => $this->key];

		$le_longs = unpack('V*', $this->key);
		$key = unpack('C*', $this->key);
		$m0 = self::$m0;
		$m1 = self::$m1;
		$m2 = self::$m2;
		$m3 = self::$m3;
		$q0 = self::$q0;
		$q1 = self::$q1;

		$K = $S0 = $S1 = $S2 = $S3 = [];

		switch (strlen($this->key)) {
			case 16:
				list($s7, $s6, $s5, $s4) = $this->mdsrem($le_longs[1], $le_longs[2]);
				list($s3, $s2, $s1, $s0) = $this->mdsrem($le_longs[3], $le_longs[4]);
				for ($i = 0, $j = 1; $i < 40; $i += 2, $j += 2) {
					$A = $m0[$q0[$q0[$i] ^ $key[ 9]] ^ $key[1]] ^
						 $m1[$q0[$q1[$i] ^ $key[10]] ^ $key[2]] ^
						 $m2[$q1[$q0[$i] ^ $key[11]] ^ $key[3]] ^
						 $m3[$q1[$q1[$i] ^ $key[12]] ^ $key[4]];
					$B = $m0[$q0[$q0[$j] ^ $key[13]] ^ $key[5]] ^
						 $m1[$q0[$q1[$j] ^ $key[14]] ^ $key[6]] ^
						 $m2[$q1[$q0[$j] ^ $key[15]] ^ $key[7]] ^
						 $m3[$q1[$q1[$j] ^ $key[16]] ^ $key[8]];
					$B = ($B << 8) | ($B >> 24 & 0xff);
					$A = self::safe_intval($A + $B);
					$K[] = $A;
					$A = self::safe_intval($A + $B);
					$K[] = ($A << 9 | $A >> 23 & 0x1ff);
				}
				for ($i = 0; $i < 256; ++$i) {
					$S0[$i] = $m0[$q0[$q0[$i] ^ $s4] ^ $s0];
					$S1[$i] = $m1[$q0[$q1[$i] ^ $s5] ^ $s1];
					$S2[$i] = $m2[$q1[$q0[$i] ^ $s6] ^ $s2];
					$S3[$i] = $m3[$q1[$q1[$i] ^ $s7] ^ $s3];
				}
				break;
			case 24:
				list($sb, $sa, $s9, $s8) = $this->mdsrem($le_longs[1], $le_longs[2]);
				list($s7, $s6, $s5, $s4) = $this->mdsrem($le_longs[3], $le_longs[4]);
				list($s3, $s2, $s1, $s0) = $this->mdsrem($le_longs[5], $le_longs[6]);
				for ($i = 0, $j = 1; $i < 40; $i += 2, $j += 2) {
					$A = $m0[$q0[$q0[$q1[$i] ^ $key[17]] ^ $key[ 9]] ^ $key[1]] ^
						 $m1[$q0[$q1[$q1[$i] ^ $key[18]] ^ $key[10]] ^ $key[2]] ^
						 $m2[$q1[$q0[$q0[$i] ^ $key[19]] ^ $key[11]] ^ $key[3]] ^
						 $m3[$q1[$q1[$q0[$i] ^ $key[20]] ^ $key[12]] ^ $key[4]];
					$B = $m0[$q0[$q0[$q1[$j] ^ $key[21]] ^ $key[13]] ^ $key[5]] ^
						 $m1[$q0[$q1[$q1[$j] ^ $key[22]] ^ $key[14]] ^ $key[6]] ^
						 $m2[$q1[$q0[$q0[$j] ^ $key[23]] ^ $key[15]] ^ $key[7]] ^
						 $m3[$q1[$q1[$q0[$j] ^ $key[24]] ^ $key[16]] ^ $key[8]];
					$B = ($B << 8) | ($B >> 24 & 0xff);
					$A = self::safe_intval($A + $B);
					$K[] = $A;
					$A = self::safe_intval($A + $B);
					$K[] = ($A << 9 | $A >> 23 & 0x1ff);
				}
				for ($i = 0; $i < 256; ++$i) {
					$S0[$i] = $m0[$q0[$q0[$q1[$i] ^ $s8] ^ $s4] ^ $s0];
					$S1[$i] = $m1[$q0[$q1[$q1[$i] ^ $s9] ^ $s5] ^ $s1];
					$S2[$i] = $m2[$q1[$q0[$q0[$i] ^ $sa] ^ $s6] ^ $s2];
					$S3[$i] = $m3[$q1[$q1[$q0[$i] ^ $sb] ^ $s7] ^ $s3];
				}
				break;
			default:
				list($sf, $se, $sd, $sc) = $this->mdsrem($le_longs[1], $le_longs[2]);
				list($sb, $sa, $s9, $s8) = $this->mdsrem($le_longs[3], $le_longs[4]);
				list($s7, $s6, $s5, $s4) = $this->mdsrem($le_longs[5], $le_longs[6]);
				list($s3, $s2, $s1, $s0) = $this->mdsrem($le_longs[7], $le_longs[8]);
				for ($i = 0, $j = 1; $i < 40; $i += 2, $j += 2) {
					$A = $m0[$q0[$q0[$q1[$q1[$i] ^ $key[25]] ^ $key[17]] ^ $key[ 9]] ^ $key[1]] ^
						 $m1[$q0[$q1[$q1[$q0[$i] ^ $key[26]] ^ $key[18]] ^ $key[10]] ^ $key[2]] ^
						 $m2[$q1[$q0[$q0[$q0[$i] ^ $key[27]] ^ $key[19]] ^ $key[11]] ^ $key[3]] ^
						 $m3[$q1[$q1[$q0[$q1[$i] ^ $key[28]] ^ $key[20]] ^ $key[12]] ^ $key[4]];
					$B = $m0[$q0[$q0[$q1[$q1[$j] ^ $key[29]] ^ $key[21]] ^ $key[13]] ^ $key[5]] ^
						 $m1[$q0[$q1[$q1[$q0[$j] ^ $key[30]] ^ $key[22]] ^ $key[14]] ^ $key[6]] ^
						 $m2[$q1[$q0[$q0[$q0[$j] ^ $key[31]] ^ $key[23]] ^ $key[15]] ^ $key[7]] ^
						 $m3[$q1[$q1[$q0[$q1[$j] ^ $key[32]] ^ $key[24]] ^ $key[16]] ^ $key[8]];
					$B = ($B << 8) | ($B >> 24 & 0xff);
					$A = self::safe_intval($A + $B);
					$K[] = $A;
					$A = self::safe_intval($A + $B);
					$K[] = ($A << 9 | $A >> 23 & 0x1ff);
				}
				for ($i = 0; $i < 256; ++$i) {
					$S0[$i] = $m0[$q0[$q0[$q1[$q1[$i] ^ $sc] ^ $s8] ^ $s4] ^ $s0];
					$S1[$i] = $m1[$q0[$q1[$q1[$q0[$i] ^ $sd] ^ $s9] ^ $s5] ^ $s1];
					$S2[$i] = $m2[$q1[$q0[$q0[$q0[$i] ^ $se] ^ $sa] ^ $s6] ^ $s2];
					$S3[$i] = $m3[$q1[$q1[$q0[$q1[$i] ^ $sf] ^ $sb] ^ $s7] ^ $s3];
				}
		}

		$this->K	= $K;
		$this->S0 = $S0;
		$this->S1 = $S1;
		$this->S2 = $S2;
		$this->S3 = $S3;
	}

	private function mdsrem($A, $B)
	{

		for ($i = 0; $i < 8; ++$i) {

			$t = 0xff & ($B >> 24);

			$B = ($B << 8) | (0xff & ($A >> 24));
			$A <<= 8;

			$u = $t << 1;

			if ($t & 0x80) {
				$u ^= 0x14d;
			}

			$B ^= $t ^ ($u << 16);

			$u ^= 0x7fffffff & ($t >> 1);

			if ($t & 0x01) {
				$u ^= 0xa6 ;
			}

			$B ^= ($u << 24) | ($u << 8);
		}

		return [
			0xff & $B >> 24,
			0xff & $B >> 16,
			0xff & $B >>	8,
			0xff & $B];
	}

	protected function encryptBlock($in)
	{
		$S0 = $this->S0;
		$S1 = $this->S1;
		$S2 = $this->S2;
		$S3 = $this->S3;
		$K	= $this->K;

		$in = unpack("V4", $in);
		$R0 = $K[0] ^ $in[1];
		$R1 = $K[1] ^ $in[2];
		$R2 = $K[2] ^ $in[3];
		$R3 = $K[3] ^ $in[4];

		$ki = 7;
		while ($ki < 39) {
			$t0 = $S0[ $R0		& 0xff] ^
					$S1[($R0 >>	8) & 0xff] ^
					$S2[($R0 >> 16) & 0xff] ^
					$S3[($R0 >> 24) & 0xff];
			$t1 = $S0[($R1 >> 24) & 0xff] ^
					$S1[ $R1		& 0xff] ^
					$S2[($R1 >>	8) & 0xff] ^
					$S3[($R1 >> 16) & 0xff];
			$R2 ^= self::safe_intval($t0 + $t1 + $K[++$ki]);
			$R2 = ($R2 >> 1 & 0x7fffffff) | ($R2 << 31);
			$R3 = ((($R3 >> 31) & 1) | ($R3 << 1)) ^ self::safe_intval($t0 + ($t1 << 1) + $K[++$ki]);

			$t0 = $S0[ $R2		& 0xff] ^
					$S1[($R2 >>	8) & 0xff] ^
					$S2[($R2 >> 16) & 0xff] ^
					$S3[($R2 >> 24) & 0xff];
			$t1 = $S0[($R3 >> 24) & 0xff] ^
					$S1[ $R3		& 0xff] ^
					$S2[($R3 >>	8) & 0xff] ^
					$S3[($R3 >> 16) & 0xff];
			$R0 ^= self::safe_intval($t0 + $t1 + $K[++$ki]);
			$R0 = ($R0 >> 1 & 0x7fffffff) | ($R0 << 31);
			$R1 = ((($R1 >> 31) & 1) | ($R1 << 1)) ^ self::safe_intval($t0 + ($t1 << 1) + $K[++$ki]);
		}

		return pack("V4", $K[4] ^ $R2,
							$K[5] ^ $R3,
							$K[6] ^ $R0,
							$K[7] ^ $R1);

	}

	protected function decryptBlock($in)
	{
		$S0 = $this->S0;
		$S1 = $this->S1;
		$S2 = $this->S2;
		$S3 = $this->S3;
		$K	= $this->K;

		$in = unpack("V4", $in);
		$R0 = $K[4] ^ $in[1];
		$R1 = $K[5] ^ $in[2];
		$R2 = $K[6] ^ $in[3];
		$R3 = $K[7] ^ $in[4];

		$ki = 40;
		while ($ki > 8) {
			$t0 = $S0[$R0		& 0xff] ^
					$S1[$R0 >>	8 & 0xff] ^
					$S2[$R0 >> 16 & 0xff] ^
					$S3[$R0 >> 24 & 0xff];
			$t1 = $S0[$R1 >> 24 & 0xff] ^
					$S1[$R1		& 0xff] ^
					$S2[$R1 >>	8 & 0xff] ^
					$S3[$R1 >> 16 & 0xff];
			$R3 ^= self::safe_intval($t0 + ($t1 << 1) + $K[--$ki]);
			$R3 = $R3 >> 1 & 0x7fffffff | $R3 << 31;
			$R2 = ($R2 >> 31 & 0x1 | $R2 << 1) ^ self::safe_intval($t0 + $t1 + $K[--$ki]);

			$t0 = $S0[$R2		& 0xff] ^
					$S1[$R2 >>	8 & 0xff] ^
					$S2[$R2 >> 16 & 0xff] ^
					$S3[$R2 >> 24 & 0xff];
			$t1 = $S0[$R3 >> 24 & 0xff] ^
					$S1[$R3		& 0xff] ^
					$S2[$R3 >>	8 & 0xff] ^
					$S3[$R3 >> 16 & 0xff];
			$R1 ^= self::safe_intval($t0 + ($t1 << 1) + $K[--$ki]);
			$R1 = $R1 >> 1 & 0x7fffffff | $R1 << 31;
			$R0 = ($R0 >> 31 & 0x1 | $R0 << 1) ^ self::safe_intval($t0 + $t1 + $K[--$ki]);
		}

		return pack("V4", $K[0] ^ $R2,
							$K[1] ^ $R3,
							$K[2] ^ $R0,
							$K[3] ^ $R1);

	}

	protected function setupInlineCrypt()
	{
		$K = $this->K;
		$init_crypt = '
            static $S0, $S1, $S2, $S3;
            if (!$S0) {
                for ($i = 0; $i < 256; ++$i) {
                    $S0[] = (int)$this->S0[$i];
                    $S1[] = (int)$this->S1[$i];
                    $S2[] = (int)$this->S2[$i];
                    $S3[] = (int)$this->S3[$i];
                }
            }
        ';

		$safeint = self::safe_intval_inline();

		$encrypt_block = '
            $in = unpack("V4", $in);
            $R0 = ' . $K[0] . ' ^ $in[1];
            $R1 = ' . $K[1] . ' ^ $in[2];
            $R2 = ' . $K[2] . ' ^ $in[3];
            $R3 = ' . $K[3] . ' ^ $in[4];
        ';
		for ($ki = 7, $i = 0; $i < 8; ++$i) {
			$encrypt_block .= '
                $t0 = $S0[ $R0        & 0xff] ^
                      $S1[($R0 >>  8) & 0xff] ^
                      $S2[($R0 >> 16) & 0xff] ^
                      $S3[($R0 >> 24) & 0xff];
                $t1 = $S0[($R1 >> 24) & 0xff] ^
                      $S1[ $R1        & 0xff] ^
                      $S2[($R1 >>  8) & 0xff] ^
                      $S3[($R1 >> 16) & 0xff];
                    $R2^= ' . sprintf($safeint, '$t0 + $t1 + ' . $K[++$ki]) . ';
                $R2 = ($R2 >> 1 & 0x7fffffff) | ($R2 << 31);
                $R3 = ((($R3 >> 31) & 1) | ($R3 << 1)) ^ ' . sprintf($safeint, '($t0 + ($t1 << 1) + ' . $K[++$ki] . ')') . ';

                $t0 = $S0[ $R2        & 0xff] ^
                      $S1[($R2 >>  8) & 0xff] ^
                      $S2[($R2 >> 16) & 0xff] ^
                      $S3[($R2 >> 24) & 0xff];
                $t1 = $S0[($R3 >> 24) & 0xff] ^
                      $S1[ $R3        & 0xff] ^
                      $S2[($R3 >>  8) & 0xff] ^
                      $S3[($R3 >> 16) & 0xff];
                $R0^= ' . sprintf($safeint, '($t0 + $t1 + ' . $K[++$ki] . ')') . ';
                $R0 = ($R0 >> 1 & 0x7fffffff) | ($R0 << 31);
                $R1 = ((($R1 >> 31) & 1) | ($R1 << 1)) ^ ' . sprintf($safeint, '($t0 + ($t1 << 1) + ' . $K[++$ki] . ')') . ';
            ';
		}
		$encrypt_block .= '
            $in = pack("V4", ' . $K[4] . ' ^ $R2,
                             ' . $K[5] . ' ^ $R3,
                             ' . $K[6] . ' ^ $R0,
                             ' . $K[7] . ' ^ $R1);
        ';

		$decrypt_block = '
            $in = unpack("V4", $in);
            $R0 = ' . $K[4] . ' ^ $in[1];
            $R1 = ' . $K[5] . ' ^ $in[2];
            $R2 = ' . $K[6] . ' ^ $in[3];
            $R3 = ' . $K[7] . ' ^ $in[4];
        ';
		for ($ki = 40, $i = 0; $i < 8; ++$i) {
			$decrypt_block .= '
                $t0 = $S0[$R0       & 0xff] ^
                      $S1[$R0 >>  8 & 0xff] ^
                      $S2[$R0 >> 16 & 0xff] ^
                      $S3[$R0 >> 24 & 0xff];
                $t1 = $S0[$R1 >> 24 & 0xff] ^
                      $S1[$R1       & 0xff] ^
                      $S2[$R1 >>  8 & 0xff] ^
                      $S3[$R1 >> 16 & 0xff];
                $R3^= ' . sprintf($safeint, '$t0 + ($t1 << 1) + ' . $K[--$ki]) . ';
                $R3 = $R3 >> 1 & 0x7fffffff | $R3 << 31;
                $R2 = ($R2 >> 31 & 0x1 | $R2 << 1) ^ ' . sprintf($safeint, '($t0 + $t1 + ' . $K[--$ki] . ')') . ';

                $t0 = $S0[$R2       & 0xff] ^
                      $S1[$R2 >>  8 & 0xff] ^
                      $S2[$R2 >> 16 & 0xff] ^
                      $S3[$R2 >> 24 & 0xff];
                $t1 = $S0[$R3 >> 24 & 0xff] ^
                      $S1[$R3       & 0xff] ^
                      $S2[$R3 >>  8 & 0xff] ^
                      $S3[$R3 >> 16 & 0xff];
                $R1^= ' . sprintf($safeint, '$t0 + ($t1 << 1) + ' . $K[--$ki]) . ';
                $R1 = $R1 >> 1 & 0x7fffffff | $R1 << 31;
                $R0 = ($R0 >> 31 & 0x1 | $R0 << 1) ^ ' . sprintf($safeint, '($t0 + $t1 + ' . $K[--$ki] . ')') . ';
            ';
		}
		$decrypt_block .= '
            $in = pack("V4", ' . $K[0] . ' ^ $R2,
                             ' . $K[1] . ' ^ $R3,
                             ' . $K[2] . ' ^ $R0,
                             ' . $K[3] . ' ^ $R1);
        ';

		$this->inline_crypt = $this->createInlineCryptFunction(
			[
				'init_crypt'	=> $init_crypt,
				'init_encrypt'	=> '',
				'init_decrypt'	=> '',
				'encrypt_block' => $encrypt_block,
				'decrypt_block' => $decrypt_block
			]
		);
	}
}
}

namespace phpseclib3\Exception {

class BadConfigurationException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class BadDecryptionException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class BadModeException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class ConnectionClosedException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class FileNotFoundException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class InconsistentSetupException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class InsufficientSetupException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class InvalidPacketLengthException extends ConnectionClosedException
{
}
}

namespace phpseclib3\Exception {

class NoKeyLoadedException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class NoSupportedAlgorithmsException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class TimeoutException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class UnableToConnectException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class UnsupportedAlgorithmException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class UnsupportedCurveException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class UnsupportedFormatException extends \RuntimeException
{
}
}

namespace phpseclib3\Exception {

class UnsupportedOperationException extends \RuntimeException
{
}
}

namespace phpseclib3\File {

class ANSI
{

	private $max_x;

	private $max_y;

	private $max_history;

	private $history;

	private $history_attrs;

	private $x;

	private $y;

	private $old_x;

	private $old_y;

	private $base_attr_cell;

	private $attr_cell;

	private $attr_row;

	private $screen;

	private $attrs;

	private $ansi;

	private $tokenization;

	public function __construct()
	{
		$attr_cell = new \stdClass();
		$attr_cell->bold = false;
		$attr_cell->underline = false;
		$attr_cell->blink = false;
		$attr_cell->background = 'black';
		$attr_cell->foreground = 'white';
		$attr_cell->reverse = false;
		$this->base_attr_cell = clone $attr_cell;
		$this->attr_cell = clone $attr_cell;

		$this->setHistory(200);
		$this->setDimensions(80, 24);
	}

	public function setDimensions($x, $y)
	{
		$this->max_x = $x - 1;
		$this->max_y = $y - 1;
		$this->x = $this->y = 0;
		$this->history = $this->history_attrs = [];
		$this->attr_row = array_fill(0, $this->max_x + 2, $this->base_attr_cell);
		$this->screen = array_fill(0, $this->max_y + 1, '');
		$this->attrs = array_fill(0, $this->max_y + 1, $this->attr_row);
		$this->ansi = '';
	}

	public function setHistory($history)
	{
		$this->max_history = $history;
	}

	public function loadString($source)
	{
		$this->setDimensions($this->max_x + 1, $this->max_y + 1);
		$this->appendString($source);
	}

	public function appendString($source)
	{
		$this->tokenization = [''];
		for ($i = 0; $i < strlen($source); $i++) {
			if (strlen($this->ansi)) {
				$this->ansi .= $source[$i];
				$chr = ord($source[$i]);

				switch (true) {
					case $this->ansi == "\x1B=":
						$this->ansi = '';
						continue 2;
					case strlen($this->ansi) == 2 && $chr >= 64 && $chr <= 95 && $chr != ord('['):
					case strlen($this->ansi) > 2 && $chr >= 64 && $chr <= 126:
						break;
					default:
						continue 2;
				}
				$this->tokenization[] = $this->ansi;
				$this->tokenization[] = '';

				switch ($this->ansi) {
					case "\x1B[H":
						$this->old_x = $this->x;
						$this->old_y = $this->y;
						$this->x = $this->y = 0;
						break;
					case "\x1B[J":
						$this->history = array_merge($this->history, array_slice(array_splice($this->screen, $this->y + 1), 0, $this->old_y));
						$this->screen = array_merge($this->screen, array_fill($this->y, $this->max_y, ''));

						$this->history_attrs = array_merge($this->history_attrs, array_slice(array_splice($this->attrs, $this->y + 1), 0, $this->old_y));
						$this->attrs = array_merge($this->attrs, array_fill($this->y, $this->max_y, $this->attr_row));

						if (count($this->history) == $this->max_history) {
							array_shift($this->history);
							array_shift($this->history_attrs);
						}

					case "\x1B[K":
						$this->screen[$this->y] = substr($this->screen[$this->y], 0, $this->x);

						array_splice($this->attrs[$this->y], $this->x + 1, $this->max_x - $this->x, array_fill($this->x, $this->max_x - ($this->x - 1), $this->base_attr_cell));
						break;
					case "\x1B[2K":
						$this->screen[$this->y] = str_repeat(' ', $this->x);
						$this->attrs[$this->y] = $this->attr_row;
						break;
					case "\x1B[?1h":
					case "\x1B[?25h":
					case "\x1B(B":
						break;
					case "\x1BE":
						$this->newLine();
						$this->x = 0;
						break;
					default:
						switch (true) {
							case preg_match('#\x1B\[(\d+)B#', $this->ansi, $match):
								$this->old_y = $this->y;
								$this->y += (int) $match[1];
								break;
							case preg_match('#\x1B\[(\d+);(\d+)H#', $this->ansi, $match):
								$this->old_x = $this->x;
								$this->old_y = $this->y;
								$this->x = $match[2] - 1;
								$this->y = (int) $match[1] - 1;
								break;
							case preg_match('#\x1B\[(\d+)C#', $this->ansi, $match):
								$this->old_x = $this->x;
								$this->x += $match[1];
								break;
							case preg_match('#\x1B\[(\d+)D#', $this->ansi, $match):
								$this->old_x = $this->x;
								$this->x -= $match[1];
								if ($this->x < 0) {
									$this->x = 0;
								}
								break;
							case preg_match('#\x1B\[(\d+);(\d+)r#', $this->ansi, $match):
								break;
							case preg_match('#\x1B\[(\d*(?:;\d*)*)m#', $this->ansi, $match):
								$attr_cell = &$this->attr_cell;
								$mods = explode(';', $match[1]);
								foreach ($mods as $mod) {
									switch ($mod) {
										case '':
										case '0':
											$attr_cell = clone $this->base_attr_cell;
											break;
										case '1':
											$attr_cell->bold = true;
											break;
										case '4':
											$attr_cell->underline = true;
											break;
										case '5':
											$attr_cell->blink = true;
											break;
										case '7':
											$attr_cell->reverse = !$attr_cell->reverse;
											$temp = $attr_cell->background;
											$attr_cell->background = $attr_cell->foreground;
											$attr_cell->foreground = $temp;
											break;
										default:

											$front = &$attr_cell->{ $attr_cell->reverse ? 'background' : 'foreground' };

											$back = &$attr_cell->{ $attr_cell->reverse ? 'foreground' : 'background' };
											switch ($mod) {

												case '30': $front = 'black'; break;
												case '31': $front = 'red'; break;
												case '32': $front = 'green'; break;
												case '33': $front = 'yellow'; break;
												case '34': $front = 'blue'; break;
												case '35': $front = 'magenta'; break;
												case '36': $front = 'cyan'; break;
												case '37': $front = 'white'; break;

												case '40': $back = 'black'; break;
												case '41': $back = 'red'; break;
												case '42': $back = 'green'; break;
												case '43': $back = 'yellow'; break;
												case '44': $back = 'blue'; break;
												case '45': $back = 'magenta'; break;
												case '46': $back = 'cyan'; break;
												case '47': $back = 'white'; break;

												default:

													$this->ansi = '';
													break 2;
											}
									}
								}
								break;
							default:

						}
				}
				$this->ansi = '';
				continue;
			}

			$this->tokenization[count($this->tokenization) - 1] .= $source[$i];
			switch ($source[$i]) {
				case "\r":
					$this->x = 0;
					break;
				case "\n":
					$this->newLine();
					break;
				case "\x08":
					if ($this->x) {
						$this->x--;
						$this->attrs[$this->y][$this->x] = clone $this->base_attr_cell;
						$this->screen[$this->y] = substr_replace(
							$this->screen[$this->y],
							$source[$i],
							$this->x,
							1
						);
					}
					break;
				case "\x0F":
					break;
				case "\x1B":
					$this->tokenization[count($this->tokenization) - 1] = substr($this->tokenization[count($this->tokenization) - 1], 0, -1);

					$this->ansi .= "\x1B";
					break;
				default:
					$this->attrs[$this->y][$this->x] = clone $this->attr_cell;
					if ($this->x > strlen($this->screen[$this->y])) {
						$this->screen[$this->y] = str_repeat(' ', $this->x);
					}
					$this->screen[$this->y] = substr_replace(
						$this->screen[$this->y],
						$source[$i],
						$this->x,
						1
					);

					if ($this->x > $this->max_x) {
						$this->x = 0;
						$this->newLine();
					} else {
						$this->x++;
					}
			}
		}
	}

	private function newLine()
	{

		while ($this->y >= $this->max_y) {
			$this->history = array_merge($this->history, [array_shift($this->screen)]);
			$this->screen[] = '';

			$this->history_attrs = array_merge($this->history_attrs, [array_shift($this->attrs)]);
			$this->attrs[] = $this->attr_row;

			if (count($this->history) >= $this->max_history) {
				array_shift($this->history);
				array_shift($this->history_attrs);
			}

			$this->y--;
		}
		$this->y++;
	}

	private function processCoordinate(\stdClass $last_attr, \stdClass $cur_attr, $char)
	{
		$output = '';

		if ($last_attr != $cur_attr) {
			$close = $open = '';
			if ($last_attr->foreground != $cur_attr->foreground) {
				if ($cur_attr->foreground != 'white') {
					$open .= '<span style="color: ' . $cur_attr->foreground . '">';
				}
				if ($last_attr->foreground != 'white') {
					$close = '</span>' . $close;
				}
			}
			if ($last_attr->background != $cur_attr->background) {
				if ($cur_attr->background != 'black') {
					$open .= '<span style="background: ' . $cur_attr->background . '">';
				}
				if ($last_attr->background != 'black') {
					$close = '</span>' . $close;
				}
			}
			if ($last_attr->bold != $cur_attr->bold) {
				if ($cur_attr->bold) {
					$open .= '<b>';
				} else {
					$close = '</b>' . $close;
				}
			}
			if ($last_attr->underline != $cur_attr->underline) {
				if ($cur_attr->underline) {
					$open .= '<u>';
				} else {
					$close = '</u>' . $close;
				}
			}
			if ($last_attr->blink != $cur_attr->blink) {
				if ($cur_attr->blink) {
					$open .= '<blink>';
				} else {
					$close = '</blink>' . $close;
				}
			}
			$output .= $close . $open;
		}

		$output .= htmlspecialchars($char);

		return $output;
	}

	private function getScreenHelper()
	{
		$output = '';
		$last_attr = $this->base_attr_cell;
		for ($i = 0; $i <= $this->max_y; $i++) {
			for ($j = 0; $j <= $this->max_x; $j++) {
				$cur_attr = $this->attrs[$i][$j];
				$output .= $this->processCoordinate($last_attr, $cur_attr, isset($this->screen[$i][$j]) ? $this->screen[$i][$j] : '');
				$last_attr = $this->attrs[$i][$j];
			}
			$output .= "\r\n";
		}
		$output = substr($output, 0, -2);

		$output .= $this->processCoordinate($last_attr, $this->base_attr_cell, '');
		return rtrim($output);
	}

	public function getScreen()
	{
		return '<pre width="' . ($this->max_x + 1) . '" style="color: white; background: black">' . $this->getScreenHelper() . '</pre>';
	}

	public function getHistory()
	{
		$scrollback = '';
		$last_attr = $this->base_attr_cell;
		for ($i = 0; $i < count($this->history); $i++) {
			for ($j = 0; $j <= $this->max_x + 1; $j++) {
				$cur_attr = $this->history_attrs[$i][$j];
				$scrollback .= $this->processCoordinate($last_attr, $cur_attr, isset($this->history[$i][$j]) ? $this->history[$i][$j] : '');
				$last_attr = $this->history_attrs[$i][$j];
			}
			$scrollback .= "\r\n";
		}
		$base_attr_cell = $this->base_attr_cell;
		$this->base_attr_cell = $last_attr;
		$scrollback .= $this->getScreen();
		$this->base_attr_cell = $base_attr_cell;

		return '<pre width="' . ($this->max_x + 1) . '" style="color: white; background: black">' . $scrollback . '</span></pre>';
	}
}
}

namespace phpseclib3\File\ASN1 {

class Element
{

	public $element;

	public function __construct($encoded)
	{
		$this->element = $encoded;
	}
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AccessDescription
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'accessMethod' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'accessLocation' => GeneralName::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AdministrationDomainName
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,

		'class' => ASN1::CLASS_APPLICATION,
		'cast' => 2,
		'children' => [
			'numeric' => ['type' => ASN1::TYPE_NUMERIC_STRING],
			'printable' => ['type' => ASN1::TYPE_PRINTABLE_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AlgorithmIdentifier
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'algorithm' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'parameters' => [
				'type' => ASN1::TYPE_ANY,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AnotherName
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'type-id' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'value' => [
				'type' => ASN1::TYPE_ANY,
				'constant' => 0,
				'optional' => true,
				'explicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Attribute
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'type' => AttributeType::MAP,
			'value' => [
				'type' => ASN1::TYPE_SET,
				'min' => 1,
				'max' => -1,
				'children' => AttributeValue::MAP
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Attributes
{
	const MAP = [
		'type' => ASN1::TYPE_SET,
		'min' => 1,
		'max' => -1,
		'children' => Attribute::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AttributeType
{
	const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AttributeTypeAndValue
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'type' => AttributeType::MAP,
			'value' => AttributeValue::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AttributeValue
{
	const MAP = ['type' => ASN1::TYPE_ANY];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AuthorityInfoAccessSyntax
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => AccessDescription::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class AuthorityKeyIdentifier
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'keyIdentifier' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + KeyIdentifier::MAP,
			'authorityCertIssuer' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + GeneralNames::MAP,
			'authorityCertSerialNumber' => [
				'constant' => 2,
				'optional' => true,
				'implicit' => true
			] + CertificateSerialNumber::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class BaseDistance
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class BasicConstraints
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'cA' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'optional' => true,
				'default' => false
			],
			'pathLenConstraint' => [
				'type' => ASN1::TYPE_INTEGER,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class BuiltInDomainDefinedAttribute
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'type' => ['type' => ASN1::TYPE_PRINTABLE_STRING],
			'value' => ['type' => ASN1::TYPE_PRINTABLE_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class BuiltInDomainDefinedAttributes
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => 4,
		'children' => BuiltInDomainDefinedAttribute::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class BuiltInStandardAttributes
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'country-name' => ['optional' => true] + CountryName::MAP,
			'administration-domain-name' => ['optional' => true] + AdministrationDomainName::MAP,
			'network-address' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + NetworkAddress::MAP,
			'terminal-identifier' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + TerminalIdentifier::MAP,
			'private-domain-name' => [
				'constant' => 2,
				'optional' => true,
				'explicit' => true
			] + PrivateDomainName::MAP,
			'organization-name' => [
				'constant' => 3,
				'optional' => true,
				'implicit' => true
			] + OrganizationName::MAP,
			'numeric-user-identifier' => [
				'constant' => 4,
				'optional' => true,
				'implicit' => true
			] + NumericUserIdentifier::MAP,
			'personal-name' => [
				'constant' => 5,
				'optional' => true,
				'implicit' => true
			] + PersonalName::MAP,
			'organizational-unit-names' => [
				'constant' => 6,
				'optional' => true,
				'implicit' => true
			] + OrganizationalUnitNames::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Certificate
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'tbsCertificate' => TBSCertificate::MAP,
			'signatureAlgorithm' => AlgorithmIdentifier::MAP,
			'signature' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

abstract class CertificateIssuer
{
	const MAP = GeneralNames::MAP;
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertificateList
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'tbsCertList' => TBSCertList::MAP,
			'signatureAlgorithm' => AlgorithmIdentifier::MAP,
			'signature' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertificatePolicies
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => PolicyInformation::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertificateSerialNumber
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertificationRequest
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'certificationRequestInfo' => CertificationRequestInfo::MAP,
			'signatureAlgorithm' => AlgorithmIdentifier::MAP,
			'signature' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertificationRequestInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => ['v1']
			],
			'subject' => Name::MAP,
			'subjectPKInfo' => SubjectPublicKeyInfo::MAP,
			'attributes' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + Attributes::MAP,
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CertPolicyId
{
	const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Characteristic_two
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'm' => ['type' => ASN1::TYPE_INTEGER],
			'basis' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'parameters' => [
				'type' => ASN1::TYPE_ANY,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CountryName
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,

		'class' => ASN1::CLASS_APPLICATION,
		'cast' => 1,
		'children' => [
			'x121-dcc-code' => ['type' => ASN1::TYPE_NUMERIC_STRING],
			'iso-3166-alpha2-code' => ['type' => ASN1::TYPE_PRINTABLE_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CPSuri
{
	const MAP = ['type' => ASN1::TYPE_IA5_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CRLDistributionPoints
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => DistributionPoint::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CRLNumber
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class CRLReason
{
	const MAP = [
		'type' => ASN1::TYPE_ENUMERATED,
		'mapping' => [
			'unspecified',
			'keyCompromise',
			'cACompromise',
			'affiliationChanged',
			'superseded',
			'cessationOfOperation',
			'certificateHold',

			8 => 'removeFromCRL',
			'privilegeWithdrawn',
			'aACompromise'
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Curve
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'a' => FieldElement::MAP,
			'b' => FieldElement::MAP,
			'seed' => [
				'type' => ASN1::TYPE_BIT_STRING,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DHParameter
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'prime' => ['type' => ASN1::TYPE_INTEGER],
			'base' => ['type' => ASN1::TYPE_INTEGER],
			'privateValueLength' => [
				'type' => ASN1::TYPE_INTEGER,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DigestInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'digestAlgorithm' => AlgorithmIdentifier::MAP,
			'digest' => ['type' => ASN1::TYPE_OCTET_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DirectoryString
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'teletexString' => ['type' => ASN1::TYPE_TELETEX_STRING],
			'printableString' => ['type' => ASN1::TYPE_PRINTABLE_STRING],
			'universalString' => ['type' => ASN1::TYPE_UNIVERSAL_STRING],
			'utf8String' => ['type' => ASN1::TYPE_UTF8_STRING],
			'bmpString' => ['type' => ASN1::TYPE_BMP_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DisplayText
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'ia5String' => ['type' => ASN1::TYPE_IA5_STRING],
			'visibleString' => ['type' => ASN1::TYPE_VISIBLE_STRING],
			'bmpString' => ['type' => ASN1::TYPE_BMP_STRING],
			'utf8String' => ['type' => ASN1::TYPE_UTF8_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DistributionPoint
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'distributionPoint' => [
				'constant' => 0,
				'optional' => true,
				'explicit' => true
			] + DistributionPointName::MAP,
			'reasons' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + ReasonFlags::MAP,
			'cRLIssuer' => [
				'constant' => 2,
				'optional' => true,
				'implicit' => true
			] + GeneralNames::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DistributionPointName
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'fullName' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + GeneralNames::MAP,
			'nameRelativeToCRLIssuer' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + RelativeDistinguishedName::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DSAParams
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'p' => ['type' => ASN1::TYPE_INTEGER],
			'q' => ['type' => ASN1::TYPE_INTEGER],
			'g' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DSAPrivateKey
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => ['type' => ASN1::TYPE_INTEGER],
			'p' => ['type' => ASN1::TYPE_INTEGER],
			'q' => ['type' => ASN1::TYPE_INTEGER],
			'g' => ['type' => ASN1::TYPE_INTEGER],
			'y' => ['type' => ASN1::TYPE_INTEGER],
			'x' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DSAPublicKey
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class DssSigValue
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'r' => ['type' => ASN1::TYPE_INTEGER],
			's' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class EcdsaSigValue
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'r' => ['type' => ASN1::TYPE_INTEGER],
			's' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ECParameters
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'namedCurve' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'implicitCurve' => ['type' => ASN1::TYPE_NULL],
			'specifiedCurve' => SpecifiedECDomain::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ECPoint
{
	const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ECPrivateKey
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => [1 => 'ecPrivkeyVer1']
			],
			'privateKey' => ['type' => ASN1::TYPE_OCTET_STRING],
			'parameters' => [
				'constant' => 0,
				'optional' => true,
				'explicit' => true
			] + ECParameters::MAP,
			'publicKey' => [
				'type' => ASN1::TYPE_BIT_STRING,
				'constant' => 1,
				'optional' => true,
				'explicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class EDIPartyName
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'nameAssigner' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + DirectoryString::MAP,

			'partyName' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + DirectoryString::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class EncryptedData
{
	const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class EncryptedPrivateKeyInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'encryptionAlgorithm' => AlgorithmIdentifier::MAP,
			'encryptedData' => EncryptedData::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Extension
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'extnId' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'critical' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'optional' => true,
				'default' => false
			],
			'extnValue' => ['type' => ASN1::TYPE_OCTET_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ExtensionAttribute
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'extension-attribute-type' => [
				'type' => ASN1::TYPE_PRINTABLE_STRING,
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			],
			'extension-attribute-value' => [
				'type' => ASN1::TYPE_ANY,
				'constant' => 1,
				'optional' => true,
				'explicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ExtensionAttributes
{
	const MAP = [
		'type' => ASN1::TYPE_SET,
		'min' => 1,
		'max' => 256,
		'children' => ExtensionAttribute::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Extensions
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,

		'max' => -1,

		'children' => Extension::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ExtKeyUsageSyntax
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => KeyPurposeId::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class FieldElement
{
	const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class FieldID
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'fieldType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
			'parameters' => [
				'type' => ASN1::TYPE_ANY,
				'optional' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class GeneralName
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'otherName' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + AnotherName::MAP,
			'rfc822Name' => [
				'type' => ASN1::TYPE_IA5_STRING,
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			],
			'dNSName' => [
				'type' => ASN1::TYPE_IA5_STRING,
				'constant' => 2,
				'optional' => true,
				'implicit' => true
			],
			'x400Address' => [
				'constant' => 3,
				'optional' => true,
				'implicit' => true
			] + ORAddress::MAP,
			'directoryName' => [
				'constant' => 4,
				'optional' => true,
				'explicit' => true
			] + Name::MAP,
			'ediPartyName' => [
				'constant' => 5,
				'optional' => true,
				'implicit' => true
			] + EDIPartyName::MAP,
			'uniformResourceIdentifier' => [
				'type' => ASN1::TYPE_IA5_STRING,
				'constant' => 6,
				'optional' => true,
				'implicit' => true
			],
			'iPAddress' => [
				'type' => ASN1::TYPE_OCTET_STRING,
				'constant' => 7,
				'optional' => true,
				'implicit' => true
			],
			'registeredID' => [
				'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
				'constant' => 8,
				'optional' => true,
				'implicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class GeneralNames
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => GeneralName::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class GeneralSubtree
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'base' => GeneralName::MAP,
			'minimum' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true,
				'default' => '0'
			] + BaseDistance::MAP,
			'maximum' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true,
			] + BaseDistance::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class GeneralSubtrees
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => GeneralSubtree::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

abstract class HashAlgorithm
{
	const MAP = AlgorithmIdentifier::MAP;
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class HoldInstructionCode
{
	const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class InvalidityDate
{
	const MAP = ['type' => ASN1::TYPE_GENERALIZED_TIME];
}
}

namespace phpseclib3\File\ASN1\Maps {

abstract class IssuerAltName
{
	const MAP = GeneralNames::MAP;
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class IssuingDistributionPoint
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'distributionPoint' => [
				'constant' => 0,
				'optional' => true,
				'explicit' => true
			] + DistributionPointName::MAP,
			'onlyContainsUserCerts' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'constant' => 1,
				'optional' => true,
				'default' => false,
				'implicit' => true
			],
			'onlyContainsCACerts' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'constant' => 2,
				'optional' => true,
				'default' => false,
				'implicit' => true
			],
			'onlySomeReasons' => [
				'constant' => 3,
				'optional' => true,
				'implicit' => true
			] + ReasonFlags::MAP,
			'indirectCRL' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'constant' => 4,
				'optional' => true,
				'default' => false,
				'implicit' => true
			],
			'onlyContainsAttributeCerts' => [
				'type' => ASN1::TYPE_BOOLEAN,
				'constant' => 5,
				'optional' => true,
				'default' => false,
				'implicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class KeyIdentifier
{
	const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class KeyPurposeId
{
	const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class KeyUsage
{
	const MAP = [
		'type' => ASN1::TYPE_BIT_STRING,
		'mapping' => [
			'digitalSignature',
			'nonRepudiation',
			'keyEncipherment',
			'dataEncipherment',
			'keyAgreement',
			'keyCertSign',
			'cRLSign',
			'encipherOnly',
			'decipherOnly'
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

abstract class MaskGenAlgorithm
{
	const MAP = AlgorithmIdentifier::MAP;
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Name
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'rdnSequence' => RDNSequence::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class NameConstraints
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'permittedSubtrees' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + GeneralSubtrees::MAP,
			'excludedSubtrees' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + GeneralSubtrees::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class netscape_ca_policy_url
{
	const MAP = ['type' => ASN1::TYPE_IA5_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class netscape_cert_type
{
	const MAP = [
		'type' => ASN1::TYPE_BIT_STRING,
		'mapping' => [
			'SSLClient',
			'SSLServer',
			'Email',
			'ObjectSigning',
			'Reserved',
			'SSLCA',
			'EmailCA',
			'ObjectSigningCA'
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class netscape_comment
{
	const MAP = ['type' => ASN1::TYPE_IA5_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class NetworkAddress
{
	const MAP = ['type' => ASN1::TYPE_NUMERIC_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class NoticeReference
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'organization' => DisplayText::MAP,
			'noticeNumbers' => [
				'type' => ASN1::TYPE_SEQUENCE,
				'min' => 1,
				'max' => 200,
				'children' => ['type' => ASN1::TYPE_INTEGER]
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class NumericUserIdentifier
{
	const MAP = ['type' => ASN1::TYPE_NUMERIC_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class OneAsymmetricKey
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => ['v1', 'v2']
			],
			'privateKeyAlgorithm' => AlgorithmIdentifier::MAP,
			'privateKey' => PrivateKey::MAP,
			'attributes' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + Attributes::MAP,
			'publicKey' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + PublicKey::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ORAddress
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'built-in-standard-attributes' => BuiltInStandardAttributes::MAP,
			'built-in-domain-defined-attributes' => ['optional' => true] + BuiltInDomainDefinedAttributes::MAP,
			'extension-attributes' => ['optional' => true] + ExtensionAttributes::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class OrganizationalUnitNames
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => 4,
		'children' => ['type' => ASN1::TYPE_PRINTABLE_STRING]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class OrganizationName
{
	const MAP = ['type' => ASN1::TYPE_PRINTABLE_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class OtherPrimeInfo
{

	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'prime' => ['type' => ASN1::TYPE_INTEGER],
			'exponent' => ['type' => ASN1::TYPE_INTEGER],
			'coefficient' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class OtherPrimeInfos
{

	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => OtherPrimeInfo::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PBEParameter
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'salt' => ['type' => ASN1::TYPE_OCTET_STRING],
			'iterationCount' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PBES2params
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'keyDerivationFunc' => AlgorithmIdentifier::MAP,
			'encryptionScheme' => AlgorithmIdentifier::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PBKDF2params
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [

			'salt' => ['type' => ASN1::TYPE_OCTET_STRING],
			'iterationCount' => ['type' => ASN1::TYPE_INTEGER],
			'keyLength' => [
				'type' => ASN1::TYPE_INTEGER,
				'optional' => true
			],
			'prf' => AlgorithmIdentifier::MAP + ['optional' => true]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PBMAC1params
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'keyDerivationFunc' => AlgorithmIdentifier::MAP,
			'messageAuthScheme' => AlgorithmIdentifier::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Pentanomial
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'k1' => ['type' => ASN1::TYPE_INTEGER],
			'k2' => ['type' => ASN1::TYPE_INTEGER],
			'k3' => ['type' => ASN1::TYPE_INTEGER],
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PersonalName
{
	const MAP = [
		'type' => ASN1::TYPE_SET,
		'children' => [
			'surname' => [
				'type' => ASN1::TYPE_PRINTABLE_STRING,
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			],
			'given-name' => [
				'type' => ASN1::TYPE_PRINTABLE_STRING,
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			],
			'initials' => [
				'type' => ASN1::TYPE_PRINTABLE_STRING,
				'constant' => 2,
				'optional' => true,
				'implicit' => true
			],
			'generation-qualifier' => [
				'type' => ASN1::TYPE_PRINTABLE_STRING,
				'constant' => 3,
				'optional' => true,
				'implicit' => true
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PKCS9String
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'ia5String' => ['type' => ASN1::TYPE_IA5_STRING],
			'directoryString' => DirectoryString::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PolicyInformation
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'policyIdentifier' => CertPolicyId::MAP,
			'policyQualifiers' => [
				'type' => ASN1::TYPE_SEQUENCE,
				'min' => 0,
				'max' => -1,
				'optional' => true,
				'children' => PolicyQualifierInfo::MAP
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PolicyMappings
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => [
			'type' => ASN1::TYPE_SEQUENCE,
			'children' => [
				'issuerDomainPolicy' => CertPolicyId::MAP,
				'subjectDomainPolicy' => CertPolicyId::MAP
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PolicyQualifierId
{
	const MAP = ['type' => ASN1::TYPE_OBJECT_IDENTIFIER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PolicyQualifierInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'policyQualifierId' => PolicyQualifierId::MAP,
			'qualifier' => ['type' => ASN1::TYPE_ANY]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PostalAddress
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'optional' => true,
		'min' => 1,
		'max' => -1,
		'children' => DirectoryString::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Prime_p
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PrivateDomainName
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'numeric' => ['type' => ASN1::TYPE_NUMERIC_STRING],
			'printable' => ['type' => ASN1::TYPE_PRINTABLE_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PrivateKey
{
	const MAP = ['type' => ASN1::TYPE_OCTET_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PrivateKeyInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => ['v1']
			],
			'privateKeyAlgorithm' => AlgorithmIdentifier::MAP,
			'privateKey' => PrivateKey::MAP,
			'attributes' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true
			] + Attributes::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PrivateKeyUsagePeriod
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'notBefore' => [
				'constant' => 0,
				'optional' => true,
				'implicit' => true,
				'type' => ASN1::TYPE_GENERALIZED_TIME],
			'notAfter' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true,
				'type' => ASN1::TYPE_GENERALIZED_TIME]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PublicKey
{
	const MAP = ['type' => ASN1::TYPE_BIT_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PublicKeyAndChallenge
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'spki' => SubjectPublicKeyInfo::MAP,
			'challenge' => ['type' => ASN1::TYPE_IA5_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class PublicKeyInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'publicKeyAlgorithm' => AlgorithmIdentifier::MAP,
			'publicKey' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RC2CBCParameter
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'rc2ParametersVersion' => [
				'type' => ASN1::TYPE_INTEGER,
				'optional' => true
			],
			'iv' => ['type' => ASN1::TYPE_OCTET_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RDNSequence
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,

		'min' => 0,
		'max' => -1,
		'children' => RelativeDistinguishedName::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class ReasonFlags
{
	const MAP = [
		'type' => ASN1::TYPE_BIT_STRING,
		'mapping' => [
			'unused',
			'keyCompromise',
			'cACompromise',
			'affiliationChanged',
			'superseded',
			'cessationOfOperation',
			'certificateHold',
			'privilegeWithdrawn',
			'aACompromise'
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RelativeDistinguishedName
{
	const MAP = [
		'type' => ASN1::TYPE_SET,
		'min' => 1,
		'max' => -1,
		'children' => AttributeTypeAndValue::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RevokedCertificate
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'userCertificate' => CertificateSerialNumber::MAP,
			'revocationDate' => Time::MAP,
			'crlEntryExtensions' => [
				'optional' => true
			] + Extensions::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RSAPrivateKey
{

	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => ['two-prime', 'multi']
			],
			'modulus' => ['type' => ASN1::TYPE_INTEGER],
			'publicExponent' => ['type' => ASN1::TYPE_INTEGER],
			'privateExponent' => ['type' => ASN1::TYPE_INTEGER],
			'prime1' => ['type' => ASN1::TYPE_INTEGER],
			'prime2' => ['type' => ASN1::TYPE_INTEGER],
			'exponent1' => ['type' => ASN1::TYPE_INTEGER],
			'exponent2' => ['type' => ASN1::TYPE_INTEGER],
			'coefficient' => ['type' => ASN1::TYPE_INTEGER],
			'otherPrimeInfos' => OtherPrimeInfos::MAP + ['optional' => true]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RSAPublicKey
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'modulus' => ['type' => ASN1::TYPE_INTEGER],
			'publicExponent' => ['type' => ASN1::TYPE_INTEGER]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class RSASSA_PSS_params
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'hashAlgorithm' => [
				'constant' => 0,
				'optional' => true,
				'explicit' => true,

			] + HashAlgorithm::MAP,
			'maskGenAlgorithm' => [
				'constant' => 1,
				'optional' => true,
				'explicit' => true,

			] + MaskGenAlgorithm::MAP,
			'saltLength' => [
				'type' => ASN1::TYPE_INTEGER,
				'constant' => 2,
				'optional' => true,
				'explicit' => true,
				'default' => 20
			],
			'trailerField' => [
				'type' => ASN1::TYPE_INTEGER,
				'constant' => 3,
				'optional' => true,
				'explicit' => true,
				'default' => 1
			]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class SignedPublicKeyAndChallenge
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'publicKeyAndChallenge' => PublicKeyAndChallenge::MAP,
			'signatureAlgorithm' => AlgorithmIdentifier::MAP,
			'signature' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class SpecifiedECDomain
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => [1 => 'ecdpVer1', 'ecdpVer2', 'ecdpVer3']
			],
			'fieldID' => FieldID::MAP,
			'curve' => Curve::MAP,
			'base' => ECPoint::MAP,
			'order' => ['type' => ASN1::TYPE_INTEGER],
			'cofactor' => [
				'type' => ASN1::TYPE_INTEGER,
				'optional' => true
			],
			'hash' => ['optional' => true] + HashAlgorithm::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

abstract class SubjectAltName
{
	const MAP = GeneralNames::MAP;
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class SubjectDirectoryAttributes
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => Attribute::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class SubjectInfoAccessSyntax
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'min' => 1,
		'max' => -1,
		'children' => AccessDescription::MAP
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class SubjectPublicKeyInfo
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'algorithm' => AlgorithmIdentifier::MAP,
			'subjectPublicKey' => ['type' => ASN1::TYPE_BIT_STRING]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class TBSCertificate
{

	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [

			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'constant' => 0,
				'optional' => true,
				'explicit' => true,
				'mapping' => ['v1', 'v2', 'v3'],
				'default' => 'v1'
			],
			'serialNumber' => CertificateSerialNumber::MAP,
			'signature' => AlgorithmIdentifier::MAP,
			'issuer' => Name::MAP,
			'validity' => Validity::MAP,
			'subject' => Name::MAP,
			'subjectPublicKeyInfo' => SubjectPublicKeyInfo::MAP,

			'issuerUniqueID' => [
				'constant' => 1,
				'optional' => true,
				'implicit' => true
			] + UniqueIdentifier::MAP,
			'subjectUniqueID' => [
				'constant' => 2,
				'optional' => true,
				'implicit' => true
			] + UniqueIdentifier::MAP,

			'extensions' => [
				'constant' => 3,
				'optional' => true,
				'explicit' => true
			] + Extensions::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class TBSCertList
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'version' => [
				'type' => ASN1::TYPE_INTEGER,
				'mapping' => ['v1', 'v2'],
				'optional' => true,
				'default' => 'v1'
			],
			'signature' => AlgorithmIdentifier::MAP,
			'issuer' => Name::MAP,
			'thisUpdate' => Time::MAP,
			'nextUpdate' => [
				'optional' => true
			] + Time::MAP,
			'revokedCertificates' => [
				'type' => ASN1::TYPE_SEQUENCE,
				'optional' => true,
				'min' => 0,
				'max' => -1,
				'children' => RevokedCertificate::MAP
			],
			'crlExtensions' => [
				'constant' => 0,
				'optional' => true,
				'explicit' => true
			] + Extensions::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class TerminalIdentifier
{
	const MAP = ['type' => ASN1::TYPE_PRINTABLE_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Time
{
	const MAP = [
		'type' => ASN1::TYPE_CHOICE,
		'children' => [
			'utcTime' => ['type' => ASN1::TYPE_UTC_TIME],
			'generalTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME]
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Trinomial
{
	const MAP = ['type' => ASN1::TYPE_INTEGER];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class UniqueIdentifier
{
	const MAP = ['type' => ASN1::TYPE_BIT_STRING];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class UserNotice
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'noticeRef' => [
				'optional' => true,
				'implicit' => true
			] + NoticeReference::MAP,
			'explicitText' => [
				'optional' => true,
				'implicit' => true
			] + DisplayText::MAP
		]
	];
}
}

namespace phpseclib3\File\ASN1\Maps {

use phpseclib3\File\ASN1;

abstract class Validity
{
	const MAP = [
		'type' => ASN1::TYPE_SEQUENCE,
		'children' => [
			'notBefore' => Time::MAP,
			'notAfter' => Time::MAP
		]
	];
}
}

namespace phpseclib3\File {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\File\ASN1\Element;
use phpseclib3\Math\BigInteger;

abstract class ASN1
{

	const CLASS_UNIVERSAL		= 0;
	const CLASS_APPLICATION		= 1;
	const CLASS_CONTEXT_SPECIFIC = 2;
	const CLASS_PRIVATE			= 3;

	const TYPE_BOOLEAN			= 1;
	const TYPE_INTEGER			= 2;
	const TYPE_BIT_STRING		= 3;
	const TYPE_OCTET_STRING		= 4;
	const TYPE_NULL				= 5;
	const TYPE_OBJECT_IDENTIFIER = 6;

	const TYPE_REAL				= 9;
	const TYPE_ENUMERATED		= 10;

	const TYPE_UTF8_STRING		= 12;

	const TYPE_SEQUENCE			= 16;
	const TYPE_SET				= 17;

	const TYPE_NUMERIC_STRING	= 18;
	const TYPE_PRINTABLE_STRING = 19;
	const TYPE_TELETEX_STRING	= 20;
	const TYPE_VIDEOTEX_STRING	= 21;
	const TYPE_IA5_STRING		= 22;
	const TYPE_UTC_TIME		 = 23;
	const TYPE_GENERALIZED_TIME = 24;
	const TYPE_GRAPHIC_STRING	= 25;
	const TYPE_VISIBLE_STRING	= 26;
	const TYPE_GENERAL_STRING	= 27;
	const TYPE_UNIVERSAL_STRING = 28;

	const TYPE_BMP_STRING		= 30;

	const TYPE_CHOICE = -1;
	const TYPE_ANY	= -2;

	private static $oids = [];

	private static $reverseOIDs = [];

	private static $format = 'D, d M Y H:i:s O';

	private static $filters;

	private static $location;

	private static $encoded;

	const ANY_MAP = [
		self::TYPE_BOOLEAN				=> true,
		self::TYPE_INTEGER				=> true,
		self::TYPE_BIT_STRING			=> 'bitString',
		self::TYPE_OCTET_STRING		 => 'octetString',
		self::TYPE_NULL				 => 'null',
		self::TYPE_OBJECT_IDENTIFIER	=> 'objectIdentifier',
		self::TYPE_REAL				 => true,
		self::TYPE_ENUMERATED			=> 'enumerated',
		self::TYPE_UTF8_STRING			=> 'utf8String',
		self::TYPE_NUMERIC_STRING		=> 'numericString',
		self::TYPE_PRINTABLE_STRING	 => 'printableString',
		self::TYPE_TELETEX_STRING		=> 'teletexString',
		self::TYPE_VIDEOTEX_STRING		=> 'videotexString',
		self::TYPE_IA5_STRING			=> 'ia5String',
		self::TYPE_UTC_TIME			 => 'utcTime',
		self::TYPE_GENERALIZED_TIME	 => 'generalTime',
		self::TYPE_GRAPHIC_STRING		=> 'graphicString',
		self::TYPE_VISIBLE_STRING		=> 'visibleString',
		self::TYPE_GENERAL_STRING		=> 'generalString',
		self::TYPE_UNIVERSAL_STRING	 => 'universalString',

		self::TYPE_BMP_STRING			=> 'bmpString'
	];

	const STRING_TYPE_SIZE = [
		self::TYPE_UTF8_STRING		=> 0,
		self::TYPE_BMP_STRING		=> 2,
		self::TYPE_UNIVERSAL_STRING => 4,
		self::TYPE_PRINTABLE_STRING => 1,
		self::TYPE_TELETEX_STRING	=> 1,
		self::TYPE_IA5_STRING		=> 1,
		self::TYPE_VISIBLE_STRING	=> 1,
	];

	public static function decodeBER($encoded)
	{
		if ($encoded instanceof Element) {
			$encoded = $encoded->element;
		}

		self::$encoded = $encoded;

		$decoded = self::decode_ber($encoded);
		if ($decoded === false) {
			return null;
		}

		return [$decoded];
	}

	private static function decode_ber($encoded, $start = 0, $encoded_pos = 0)
	{
		$current = ['start' => $start];

		if (!isset($encoded[$encoded_pos])) {
			return false;
		}
		$type = ord($encoded[$encoded_pos++]);
		$startOffset = 1;

		$constructed = ($type >> 5) & 1;

		$tag = $type & 0x1F;
		if ($tag == 0x1F) {
			$tag = 0;

			do {
				if (!isset($encoded[$encoded_pos])) {
					return false;
				}
				$temp = ord($encoded[$encoded_pos++]);
				$startOffset++;
				$loop = $temp >> 7;
				$tag <<= 7;
				$temp &= 0x7F;

				if ($startOffset == 2 && $temp == 0) {
					return false;
				}
				$tag |= $temp;
			} while ($loop);
		}

		$start += $startOffset;

		if (!isset($encoded[$encoded_pos])) {
			return false;
		}
		$length = ord($encoded[$encoded_pos++]);
		$start++;
		if ($length == 0x80) {

			$length = strlen($encoded) - $encoded_pos;
		} elseif ($length & 0x80) {

			$length &= 0x7F;
			$temp = substr($encoded, $encoded_pos, $length);
			$encoded_pos += $length;

			$current += ['headerlength' => $length + 2];
			$start += $length;
			extract(unpack('Nlength', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4)));

		} else {
			$current += ['headerlength' => 2];
		}

		if ($length > (strlen($encoded) - $encoded_pos)) {
			return false;
		}

		$content = substr($encoded, $encoded_pos, $length);
		$content_pos = 0;

		$class = ($type >> 6) & 3;
		switch ($class) {
			case self::CLASS_APPLICATION:
			case self::CLASS_PRIVATE:
			case self::CLASS_CONTEXT_SPECIFIC:
				if (!$constructed) {
					return [
						'type'	 => $class,
						'constant' => $tag,
						'content'	=> $content,
						'length'	=> $length + $start - $current['start']
					] + $current;
				}

				$newcontent = [];
				$remainingLength = $length;
				while ($remainingLength > 0) {
					$temp = self::decode_ber($content, $start, $content_pos);
					if ($temp === false) {
						break;
					}
					$length = $temp['length'];

					if (substr($content, $content_pos + $length, 2) == "\0\0") {
						$length += 2;
						$start += $length;
						$newcontent[] = $temp;
						break;
					}
					$start += $length;
					$remainingLength -= $length;
					$newcontent[] = $temp;
					$content_pos += $length;
				}

				return [
					'type'	 => $class,
					'constant' => $tag,

					'content'	=> $newcontent,

					'length'	=> $start - $current['start']
				] + $current;
		}

		$current += ['type' => $tag];

		switch ($tag) {
			case self::TYPE_BOOLEAN:

				if ($constructed || strlen($content) != 1) {
					return false;
				}
				$current['content'] = (bool) ord($content[$content_pos]);
				break;
			case self::TYPE_INTEGER:
			case self::TYPE_ENUMERATED:
				if ($constructed) {
					return false;
				}
				$current['content'] = new BigInteger(substr($content, $content_pos), -256);
				break;
			case self::TYPE_REAL:
				return false;
			case self::TYPE_BIT_STRING:

				if (!$constructed) {
					$current['content'] = substr($content, $content_pos);
				} else {
					$temp = self::decode_ber($content, $start, $content_pos);
					if ($temp === false) {
						return false;
					}
					$length -= (strlen($content) - $content_pos);
					$last = count($temp) - 1;
					for ($i = 0; $i < $last; $i++) {

						if ($temp[$i]['type'] != self::TYPE_BIT_STRING) {
							return false;
						}
						$current['content'] .= substr($temp[$i]['content'], 1);
					}

					if ($temp[$last]['type'] != self::TYPE_BIT_STRING) {
						return false;
					}
					$current['content'] = $temp[$last]['content'][0] . $current['content'] . substr($temp[$i]['content'], 1);
				}
				break;
			case self::TYPE_OCTET_STRING:
				if (!$constructed) {
					$current['content'] = substr($content, $content_pos);
				} else {
					$current['content'] = '';
					$length = 0;
					while (substr($content, $content_pos, 2) != "\0\0") {
						$temp = self::decode_ber($content, $length + $start, $content_pos);
						if ($temp === false) {
							return false;
						}
						$content_pos += $temp['length'];

						if ($temp['type'] != self::TYPE_OCTET_STRING) {
							return false;
						}
						$current['content'] .= $temp['content'];
						$length += $temp['length'];
					}
					if (substr($content, $content_pos, 2) == "\0\0") {
						$length += 2;
					}
				}
				break;
			case self::TYPE_NULL:

				if ($constructed || strlen($content)) {
					return false;
				}
				break;
			case self::TYPE_SEQUENCE:
			case self::TYPE_SET:
				if (!$constructed) {
					return false;
				}
				$offset = 0;
				$current['content'] = [];
				$content_len = strlen($content);
				while ($content_pos < $content_len) {

					if (!isset($current['headerlength']) && substr($content, $content_pos, 2) == "\0\0") {
						$length = $offset + 2;
						break 2;
					}
					$temp = self::decode_ber($content, $start + $offset, $content_pos);
					if ($temp === false) {
						return false;
					}
					$content_pos += $temp['length'];
					$current['content'][] = $temp;
					$offset += $temp['length'];
				}
				break;
			case self::TYPE_OBJECT_IDENTIFIER:
				if ($constructed) {
					return false;
				}
				$current['content'] = self::decodeOID(substr($content, $content_pos));
				if ($current['content'] === false) {
					return false;
				}
				break;

			case self::TYPE_NUMERIC_STRING:

			case self::TYPE_PRINTABLE_STRING:

			case self::TYPE_TELETEX_STRING:

			case self::TYPE_VIDEOTEX_STRING:

			case self::TYPE_VISIBLE_STRING:

			case self::TYPE_IA5_STRING:

			case self::TYPE_GRAPHIC_STRING:

			case self::TYPE_GENERAL_STRING:

			case self::TYPE_UTF8_STRING:

			case self::TYPE_BMP_STRING:
				if ($constructed) {
					return false;
				}
				$current['content'] = substr($content, $content_pos);
				break;
			case self::TYPE_UTC_TIME:
			case self::TYPE_GENERALIZED_TIME:
				if ($constructed) {
					return false;
				}
				$current['content'] = self::decodeTime(substr($content, $content_pos), $tag);
				break;
			default:
				return false;
		}

		$start += $length;

		return $current + ['length' => $start - $current['start']];
	}

	public static function asn1map(array $decoded, $mapping, $special = [])
	{
		if (isset($mapping['explicit']) && is_array($decoded['content'])) {
			$decoded = $decoded['content'][0];
		}

		switch (true) {
			case $mapping['type'] == self::TYPE_ANY:
				$intype = $decoded['type'];

				if (isset($decoded['constant']) || !array_key_exists($intype, self::ANY_MAP) || (ord(self::$encoded[$decoded['start']]) & 0x20)) {
					return new Element(substr(self::$encoded, $decoded['start'], $decoded['length']));
				}
				$inmap = self::ANY_MAP[$intype];
				if (is_string($inmap)) {
					return [$inmap => self::asn1map($decoded, ['type' => $intype] + $mapping, $special)];
				}
				break;
			case $mapping['type'] == self::TYPE_CHOICE:
				foreach ($mapping['children'] as $key => $option) {
					switch (true) {
						case isset($option['constant']) && $option['constant'] == $decoded['constant']:
						case !isset($option['constant']) && $option['type'] == $decoded['type']:
							$value = self::asn1map($decoded, $option, $special);
							break;
						case !isset($option['constant']) && $option['type'] == self::TYPE_CHOICE:
							$v = self::asn1map($decoded, $option, $special);
							if (isset($v)) {
								$value = $v;
							}
					}
					if (isset($value)) {
						if (isset($special[$key])) {
							$value = $special[$key]($value);
						}
						return [$key => $value];
					}
				}
				return null;
			case isset($mapping['implicit']):
			case isset($mapping['explicit']):
			case $decoded['type'] == $mapping['type']:
				break;
			default:

				switch (true) {
					case $decoded['type'] < 18:
					case $decoded['type'] > 30:
					case $mapping['type'] < 18:
					case $mapping['type'] > 30:
						return null;
				}
		}

		if (isset($mapping['implicit'])) {
			$decoded['type'] = $mapping['type'];
		}

		switch ($decoded['type']) {
			case self::TYPE_SEQUENCE:
				$map = [];

				if (isset($mapping['min']) && isset($mapping['max'])) {
					$child = $mapping['children'];
					foreach ($decoded['content'] as $content) {
						if (($map[] = self::asn1map($content, $child, $special)) === null) {
							return null;
						}
					}

					return $map;
				}

				$n = count($decoded['content']);
				$i = 0;

				foreach ($mapping['children'] as $key => $child) {
					$maymatch = $i < $n;
					if ($maymatch) {
						$temp = $decoded['content'][$i];

						if ($child['type'] != self::TYPE_CHOICE) {

							$childClass = $tempClass = self::CLASS_UNIVERSAL;
							$constant = null;
							if (isset($temp['constant'])) {
								$tempClass = $temp['type'];
							}
							if (isset($child['class'])) {
								$childClass = $child['class'];
								$constant = $child['cast'];
							} elseif (isset($child['constant'])) {
								$childClass = self::CLASS_CONTEXT_SPECIFIC;
								$constant = $child['constant'];
							}

							if (isset($constant) && isset($temp['constant'])) {

								$maymatch = $constant == $temp['constant'] && $childClass == $tempClass;
							} else {

								$maymatch = !isset($child['constant']) && array_search($child['type'], [$temp['type'], self::TYPE_ANY, self::TYPE_CHOICE]) !== false;
							}
						}
					}

					if ($maymatch) {

						$candidate = self::asn1map($temp, $child, $special);
						$maymatch = $candidate !== null;
					}

					if ($maymatch) {

						if (isset($special[$key])) {
							$candidate = $special[$key]($candidate);
						}
						$map[$key] = $candidate;
						$i++;
					} elseif (isset($child['default'])) {
						$map[$key] = $child['default'];
					} elseif (!isset($child['optional'])) {
						return null;
					}
				}

				return $i < $n ? null : $map;

			case self::TYPE_SET:
				$map = [];

				if (isset($mapping['min']) && isset($mapping['max'])) {
					$child = $mapping['children'];
					foreach ($decoded['content'] as $content) {
						if (($map[] = self::asn1map($content, $child, $special)) === null) {
							return null;
						}
					}

					return $map;
				}

				for ($i = 0; $i < count($decoded['content']); $i++) {
					$temp = $decoded['content'][$i];
					$tempClass = self::CLASS_UNIVERSAL;
					if (isset($temp['constant'])) {
						$tempClass = $temp['type'];
					}

					foreach ($mapping['children'] as $key => $child) {
						if (isset($map[$key])) {
							continue;
						}
						$maymatch = true;
						if ($child['type'] != self::TYPE_CHOICE) {
							$childClass = self::CLASS_UNIVERSAL;
							$constant = null;
							if (isset($child['class'])) {
								$childClass = $child['class'];
								$constant = $child['cast'];
							} elseif (isset($child['constant'])) {
								$childClass = self::CLASS_CONTEXT_SPECIFIC;
								$constant = $child['constant'];
							}

							if (isset($constant) && isset($temp['constant'])) {

								$maymatch = $constant == $temp['constant'] && $childClass == $tempClass;
							} else {

								$maymatch = !isset($child['constant']) && array_search($child['type'], [$temp['type'], self::TYPE_ANY, self::TYPE_CHOICE]) !== false;
							}
						}

						if ($maymatch) {

							$candidate = self::asn1map($temp, $child, $special);
							$maymatch = $candidate !== null;
						}

						if (!$maymatch) {
							break;
						}

						if (isset($special[$key])) {
							$candidate = $special[$key]($candidate);
						}
						$map[$key] = $candidate;
						break;
					}
				}

				foreach ($mapping['children'] as $key => $child) {
					if (!isset($map[$key])) {
						if (isset($child['default'])) {
							$map[$key] = $child['default'];
						} elseif (!isset($child['optional'])) {
							return null;
						}
					}
				}
				return $map;
			case self::TYPE_OBJECT_IDENTIFIER:
				return isset(self::$oids[$decoded['content']]) ? self::$oids[$decoded['content']] : $decoded['content'];
			case self::TYPE_UTC_TIME:
			case self::TYPE_GENERALIZED_TIME:

				if (is_array($decoded['content'])) {
					$decoded['content'] = $decoded['content'][0]['content'];
				}

				if (!is_object($decoded['content'])) {
					$decoded['content'] = self::decodeTime($decoded['content'], $decoded['type']);
				}
				return $decoded['content'] ? $decoded['content']->format(self::$format) : false;
			case self::TYPE_BIT_STRING:
				if (isset($mapping['mapping'])) {
					$offset = ord($decoded['content'][0]);
					$size = (strlen($decoded['content']) - 1) * 8 - $offset;

					$bits = count($mapping['mapping']) == $size ? [] : array_fill(0, count($mapping['mapping']) - $size, false);
					for ($i = strlen($decoded['content']) - 1; $i > 0; $i--) {
						$current = ord($decoded['content'][$i]);
						for ($j = $offset; $j < 8; $j++) {
							$bits[] = (bool) ($current & (1 << $j));
						}
						$offset = 0;
					}
					$values = [];
					$map = array_reverse($mapping['mapping']);
					foreach ($map as $i => $value) {
						if ($bits[$i]) {
							$values[] = $value;
						}
					}
					return $values;
				}

			case self::TYPE_OCTET_STRING:
				return $decoded['content'];
			case self::TYPE_NULL:
				return '';
			case self::TYPE_BOOLEAN:
			case self::TYPE_NUMERIC_STRING:
			case self::TYPE_PRINTABLE_STRING:
			case self::TYPE_TELETEX_STRING:
			case self::TYPE_VIDEOTEX_STRING:
			case self::TYPE_IA5_STRING:
			case self::TYPE_GRAPHIC_STRING:
			case self::TYPE_VISIBLE_STRING:
			case self::TYPE_GENERAL_STRING:
			case self::TYPE_UNIVERSAL_STRING:
			case self::TYPE_UTF8_STRING:
			case self::TYPE_BMP_STRING:
				return $decoded['content'];
			case self::TYPE_INTEGER:
			case self::TYPE_ENUMERATED:
				$temp = $decoded['content'];
				if (isset($mapping['implicit'])) {
					$temp = new BigInteger($decoded['content'], -256);
				}
				if (isset($mapping['mapping'])) {
					$temp = (int) $temp->toString();
					return isset($mapping['mapping'][$temp]) ?
						$mapping['mapping'][$temp] :
						false;
				}
				return $temp;
		}
	}

	public static function decodeLength(&$string)
	{
		$length = ord(Strings::shift($string));
		if ($length & 0x80) {
			$length &= 0x7F;
			$temp = Strings::shift($string, $length);
			list(, $length) = unpack('N', substr(str_pad($temp, 4, chr(0), STR_PAD_LEFT), -4));
		}
		return $length;
	}

	public static function encodeDER($source, $mapping, $special = [])
	{
		self::$location = [];
		return self::encode_der($source, $mapping, null, $special);
	}

	private static function encode_der($source, array $mapping, $idx = null, array $special = [])
	{
		if ($source instanceof Element) {
			return $source->element;
		}

		if (isset($mapping['default']) && $source === $mapping['default']) {
			return '';
		}

		if (isset($idx)) {
			if (isset($special[$idx])) {
				$source = $special[$idx]($source);
			}
			self::$location[] = $idx;
		}

		$tag = $mapping['type'];

		switch ($tag) {
			case self::TYPE_SET:
			case self::TYPE_SEQUENCE:
				$tag |= 0x20;

				if (isset($mapping['min']) && isset($mapping['max'])) {
					$value = [];
					$child = $mapping['children'];

					foreach ($source as $content) {
						$temp = self::encode_der($content, $child, null, $special);
						if ($temp === false) {
							return false;
						}
						$value[] = $temp;
					}

					if ($mapping['type'] == self::TYPE_SET) {
						sort($value);
					}
					$value = implode('', $value);
					break;
				}

				$value = '';
				foreach ($mapping['children'] as $key => $child) {
					if (!array_key_exists($key, $source)) {
						if (!isset($child['optional'])) {
							return false;
						}
						continue;
					}

					$temp = self::encode_der($source[$key], $child, $key, $special);
					if ($temp === false) {
						return false;
					}

					if ($temp === '') {
						continue;
					}

					if (isset($child['constant'])) {

						if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
							$subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
							$temp = $subtag . self::encodeLength(strlen($temp)) . $temp;
						} else {
							$subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']);
							$temp = $subtag . substr($temp, 1);
						}
					}
					$value .= $temp;
				}
				break;
			case self::TYPE_CHOICE:
				$temp = false;

				foreach ($mapping['children'] as $key => $child) {
					if (!isset($source[$key])) {
						continue;
					}

					$temp = self::encode_der($source[$key], $child, $key, $special);
					if ($temp === false) {
						return false;
					}

					if ($temp === '') {
						continue;
					}

					$tag = ord($temp[0]);

					if (isset($child['constant'])) {
						if (isset($child['explicit']) || $child['type'] == self::TYPE_CHOICE) {
							$subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | 0x20 | $child['constant']);
							$temp = $subtag . self::encodeLength(strlen($temp)) . $temp;
						} else {
							$subtag = chr((self::CLASS_CONTEXT_SPECIFIC << 6) | (ord($temp[0]) & 0x20) | $child['constant']);
							$temp = $subtag . substr($temp, 1);
						}
					}
				}

				if (isset($idx)) {
					array_pop(self::$location);
				}

				if ($temp && isset($mapping['cast'])) {
					$temp[0] = chr(($mapping['class'] << 6) | ($tag & 0x20) | $mapping['cast']);
				}

				return $temp;
			case self::TYPE_INTEGER:
			case self::TYPE_ENUMERATED:
				if (!isset($mapping['mapping'])) {
					if (is_numeric($source)) {
						$source = new BigInteger($source);
					}
					$value = $source->toBytes(true);
				} else {
					$value = array_search($source, $mapping['mapping']);
					if ($value === false) {
						return false;
					}
					$value = new BigInteger($value);
					$value = $value->toBytes(true);
				}
				if (!strlen($value)) {
					$value = chr(0);
				}
				break;
			case self::TYPE_UTC_TIME:
			case self::TYPE_GENERALIZED_TIME:
				$format = $mapping['type'] == self::TYPE_UTC_TIME ? 'y' : 'Y';
				$format .= 'mdHis';

				$date = new \DateTime($source, new \DateTimeZone('GMT'));

				$date->setTimezone(new \DateTimeZone('GMT'));
				$value = $date->format($format) . 'Z';
				break;
			case self::TYPE_BIT_STRING:
				if (isset($mapping['mapping'])) {
					$bits = array_fill(0, count($mapping['mapping']), 0);
					$size = 0;
					for ($i = 0; $i < count($mapping['mapping']); $i++) {
						if (in_array($mapping['mapping'][$i], $source)) {
							$bits[$i] = 1;
							$size = $i;
						}
					}

					if (isset($mapping['min']) && $mapping['min'] >= 1 && $size < $mapping['min']) {
						$size = $mapping['min'] - 1;
					}

					$offset = 8 - (($size + 1) & 7);
					$offset = $offset !== 8 ? $offset : 0;

					$value = chr($offset);

					for ($i = $size + 1; $i < count($mapping['mapping']); $i++) {
						unset($bits[$i]);
					}

					$bits = implode('', array_pad($bits, $size + $offset + 1, 0));
					$bytes = explode(' ', rtrim(chunk_split($bits, 8, ' ')));
					foreach ($bytes as $byte) {
						$value .= chr(bindec($byte));
					}

					break;
				}

			case self::TYPE_OCTET_STRING:

				$value = $source;
				break;
			case self::TYPE_OBJECT_IDENTIFIER:
				$value = self::encodeOID($source);
				break;
			case self::TYPE_ANY:
				$loc = self::$location;
				if (isset($idx)) {
					array_pop(self::$location);
				}

				switch (true) {
					case !isset($source):
						return self::encode_der(null, ['type' => self::TYPE_NULL] + $mapping, null, $special);
					case is_int($source):
					case $source instanceof BigInteger:
						return self::encode_der($source, ['type' => self::TYPE_INTEGER] + $mapping, null, $special);
					case is_float($source):
						return self::encode_der($source, ['type' => self::TYPE_REAL] + $mapping, null, $special);
					case is_bool($source):
						return self::encode_der($source, ['type' => self::TYPE_BOOLEAN] + $mapping, null, $special);
					case is_array($source) && count($source) == 1:
						$typename = implode('', array_keys($source));
						$outtype = array_search($typename, self::ANY_MAP, true);
						if ($outtype !== false) {
							return self::encode_der($source[$typename], ['type' => $outtype] + $mapping, null, $special);
						}
				}

				$filters = self::$filters;
				foreach ($loc as $part) {
					if (!isset($filters[$part])) {
						$filters = false;
						break;
					}
					$filters = $filters[$part];
				}
				if ($filters === false) {
					throw new \RuntimeException('No filters defined for ' . implode('/', $loc));
				}
				return self::encode_der($source, $filters + $mapping, null, $special);
			case self::TYPE_NULL:
				$value = '';
				break;
			case self::TYPE_NUMERIC_STRING:
			case self::TYPE_TELETEX_STRING:
			case self::TYPE_PRINTABLE_STRING:
			case self::TYPE_UNIVERSAL_STRING:
			case self::TYPE_UTF8_STRING:
			case self::TYPE_BMP_STRING:
			case self::TYPE_IA5_STRING:
			case self::TYPE_VISIBLE_STRING:
			case self::TYPE_VIDEOTEX_STRING:
			case self::TYPE_GRAPHIC_STRING:
			case self::TYPE_GENERAL_STRING:
				$value = $source;
				break;
			case self::TYPE_BOOLEAN:
				$value = $source ? "\xFF" : "\x00";
				break;
			default:
				throw new \RuntimeException('Mapping provides no type definition for ' . implode('/', self::$location));
		}

		if (isset($idx)) {
			array_pop(self::$location);
		}

		if (isset($mapping['cast'])) {
			if (isset($mapping['explicit']) || $mapping['type'] == self::TYPE_CHOICE) {
				$value = chr($tag) . self::encodeLength(strlen($value)) . $value;
				$tag = ($mapping['class'] << 6) | 0x20 | $mapping['cast'];
			} else {
				$tag = ($mapping['class'] << 6) | (ord($temp[0]) & 0x20) | $mapping['cast'];
			}
		}

		return chr($tag) . self::encodeLength(strlen($value)) . $value;
	}

	public static function decodeOID($content)
	{
		static $eighty;
		if (!$eighty) {
			$eighty = new BigInteger(80);
		}

		$oid = [];
		$pos = 0;
		$len = strlen($content);

		if ($len > 4096) {

			return false;
		}

		if (ord($content[$len - 1]) & 0x80) {
			return false;
		}

		$n = new BigInteger();
		while ($pos < $len) {
			$temp = ord($content[$pos++]);
			$n = $n->bitwise_leftShift(7);
			$n = $n->bitwise_or(new BigInteger($temp & 0x7F));
			if (~$temp & 0x80) {
				$oid[] = $n;
				$n = new BigInteger();
			}
		}
		$part1 = array_shift($oid);
		$first = floor(ord($content[0]) / 40);

		if ($first <= 2) {
			array_unshift($oid, ord($content[0]) % 40);
			array_unshift($oid, $first);
		} else {
			array_unshift($oid, $part1->subtract($eighty));
			array_unshift($oid, 2);
		}

		return implode('.', $oid);
	}

	public static function encodeOID($source)
	{
		static $mask, $zero, $forty;
		if (!$mask) {
			$mask = new BigInteger(0x7F);
			$zero = new BigInteger();
			$forty = new BigInteger(40);
		}

		if (!preg_match('#(?:\d+\.)+#', $source)) {
			$oid = isset(self::$reverseOIDs[$source]) ? self::$reverseOIDs[$source] : false;
		} else {
			$oid = $source;
		}
		if ($oid === false) {
			throw new \RuntimeException('Invalid OID');
		}

		$parts = explode('.', $oid);
		$part1 = array_shift($parts);
		$part2 = array_shift($parts);

		$first = new BigInteger($part1);
		$first = $first->multiply($forty);
		$first = $first->add(new BigInteger($part2));

		array_unshift($parts, $first->toString());

		$value = '';
		foreach ($parts as $part) {
			if (!$part) {
				$temp = "\0";
			} else {
				$temp = '';
				$part = new BigInteger($part);
				while (!$part->equals($zero)) {
					$submask = $part->bitwise_and($mask);
					$submask->setPrecision(8);
					$temp = (chr(0x80) | $submask->toBytes()) . $temp;
					$part = $part->bitwise_rightShift(7);
				}
				$temp[strlen($temp) - 1] = $temp[strlen($temp) - 1] & chr(0x7F);
			}
			$value .= $temp;
		}

		return $value;
	}

	private static function decodeTime($content, $tag)
	{

		$format = 'YmdHis';

		if ($tag == self::TYPE_UTC_TIME) {

			if (preg_match('#^(\d{10})(Z|[+-]\d{4})$#', $content, $matches)) {
				$content = $matches[1] . '00' . $matches[2];
			}
			$prefix = substr($content, 0, 2) >= 50 ? '19' : '20';
			$content = $prefix . $content;
		} elseif (strpos($content, '.') !== false) {
			$format .= '.u';
		}

		if ($content[strlen($content) - 1] == 'Z') {
			$content = substr($content, 0, -1) . '+0000';
		}

		if (strpos($content, '-') !== false || strpos($content, '+') !== false) {
			$format .= 'O';
		}

		return @\DateTime::createFromFormat($format, $content);
	}

	public static function setTimeFormat($format)
	{
		self::$format = $format;
	}

	public static function loadOIDs(array $oids)
	{
		self::$reverseOIDs += $oids;
		self::$oids = array_flip(self::$reverseOIDs);
	}

	public static function setFilters(array $filters)
	{
		self::$filters = $filters;
	}

	public static function convert($in, $from = self::TYPE_UTF8_STRING, $to = self::TYPE_UTF8_STRING)
	{

		if (!array_key_exists($from, self::STRING_TYPE_SIZE) || !array_key_exists($to, self::STRING_TYPE_SIZE)) {
			return false;
		}
		$insize = self::STRING_TYPE_SIZE[$from];
		$outsize = self::STRING_TYPE_SIZE[$to];
		$inlength = strlen($in);
		$out = '';

		for ($i = 0; $i < $inlength;) {
			if ($inlength - $i < $insize) {
				return false;
			}

			$c = ord($in[$i++]);
			switch (true) {
				case $insize == 4:
					$c = ($c << 8) | ord($in[$i++]);
					$c = ($c << 8) | ord($in[$i++]);

				case $insize == 2:
					$c = ($c << 8) | ord($in[$i++]);

				case $insize == 1:
					break;
				case ($c & 0x80) == 0x00:
					break;
				case ($c & 0x40) == 0x00:
					return false;
				default:
					$bit = 6;
					do {
						if ($bit > 25 || $i >= $inlength || (ord($in[$i]) & 0xC0) != 0x80) {
							return false;
						}
						$c = ($c << 6) | (ord($in[$i++]) & 0x3F);
						$bit += 5;
						$mask = 1 << $bit;
					} while ($c & $bit);
					$c &= $mask - 1;
					break;
			}

			$v = '';
			switch (true) {
				case $outsize == 4:
					$v .= chr($c & 0xFF);
					$c >>= 8;
					$v .= chr($c & 0xFF);
					$c >>= 8;

				case $outsize == 2:
					$v .= chr($c & 0xFF);
					$c >>= 8;

				case $outsize == 1:
					$v .= chr($c & 0xFF);
					$c >>= 8;
					if ($c) {
						return false;
					}
					break;
				case ($c & (PHP_INT_SIZE == 8 ? 0x80000000 : (1 << 31))) != 0:
					return false;
				case $c >= 0x04000000:
					$v .= chr(0x80 | ($c & 0x3F));
					$c = ($c >> 6) | 0x04000000;

				case $c >= 0x00200000:
					$v .= chr(0x80 | ($c & 0x3F));
					$c = ($c >> 6) | 0x00200000;

				case $c >= 0x00010000:
					$v .= chr(0x80 | ($c & 0x3F));
					$c = ($c >> 6) | 0x00010000;

				case $c >= 0x00000800:
					$v .= chr(0x80 | ($c & 0x3F));
					$c = ($c >> 6) | 0x00000800;

				case $c >= 0x00000080:
					$v .= chr(0x80 | ($c & 0x3F));
					$c = ($c >> 6) | 0x000000C0;

				default:
					$v .= chr($c);
					break;
			}
			$out .= strrev($v);
		}
		return $out;
	}

	public static function extractBER($str)
	{

		if (strlen($str) > ini_get('pcre.backtrack_limit')) {
			$temp = $str;
		} else {
			$temp = preg_replace('#.*?^-+[^-]+-+[\r\n ]*$#ms', '', $str, 1);
			$temp = preg_replace('#-+END.*[\r\n ]*.*#ms', '', $temp, 1);
		}

		$temp = str_replace(["\r", "\n", ' '], '', $temp);

		$temp = preg_replace('#^-+[^-]+-+|-+[^-]+-+$#', '', $temp);
		$temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? Strings::base64_decode($temp) : false;
		return $temp != false ? $temp : $str;
	}

	public static function encodeLength($length)
	{
		if ($length <= 0x7F) {
			return chr($length);
		}

		$temp = ltrim(pack('N', $length), chr(0));
		return pack('Ca*', 0x80 | strlen($temp), $temp);
	}

	public static function getOID($name)
	{
		return isset(self::$reverseOIDs[$name]) ? self::$reverseOIDs[$name] : $name;
	}
}
}

namespace phpseclib3\File {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\DSA;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\Hash;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\Random;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\Formats\Keys\PSS;
use phpseclib3\Exception\UnsupportedAlgorithmException;
use phpseclib3\File\ASN1\Element;
use phpseclib3\File\ASN1\Maps;
use phpseclib3\Math\BigInteger;

class X509
{

	const VALIDATE_SIGNATURE_BY_CA = 1;

	const DN_ARRAY = 0;

	const DN_STRING = 1;

	const DN_ASN1 = 2;

	const DN_OPENSSL = 3;

	const DN_CANON = 4;

	const DN_HASH = 5;

	const FORMAT_PEM = 0;

	const FORMAT_DER = 1;

	const FORMAT_SPKAC = 2;

	const FORMAT_AUTO_DETECT = 3;

	const ATTR_ALL = -1;
	const ATTR_APPEND = -2;
	const ATTR_REPLACE = -3;

	private $dn;

	private $publicKey;

	private $privateKey;

	private $CAs = [];

	private $currentCert;

	private $signatureSubject;

	private $startDate;

	private $endDate;

	private $serialNumber;

	private $currentKeyIdentifier;

	private $caFlag = false;

	private $challenge;

	private $extensionValues = [];

	private static $oidsLoaded = false;

	private static $recur_limit = 5;

	private static $disable_url_fetch = false;

	private static $extensions = [];

	private $ipAddresses = null;

	private $domains = null;

	public function __construct()
	{

		if (!self::$oidsLoaded) {

			ASN1::loadOIDs([

				'id-qt-cps' => '1.3.6.1.5.5.7.2.1',
				'id-qt-unotice' => '1.3.6.1.5.5.7.2.2',
				'id-ad-ocsp' => '1.3.6.1.5.5.7.48.1',
				'id-ad-caIssuers' => '1.3.6.1.5.5.7.48.2',
				'id-ad-timeStamping' => '1.3.6.1.5.5.7.48.3',
				'id-ad-caRepository' => '1.3.6.1.5.5.7.48.5',

				'id-at-name' => '2.5.4.41',
				'id-at-surname' => '2.5.4.4',
				'id-at-givenName' => '2.5.4.42',
				'id-at-initials' => '2.5.4.43',
				'id-at-generationQualifier' => '2.5.4.44',
				'id-at-commonName' => '2.5.4.3',
				'id-at-localityName' => '2.5.4.7',
				'id-at-stateOrProvinceName' => '2.5.4.8',
				'id-at-organizationName' => '2.5.4.10',
				'id-at-organizationalUnitName' => '2.5.4.11',
				'id-at-title' => '2.5.4.12',
				'id-at-description' => '2.5.4.13',
				'id-at-dnQualifier' => '2.5.4.46',
				'id-at-countryName' => '2.5.4.6',
				'id-at-serialNumber' => '2.5.4.5',
				'id-at-pseudonym' => '2.5.4.65',
				'id-at-postalCode' => '2.5.4.17',
				'id-at-streetAddress' => '2.5.4.9',
				'id-at-uniqueIdentifier' => '2.5.4.45',
				'id-at-role' => '2.5.4.72',
				'id-at-postalAddress' => '2.5.4.16',
				'jurisdictionOfIncorporationCountryName' => '1.3.6.1.4.1.311.60.2.1.3',
				'jurisdictionOfIncorporationStateOrProvinceName' => '1.3.6.1.4.1.311.60.2.1.2',
				'jurisdictionLocalityName' => '1.3.6.1.4.1.311.60.2.1.1',
				'id-at-businessCategory' => '2.5.4.15',

				'pkcs-9-at-emailAddress' => '1.2.840.113549.1.9.1',

				'id-ce-authorityKeyIdentifier' => '2.5.29.35',
				'id-ce-subjectKeyIdentifier' => '2.5.29.14',
				'id-ce-keyUsage' => '2.5.29.15',
				'id-ce-privateKeyUsagePeriod' => '2.5.29.16',
				'id-ce-certificatePolicies' => '2.5.29.32',

				'id-ce-policyMappings' => '2.5.29.33',

				'id-ce-subjectAltName' => '2.5.29.17',
				'id-ce-issuerAltName' => '2.5.29.18',
				'id-ce-subjectDirectoryAttributes' => '2.5.29.9',
				'id-ce-basicConstraints' => '2.5.29.19',
				'id-ce-nameConstraints' => '2.5.29.30',
				'id-ce-policyConstraints' => '2.5.29.36',
				'id-ce-cRLDistributionPoints' => '2.5.29.31',
				'id-ce-extKeyUsage' => '2.5.29.37',

				'id-kp-serverAuth' => '1.3.6.1.5.5.7.3.1',
				'id-kp-clientAuth' => '1.3.6.1.5.5.7.3.2',
				'id-kp-codeSigning' => '1.3.6.1.5.5.7.3.3',
				'id-kp-emailProtection' => '1.3.6.1.5.5.7.3.4',
				'id-kp-timeStamping' => '1.3.6.1.5.5.7.3.8',
				'id-kp-OCSPSigning' => '1.3.6.1.5.5.7.3.9',
				'id-ce-inhibitAnyPolicy' => '2.5.29.54',
				'id-ce-freshestCRL' => '2.5.29.46',
				'id-pe-authorityInfoAccess' => '1.3.6.1.5.5.7.1.1',
				'id-pe-subjectInfoAccess' => '1.3.6.1.5.5.7.1.11',
				'id-ce-cRLNumber' => '2.5.29.20',
				'id-ce-issuingDistributionPoint' => '2.5.29.28',
				'id-ce-deltaCRLIndicator' => '2.5.29.27',
				'id-ce-cRLReasons' => '2.5.29.21',
				'id-ce-certificateIssuer' => '2.5.29.29',
				'id-ce-holdInstructionCode' => '2.5.29.23',

				'id-holdinstruction-none' => '1.2.840.10040.2.1',
				'id-holdinstruction-callissuer' => '1.2.840.10040.2.2',
				'id-holdinstruction-reject' => '1.2.840.10040.2.3',
				'id-ce-invalidityDate' => '2.5.29.24',

				'rsaEncryption' => '1.2.840.113549.1.1.1',
				'md2WithRSAEncryption' => '1.2.840.113549.1.1.2',
				'md5WithRSAEncryption' => '1.2.840.113549.1.1.4',
				'sha1WithRSAEncryption' => '1.2.840.113549.1.1.5',
				'sha224WithRSAEncryption' => '1.2.840.113549.1.1.14',
				'sha256WithRSAEncryption' => '1.2.840.113549.1.1.11',
				'sha384WithRSAEncryption' => '1.2.840.113549.1.1.12',
				'sha512WithRSAEncryption' => '1.2.840.113549.1.1.13',

				'id-ecPublicKey' => '1.2.840.10045.2.1',
				'ecdsa-with-SHA1' => '1.2.840.10045.4.1',

				'ecdsa-with-SHA224' => '1.2.840.10045.4.3.1',
				'ecdsa-with-SHA256' => '1.2.840.10045.4.3.2',
				'ecdsa-with-SHA384' => '1.2.840.10045.4.3.3',
				'ecdsa-with-SHA512' => '1.2.840.10045.4.3.4',

				'id-dsa' => '1.2.840.10040.4.1',
				'id-dsa-with-sha1' => '1.2.840.10040.4.3',

				'id-dsa-with-sha224' => '2.16.840.1.101.3.4.3.1',
				'id-dsa-with-sha256' => '2.16.840.1.101.3.4.3.2',

				'id-Ed25519' => '1.3.101.112',
				'id-Ed448' => '1.3.101.113',

				'id-RSASSA-PSS' => '1.2.840.113549.1.1.10',

				'netscape' => '2.16.840.1.113730',
				'netscape-cert-extension' => '2.16.840.1.113730.1',
				'netscape-cert-type' => '2.16.840.1.113730.1.1',
				'netscape-comment' => '2.16.840.1.113730.1.13',
				'netscape-ca-policy-url' => '2.16.840.1.113730.1.8',

				'id-pe-logotype' => '1.3.6.1.5.5.7.1.12',
				'entrustVersInfo' => '1.2.840.113533.7.65.0',
				'verisignPrivate' => '2.16.840.1.113733.1.6.9',

				'pkcs-9-at-unstructuredName' => '1.2.840.113549.1.9.2',
				'pkcs-9-at-challengePassword' => '1.2.840.113549.1.9.7',
				'pkcs-9-at-extensionRequest' => '1.2.840.113549.1.9.14'
			]);
		}
	}

	public function loadX509($cert, $mode = self::FORMAT_AUTO_DETECT)
	{
		if (is_array($cert) && isset($cert['tbsCertificate'])) {
			unset($this->currentCert);
			unset($this->currentKeyIdentifier);
			$this->dn = $cert['tbsCertificate']['subject'];
			if (!isset($this->dn)) {
				return false;
			}
			$this->currentCert = $cert;

			$currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
			$this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;

			unset($this->signatureSubject);

			return $cert;
		}

		if ($mode != self::FORMAT_DER) {
			$newcert = ASN1::extractBER($cert);
			if ($mode == self::FORMAT_PEM && $cert == $newcert) {
				return false;
			}
			$cert = $newcert;
		}

		if ($cert === false) {
			$this->currentCert = false;
			return false;
		}

		$decoded = ASN1::decodeBER($cert);

		if ($decoded) {
			$x509 = ASN1::asn1map($decoded[0], Maps\Certificate::MAP);
		}
		if (!isset($x509) || $x509 === false) {
			$this->currentCert = false;
			return false;
		}

		$this->signatureSubject = substr($cert, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

		if ($this->isSubArrayValid($x509, 'tbsCertificate/extensions')) {
			$this->mapInExtensions($x509, 'tbsCertificate/extensions');
		}
		$this->mapInDNs($x509, 'tbsCertificate/issuer/rdnSequence');
		$this->mapInDNs($x509, 'tbsCertificate/subject/rdnSequence');

		$key = $x509['tbsCertificate']['subjectPublicKeyInfo'];
		$key = ASN1::encodeDER($key, Maps\SubjectPublicKeyInfo::MAP);
		$x509['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] =
			"-----BEGIN PUBLIC KEY-----\r\n" .
			chunk_split(base64_encode($key), 64) .
			"-----END PUBLIC KEY-----";

		$this->currentCert = $x509;
		$this->dn = $x509['tbsCertificate']['subject'];

		$currentKeyIdentifier = $this->getExtension('id-ce-subjectKeyIdentifier');
		$this->currentKeyIdentifier = is_string($currentKeyIdentifier) ? $currentKeyIdentifier : null;

		return $x509;
	}

	public function saveX509(array $cert, $format = self::FORMAT_PEM)
	{
		if (!is_array($cert) || !isset($cert['tbsCertificate'])) {
			return false;
		}

		switch (true) {

			case !($algorithm = $this->subArray($cert, 'tbsCertificate/subjectPublicKeyInfo/algorithm/algorithm')):
			case is_object($cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']):
				break;
			default:
				$cert['tbsCertificate']['subjectPublicKeyInfo'] = new Element(
					base64_decode(preg_replace('#-.+-|[\r\n]#', '', $cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']))
				);
		}

		$filters = [];
		$type_utf8_string = ['type' => ASN1::TYPE_UTF8_STRING];
		$filters['tbsCertificate']['signature']['parameters'] = $type_utf8_string;
		$filters['tbsCertificate']['signature']['issuer']['rdnSequence']['value'] = $type_utf8_string;
		$filters['tbsCertificate']['issuer']['rdnSequence']['value'] = $type_utf8_string;
		$filters['tbsCertificate']['subject']['rdnSequence']['value'] = $type_utf8_string;
		$filters['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['parameters'] = $type_utf8_string;
		$filters['signatureAlgorithm']['parameters'] = $type_utf8_string;
		$filters['authorityCertIssuer']['directoryName']['rdnSequence']['value'] = $type_utf8_string;

		$filters['distributionPoint']['fullName']['directoryName']['rdnSequence']['value'] = $type_utf8_string;
		$filters['directoryName']['rdnSequence']['value'] = $type_utf8_string;

		foreach (self::$extensions as $extension) {
			$filters['tbsCertificate']['extensions'][] = $extension;
		}

		$filters['policyQualifiers']['qualifier']
			= ['type' => ASN1::TYPE_IA5_STRING];

		ASN1::setFilters($filters);

		$this->mapOutExtensions($cert, 'tbsCertificate/extensions');
		$this->mapOutDNs($cert, 'tbsCertificate/issuer/rdnSequence');
		$this->mapOutDNs($cert, 'tbsCertificate/subject/rdnSequence');

		$cert = ASN1::encodeDER($cert, Maps\Certificate::MAP);

		switch ($format) {
			case self::FORMAT_DER:
				return $cert;

			default:
				return "-----BEGIN CERTIFICATE-----\r\n" . chunk_split(Strings::base64_encode($cert), 64) . '-----END CERTIFICATE-----';
		}
	}

	private function mapInExtensions(array &$root, $path)
	{
		$extensions = &$this->subArrayUnchecked($root, $path);

		if ($extensions) {
			for ($i = 0; $i < count($extensions); $i++) {
				$id = $extensions[$i]['extnId'];
				$value = &$extensions[$i]['extnValue'];

				$map = $this->getMapping($id);
				if (!is_bool($map)) {
					$decoder = $id == 'id-ce-nameConstraints' ?
						[static::class, 'decodeNameConstraintIP'] :
						[static::class, 'decodeIP'];
					$decoded = ASN1::decodeBER($value);
					if (!$decoded) {
						continue;
					}
					$mapped = ASN1::asn1map($decoded[0], $map, ['iPAddress' => $decoder]);
					$value = $mapped === false ? $decoded[0] : $mapped;

					if ($id == 'id-ce-certificatePolicies') {
						for ($j = 0; $j < count($value); $j++) {
							if (!isset($value[$j]['policyQualifiers'])) {
								continue;
							}
							for ($k = 0; $k < count($value[$j]['policyQualifiers']); $k++) {
								$subid = $value[$j]['policyQualifiers'][$k]['policyQualifierId'];
								$map = $this->getMapping($subid);
								$subvalue = &$value[$j]['policyQualifiers'][$k]['qualifier'];
								if ($map !== false) {
									$decoded = ASN1::decodeBER($subvalue);
									if (!$decoded) {
										continue;
									}
									$mapped = ASN1::asn1map($decoded[0], $map);
									$subvalue = $mapped === false ? $decoded[0] : $mapped;
								}
							}
						}
					}
				}
			}
		}
	}

	private function mapOutExtensions(array &$root, $path)
	{
		$extensions = &$this->subArray($root, $path, !empty($this->extensionValues));

		foreach ($this->extensionValues as $id => $data) {
			extract($data);
			$newext = [
				'extnId' => $id,
				'extnValue' => $value,
				'critical' => $critical
			];
			if ($replace) {
				foreach ($extensions as $key => $value) {
					if ($value['extnId'] == $id) {
						$extensions[$key] = $newext;
						continue 2;
					}
				}
			}
			$extensions[] = $newext;
		}

		if (is_array($extensions)) {
			$size = count($extensions);
			for ($i = 0; $i < $size; $i++) {
				if ($extensions[$i] instanceof Element) {
					continue;
				}

				$id = $extensions[$i]['extnId'];
				$value = &$extensions[$i]['extnValue'];

				switch ($id) {
					case 'id-ce-certificatePolicies':
						for ($j = 0; $j < count($value); $j++) {
							if (!isset($value[$j]['policyQualifiers'])) {
								continue;
							}
							for ($k = 0; $k < count($value[$j]['policyQualifiers']); $k++) {
								$subid = $value[$j]['policyQualifiers'][$k]['policyQualifierId'];
								$map = $this->getMapping($subid);
								$subvalue = &$value[$j]['policyQualifiers'][$k]['qualifier'];
								if ($map !== false) {

									$subvalue = new Element(ASN1::encodeDER($subvalue, $map));
								}
							}
						}
						break;
					case 'id-ce-authorityKeyIdentifier':
						if (isset($value['authorityCertSerialNumber'])) {
							if ($value['authorityCertSerialNumber']->toBytes() == '') {
								$temp = chr((ASN1::CLASS_CONTEXT_SPECIFIC << 6) | 2) . "\1\0";
								$value['authorityCertSerialNumber'] = new Element($temp);
							}
						}
				}

				$map = $this->getMapping($id);
				if (is_bool($map)) {
					if (!$map) {

						unset($extensions[$i]);
					}
				} else {
					$value = ASN1::encodeDER($value, $map, ['iPAddress' => [static::class, 'encodeIP']]);
				}
			}
		}
	}

	private function mapInAttributes(&$root, $path)
	{
		$attributes = &$this->subArray($root, $path);

		if (is_array($attributes)) {
			for ($i = 0; $i < count($attributes); $i++) {
				$id = $attributes[$i]['type'];

				$map = $this->getMapping($id);
				if (is_array($attributes[$i]['value'])) {
					$values = &$attributes[$i]['value'];
					for ($j = 0; $j < count($values); $j++) {
						$value = ASN1::encodeDER($values[$j], Maps\AttributeValue::MAP);
						$decoded = ASN1::decodeBER($value);
						if (!is_bool($map)) {
							if (!$decoded) {
								continue;
							}
							$mapped = ASN1::asn1map($decoded[0], $map);
							if ($mapped !== false) {
								$values[$j] = $mapped;
							}
							if ($id == 'pkcs-9-at-extensionRequest' && $this->isSubArrayValid($values, $j)) {
								$this->mapInExtensions($values, $j);
							}
						} elseif ($map) {
							$values[$j] = $value;
						}
					}
				}
			}
		}
	}

	private function mapOutAttributes(&$root, $path)
	{
		$attributes = &$this->subArray($root, $path);

		if (is_array($attributes)) {
			$size = count($attributes);
			for ($i = 0; $i < $size; $i++) {

				$id = $attributes[$i]['type'];
				$map = $this->getMapping($id);
				if ($map === false) {

					unset($attributes[$i]);
				} elseif (is_array($attributes[$i]['value'])) {
					$values = &$attributes[$i]['value'];
					for ($j = 0; $j < count($values); $j++) {
						switch ($id) {
							case 'pkcs-9-at-extensionRequest':
								$this->mapOutExtensions($values, $j);
								break;
						}

						if (!is_bool($map)) {
							$temp = ASN1::encodeDER($values[$j], $map);
							$decoded = ASN1::decodeBER($temp);
							if (!$decoded) {
								continue;
							}
							$values[$j] = ASN1::asn1map($decoded[0], Maps\AttributeValue::MAP);
						}
					}
				}
			}
		}
	}

	private function mapInDNs(array &$root, $path)
	{
		$dns = &$this->subArray($root, $path);

		if (is_array($dns)) {
			for ($i = 0; $i < count($dns); $i++) {
				for ($j = 0; $j < count($dns[$i]); $j++) {
					$type = $dns[$i][$j]['type'];
					$value = &$dns[$i][$j]['value'];
					if (is_object($value) && $value instanceof Element) {
						$map = $this->getMapping($type);
						if (!is_bool($map)) {
							$decoded = ASN1::decodeBER($value);
							if (!$decoded) {
								continue;
							}
							$value = ASN1::asn1map($decoded[0], $map);
						}
					}
				}
			}
		}
	}

	private function mapOutDNs(array &$root, $path)
	{
		$dns = &$this->subArray($root, $path);

		if (is_array($dns)) {
			$size = count($dns);
			for ($i = 0; $i < $size; $i++) {
				for ($j = 0; $j < count($dns[$i]); $j++) {
					$type = $dns[$i][$j]['type'];
					$value = &$dns[$i][$j]['value'];
					if (is_object($value) && $value instanceof Element) {
						continue;
					}

					$map = $this->getMapping($type);
					if (!is_bool($map)) {
						$value = new Element(ASN1::encodeDER($value, $map));
					}
				}
			}
		}
	}

	private function getMapping($extnId)
	{
		if (!is_string($extnId)) {
			return true;
		}

		if (isset(self::$extensions[$extnId])) {
			return self::$extensions[$extnId];
		}

		switch ($extnId) {
			case 'id-ce-keyUsage':
				return Maps\KeyUsage::MAP;
			case 'id-ce-basicConstraints':
				return Maps\BasicConstraints::MAP;
			case 'id-ce-subjectKeyIdentifier':
				return Maps\KeyIdentifier::MAP;
			case 'id-ce-cRLDistributionPoints':
				return Maps\CRLDistributionPoints::MAP;
			case 'id-ce-authorityKeyIdentifier':
				return Maps\AuthorityKeyIdentifier::MAP;
			case 'id-ce-certificatePolicies':
				return Maps\CertificatePolicies::MAP;
			case 'id-ce-extKeyUsage':
				return Maps\ExtKeyUsageSyntax::MAP;
			case 'id-pe-authorityInfoAccess':
				return Maps\AuthorityInfoAccessSyntax::MAP;
			case 'id-ce-subjectAltName':
				return Maps\SubjectAltName::MAP;
			case 'id-ce-subjectDirectoryAttributes':
				return Maps\SubjectDirectoryAttributes::MAP;
			case 'id-ce-privateKeyUsagePeriod':
				return Maps\PrivateKeyUsagePeriod::MAP;
			case 'id-ce-issuerAltName':
				return Maps\IssuerAltName::MAP;
			case 'id-ce-policyMappings':
				return Maps\PolicyMappings::MAP;
			case 'id-ce-nameConstraints':
				return Maps\NameConstraints::MAP;

			case 'netscape-cert-type':
				return Maps\netscape_cert_type::MAP;
			case 'netscape-comment':
				return Maps\netscape_comment::MAP;
			case 'netscape-ca-policy-url':
				return Maps\netscape_ca_policy_url::MAP;

			case 'id-qt-unotice':
				return Maps\UserNotice::MAP;

			case 'id-pe-logotype':
			case 'entrustVersInfo':

			case '1.3.6.1.4.1.311.20.2':
			case '1.3.6.1.4.1.311.21.1':

			case '2.23.42.7.0':

			case '1.3.6.1.4.1.11129.2.4.2':

			case '1.3.6.1.5.5.7.1.3':
				return true;

			case 'pkcs-9-at-unstructuredName':
				return Maps\PKCS9String::MAP;
			case 'pkcs-9-at-challengePassword':
				return Maps\DirectoryString::MAP;
			case 'pkcs-9-at-extensionRequest':
				return Maps\Extensions::MAP;

			case 'id-ce-cRLNumber':
				return Maps\CRLNumber::MAP;
			case 'id-ce-deltaCRLIndicator':
				return Maps\CRLNumber::MAP;
			case 'id-ce-issuingDistributionPoint':
				return Maps\IssuingDistributionPoint::MAP;
			case 'id-ce-freshestCRL':
				return Maps\CRLDistributionPoints::MAP;
			case 'id-ce-cRLReasons':
				return Maps\CRLReason::MAP;
			case 'id-ce-invalidityDate':
				return Maps\InvalidityDate::MAP;
			case 'id-ce-certificateIssuer':
				return Maps\CertificateIssuer::MAP;
			case 'id-ce-holdInstructionCode':
				return Maps\HoldInstructionCode::MAP;
			case 'id-at-postalAddress':
				return Maps\PostalAddress::MAP;
		}

		return false;
	}

	public function loadCA($cert)
	{
		$olddn = $this->dn;
		$oldcert = $this->currentCert;
		$oldsigsubj = $this->signatureSubject;
		$oldkeyid = $this->currentKeyIdentifier;

		$cert = $this->loadX509($cert);
		if (!$cert) {
			$this->dn = $olddn;
			$this->currentCert = $oldcert;
			$this->signatureSubject = $oldsigsubj;
			$this->currentKeyIdentifier = $oldkeyid;

			return false;
		}

		$this->CAs[] = $cert;

		$this->dn = $olddn;
		$this->currentCert = $oldcert;
		$this->signatureSubject = $oldsigsubj;

		return true;
	}

	public function validateURL($url)
	{
		if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
			return false;
		}

		$components = parse_url($url);
		if (!isset($components['host'])) {
			return false;
		}

		if ($names = $this->getExtension('id-ce-subjectAltName')) {
			foreach ($names as $name) {
				foreach ($name as $key => $value) {
					$value = preg_quote($value);
					$value = str_replace('\*', '[^.]*', $value);
					switch ($key) {
						case 'dNSName':

							if (preg_match('#^' . $value . '$#', $components['host'])) {
								return true;
							}
							break;
						case 'iPAddress':

							if (preg_match('#(?:\d{1-3}\.){4}#', $components['host'] . '.') && preg_match('#^' . $value . '$#', $components['host'])) {
								return true;
							}
					}
				}
			}
			return false;
		}

		if ($value = $this->getDNProp('id-at-commonName')) {
			$value = str_replace(['.', '*'], ['\.', '[^.]*'], $value[0]);
			return preg_match('#^' . $value . '$#', $components['host']) === 1;
		}

		return false;
	}

	public function validateDate($date = null)
	{
		if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
			return false;
		}

		if (!isset($date)) {
			$date = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
		}

		$notBefore = $this->currentCert['tbsCertificate']['validity']['notBefore'];
		$notBefore = isset($notBefore['generalTime']) ? $notBefore['generalTime'] : $notBefore['utcTime'];

		$notAfter = $this->currentCert['tbsCertificate']['validity']['notAfter'];
		$notAfter = isset($notAfter['generalTime']) ? $notAfter['generalTime'] : $notAfter['utcTime'];

		if (is_string($date)) {
			$date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
		}

		$notBefore = new \DateTimeImmutable($notBefore, new \DateTimeZone(@date_default_timezone_get()));
		$notAfter = new \DateTimeImmutable($notAfter, new \DateTimeZone(@date_default_timezone_get()));

		return $date >= $notBefore && $date <= $notAfter;
	}

	private static function fetchURL($url)
	{
		if (self::$disable_url_fetch) {
			return false;
		}

		$parts = parse_url($url);
		$data = '';
		switch ($parts['scheme']) {
			case 'http':
				$fsock = @fsockopen($parts['host'], isset($parts['port']) ? $parts['port'] : 80);
				if (!$fsock) {
					return false;
				}
				$path = $parts['path'];
				if (isset($parts['query'])) {
					$path .= '?' . $parts['query'];
				}
				fputs($fsock, "GET $path HTTP/1.0\r\n");
				fputs($fsock, "Host: $parts[host]\r\n\r\n");
				$line = fgets($fsock, 1024);
				if (strlen($line) < 3) {
					return false;
				}
				preg_match('#HTTP/1.\d (\d{3})#', $line, $temp);
				if ($temp[1] != '200') {
					return false;
				}

				while (!feof($fsock) && fgets($fsock, 1024) != "\r\n") {
				}

				while (!feof($fsock)) {
					$temp = fread($fsock, 1024);
					if ($temp === false) {
						return false;
					}
					$data .= $temp;
				}

				break;

		}

		return $data;
	}

	private function testForIntermediate($caonly, $count)
	{
		$opts = $this->getExtension('id-pe-authorityInfoAccess');
		if (!is_array($opts)) {
			return false;
		}
		foreach ($opts as $opt) {
			if ($opt['accessMethod'] == 'id-ad-caIssuers') {

				if (isset($opt['accessLocation']['uniformResourceIdentifier'])) {
					$url = $opt['accessLocation']['uniformResourceIdentifier'];
					break;
				}
			}
		}

		if (!isset($url)) {
			return false;
		}

		$cert = static::fetchURL($url);
		if (!is_string($cert)) {
			return false;
		}

		$parent = new static();
		$parent->CAs = $this->CAs;

		if (!is_array($parent->loadX509($cert))) {
			return false;
		}

		if (!$parent->validateSignatureCountable($caonly, ++$count)) {
			return false;
		}

		$this->CAs[] = $parent->currentCert;

		return true;
	}

	public function validateSignature($caonly = true)
	{
		return $this->validateSignatureCountable($caonly, 0);
	}

	private function validateSignatureCountable($caonly, $count)
	{
		if (!is_array($this->currentCert) || !isset($this->signatureSubject)) {
			return null;
		}

		if ($count == self::$recur_limit) {
			return false;
		}

		switch (true) {
			case isset($this->currentCert['tbsCertificate']):

				switch (true) {
					case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $this->currentCert['tbsCertificate']['subject']:
					case defined('FILE_X509_IGNORE_TYPE') && $this->getIssuerDN(self::DN_STRING) === $this->getDN(self::DN_STRING):
						$authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
						$subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier');
						switch (true) {
							case !is_array($authorityKey):
							case !$subjectKeyID:
							case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
								$signingCert = $this->currentCert;
						}
				}

				if (!empty($this->CAs)) {
					for ($i = 0; $i < count($this->CAs); $i++) {

						$ca = $this->CAs[$i];
						switch (true) {
							case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']:
							case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(self::DN_STRING, $this->currentCert['tbsCertificate']['issuer']) === $this->getDN(self::DN_STRING, $ca['tbsCertificate']['subject']):
								$authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
								$subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
								switch (true) {
									case !is_array($authorityKey):
									case !$subjectKeyID:
									case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
										if (is_array($authorityKey) && isset($authorityKey['authorityCertSerialNumber']) && !$authorityKey['authorityCertSerialNumber']->equals($ca['tbsCertificate']['serialNumber'])) {
											break 2;
										}
										$signingCert = $ca;
										break 3;
								}
						}
					}
					if (count($this->CAs) == $i && $caonly) {
						return $this->testForIntermediate($caonly, $count) && $this->validateSignature($caonly);
					}
				} elseif (!isset($signingCert) || $caonly) {
					return $this->testForIntermediate($caonly, $count) && $this->validateSignature($caonly);
				}
				return $this->validateSignatureHelper(
					$signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
					$signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
					$this->currentCert['signatureAlgorithm']['algorithm'],
					substr($this->currentCert['signature'], 1),
					$this->signatureSubject
				);
			case isset($this->currentCert['certificationRequestInfo']):
				return $this->validateSignatureHelper(
					$this->currentCert['certificationRequestInfo']['subjectPKInfo']['algorithm']['algorithm'],
					$this->currentCert['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'],
					$this->currentCert['signatureAlgorithm']['algorithm'],
					substr($this->currentCert['signature'], 1),
					$this->signatureSubject
				);
			case isset($this->currentCert['publicKeyAndChallenge']):
				return $this->validateSignatureHelper(
					$this->currentCert['publicKeyAndChallenge']['spki']['algorithm']['algorithm'],
					$this->currentCert['publicKeyAndChallenge']['spki']['subjectPublicKey'],
					$this->currentCert['signatureAlgorithm']['algorithm'],
					substr($this->currentCert['signature'], 1),
					$this->signatureSubject
				);
			case isset($this->currentCert['tbsCertList']):
				if (!empty($this->CAs)) {
					for ($i = 0; $i < count($this->CAs); $i++) {
						$ca = $this->CAs[$i];
						switch (true) {
							case !defined('FILE_X509_IGNORE_TYPE') && $this->currentCert['tbsCertList']['issuer'] === $ca['tbsCertificate']['subject']:
							case defined('FILE_X509_IGNORE_TYPE') && $this->getDN(self::DN_STRING, $this->currentCert['tbsCertList']['issuer']) === $this->getDN(self::DN_STRING, $ca['tbsCertificate']['subject']):
								$authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier');
								$subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
								switch (true) {
									case !is_array($authorityKey):
									case !$subjectKeyID:
									case isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
										if (is_array($authorityKey) && isset($authorityKey['authorityCertSerialNumber']) && !$authorityKey['authorityCertSerialNumber']->equals($ca['tbsCertificate']['serialNumber'])) {
											break 2;
										}
										$signingCert = $ca;
										break 3;
								}
						}
					}
				}
				if (!isset($signingCert)) {
					return false;
				}
				return $this->validateSignatureHelper(
					$signingCert['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['algorithm'],
					$signingCert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'],
					$this->currentCert['signatureAlgorithm']['algorithm'],
					substr($this->currentCert['signature'], 1),
					$this->signatureSubject
				);
			default:
				return false;
		}
	}

	private function validateSignatureHelper($publicKeyAlgorithm, $publicKey, $signatureAlgorithm, $signature, $signatureSubject)
	{
		switch ($publicKeyAlgorithm) {
			case 'id-RSASSA-PSS':
				$key = RSA::loadFormat('PSS', $publicKey);
				break;
			case 'rsaEncryption':
				$key = RSA::loadFormat('PKCS8', $publicKey);
				switch ($signatureAlgorithm) {
					case 'id-RSASSA-PSS':
						break;
					case 'md2WithRSAEncryption':
					case 'md5WithRSAEncryption':
					case 'sha1WithRSAEncryption':
					case 'sha224WithRSAEncryption':
					case 'sha256WithRSAEncryption':
					case 'sha384WithRSAEncryption':
					case 'sha512WithRSAEncryption':
						$key = $key
							->withHash(preg_replace('#WithRSAEncryption$#', '', $signatureAlgorithm))
							->withPadding(RSA::SIGNATURE_PKCS1);
						break;
					default:
						throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
				}
				break;
			case 'id-Ed25519':
			case 'id-Ed448':
				$key = EC::loadFormat('PKCS8', $publicKey);
				break;
			case 'id-ecPublicKey':
				$key = EC::loadFormat('PKCS8', $publicKey);
				switch ($signatureAlgorithm) {
					case 'ecdsa-with-SHA1':
					case 'ecdsa-with-SHA224':
					case 'ecdsa-with-SHA256':
					case 'ecdsa-with-SHA384':
					case 'ecdsa-with-SHA512':
						$key = $key
							->withHash(preg_replace('#^ecdsa-with-#', '', strtolower($signatureAlgorithm)));
						break;
					default:
						throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
				}
				break;
			case 'id-dsa':
				$key = DSA::loadFormat('PKCS8', $publicKey);
				switch ($signatureAlgorithm) {
					case 'id-dsa-with-sha1':
					case 'id-dsa-with-sha224':
					case 'id-dsa-with-sha256':
						$key = $key
							->withHash(preg_replace('#^id-dsa-with-#', '', strtolower($signatureAlgorithm)));
						break;
					default:
						throw new UnsupportedAlgorithmException('Signature algorithm unsupported');
				}
				break;
			default:
				throw new UnsupportedAlgorithmException('Public key algorithm unsupported');
		}

		return $key->verify($signatureSubject, $signature);
	}

	public static function setRecurLimit($count)
	{
		self::$recur_limit = $count;
	}

	public static function disableURLFetch()
	{
		self::$disable_url_fetch = true;
	}

	public static function enableURLFetch()
	{
		self::$disable_url_fetch = false;
	}

	public static function decodeIP($ip)
	{
		return inet_ntop($ip);
	}

	public static function decodeNameConstraintIP($ip)
	{
		$size = strlen($ip) >> 1;
		$mask = substr($ip, $size);
		$ip = substr($ip, 0, $size);
		return [inet_ntop($ip), inet_ntop($mask)];
	}

	public static function encodeIP($ip)
	{
		return is_string($ip) ?
			inet_pton($ip) :
			inet_pton($ip[0]) . inet_pton($ip[1]);
	}

	private function translateDNProp($propName)
	{
		switch (strtolower($propName)) {
			case 'jurisdictionofincorporationcountryname':
			case 'jurisdictioncountryname':
			case 'jurisdictionc':
				return 'jurisdictionOfIncorporationCountryName';
			case 'jurisdictionofincorporationstateorprovincename':
			case 'jurisdictionstateorprovincename':
			case 'jurisdictionst':
				return 'jurisdictionOfIncorporationStateOrProvinceName';
			case 'jurisdictionlocalityname':
			case 'jurisdictionl':
				return 'jurisdictionLocalityName';
			case 'id-at-businesscategory':
			case 'businesscategory':
				return 'id-at-businessCategory';
			case 'id-at-countryname':
			case 'countryname':
			case 'c':
				return 'id-at-countryName';
			case 'id-at-organizationname':
			case 'organizationname':
			case 'o':
				return 'id-at-organizationName';
			case 'id-at-dnqualifier':
			case 'dnqualifier':
				return 'id-at-dnQualifier';
			case 'id-at-commonname':
			case 'commonname':
			case 'cn':
				return 'id-at-commonName';
			case 'id-at-stateorprovincename':
			case 'stateorprovincename':
			case 'state':
			case 'province':
			case 'provincename':
			case 'st':
				return 'id-at-stateOrProvinceName';
			case 'id-at-localityname':
			case 'localityname':
			case 'l':
				return 'id-at-localityName';
			case 'id-emailaddress':
			case 'emailaddress':
				return 'pkcs-9-at-emailAddress';
			case 'id-at-serialnumber':
			case 'serialnumber':
				return 'id-at-serialNumber';
			case 'id-at-postalcode':
			case 'postalcode':
				return 'id-at-postalCode';
			case 'id-at-streetaddress':
			case 'streetaddress':
				return 'id-at-streetAddress';
			case 'id-at-name':
			case 'name':
				return 'id-at-name';
			case 'id-at-givenname':
			case 'givenname':
				return 'id-at-givenName';
			case 'id-at-surname':
			case 'surname':
			case 'sn':
				return 'id-at-surname';
			case 'id-at-initials':
			case 'initials':
				return 'id-at-initials';
			case 'id-at-generationqualifier':
			case 'generationqualifier':
				return 'id-at-generationQualifier';
			case 'id-at-organizationalunitname':
			case 'organizationalunitname':
			case 'ou':
				return 'id-at-organizationalUnitName';
			case 'id-at-pseudonym':
			case 'pseudonym':
				return 'id-at-pseudonym';
			case 'id-at-title':
			case 'title':
				return 'id-at-title';
			case 'id-at-description':
			case 'description':
				return 'id-at-description';
			case 'id-at-role':
			case 'role':
				return 'id-at-role';
			case 'id-at-uniqueidentifier':
			case 'uniqueidentifier':
			case 'x500uniqueidentifier':
				return 'id-at-uniqueIdentifier';
			case 'postaladdress':
			case 'id-at-postaladdress':
				return 'id-at-postalAddress';
			default:
				return false;
		}
	}

	public function setDNProp($propName, $propValue, $type = 'utf8String')
	{
		if (empty($this->dn)) {
			$this->dn = ['rdnSequence' => []];
		}

		if (($propName = $this->translateDNProp($propName)) === false) {
			return false;
		}

		foreach ((array) $propValue as $v) {
			if (!is_array($v) && isset($type)) {
				$v = [$type => $v];
			}
			$this->dn['rdnSequence'][] = [
				[
					'type' => $propName,
					'value' => $v
				]
			];
		}

		return true;
	}

	public function removeDNProp($propName)
	{
		if (empty($this->dn)) {
			return;
		}

		if (($propName = $this->translateDNProp($propName)) === false) {
			return;
		}

		$dn = &$this->dn['rdnSequence'];
		$size = count($dn);
		for ($i = 0; $i < $size; $i++) {
			if ($dn[$i][0]['type'] == $propName) {
				unset($dn[$i]);
			}
		}

		$dn = array_values($dn);

		if (!isset($dn[0])) {
			$dn = array_splice($dn, 0, 0);
		}
	}

	public function getDNProp($propName, $dn = null, $withType = false)
	{
		if (!isset($dn)) {
			$dn = $this->dn;
		}

		if (empty($dn)) {
			return false;
		}

		if (($propName = $this->translateDNProp($propName)) === false) {
			return false;
		}

		$filters = [];
		$filters['value'] = ['type' => ASN1::TYPE_UTF8_STRING];
		ASN1::setFilters($filters);
		$this->mapOutDNs($dn, 'rdnSequence');
		$dn = $dn['rdnSequence'];
		$result = [];
		for ($i = 0; $i < count($dn); $i++) {
			if ($dn[$i][0]['type'] == $propName) {
				$v = $dn[$i][0]['value'];
				if (!$withType) {
					if (is_array($v)) {
						foreach ($v as $type => $s) {
							$type = array_search($type, ASN1::ANY_MAP);
							if ($type !== false && array_key_exists($type, ASN1::STRING_TYPE_SIZE)) {
								$s = ASN1::convert($s, $type);
								if ($s !== false) {
									$v = $s;
									break;
								}
							}
						}
						if (is_array($v)) {
							$v = array_pop($v);
						}
					} elseif (is_object($v) && $v instanceof Element) {
						$map = $this->getMapping($propName);
						if (!is_bool($map)) {
							$decoded = ASN1::decodeBER($v);
							if (!$decoded) {
								return false;
							}
							$v = ASN1::asn1map($decoded[0], $map);
						}
					}
				}
				$result[] = $v;
			}
		}

		return $result;
	}

	public function setDN($dn, $merge = false, $type = 'utf8String')
	{
		if (!$merge) {
			$this->dn = null;
		}

		if (is_array($dn)) {
			if (isset($dn['rdnSequence'])) {
				$this->dn = $dn;
				return true;
			}

			foreach ($dn as $prop => $value) {
				if (!$this->setDNProp($prop, $value, $type)) {
					return false;
				}
			}
			return true;
		}

		$results = preg_split('#((?:^|, *|/)(?:C=|O=|OU=|CN=|L=|ST=|SN=|postalCode=|streetAddress=|emailAddress=|serialNumber=|organizationalUnitName=|title=|description=|role=|x500UniqueIdentifier=|postalAddress=))#', $dn, -1, PREG_SPLIT_DELIM_CAPTURE);
		for ($i = 1; $i < count($results); $i += 2) {
			$prop = trim($results[$i], ', =/');
			$value = $results[$i + 1];
			if (!$this->setDNProp($prop, $value, $type)) {
				return false;
			}
		}

		return true;
	}

	public function getDN($format = self::DN_ARRAY, $dn = null)
	{
		if (!isset($dn)) {
			$dn = isset($this->currentCert['tbsCertList']) ? $this->currentCert['tbsCertList']['issuer'] : $this->dn;
		}

		switch ((int) $format) {
			case self::DN_ARRAY:
				return $dn;
			case self::DN_ASN1:
				$filters = [];
				$filters['rdnSequence']['value'] = ['type' => ASN1::TYPE_UTF8_STRING];
				ASN1::setFilters($filters);
				$this->mapOutDNs($dn, 'rdnSequence');
				return ASN1::encodeDER($dn, Maps\Name::MAP);
			case self::DN_CANON:

				$filters = [];
				$filters['value'] = ['type' => ASN1::TYPE_UTF8_STRING];
				ASN1::setFilters($filters);
				$result = '';
				$this->mapOutDNs($dn, 'rdnSequence');
				foreach ($dn['rdnSequence'] as $rdn) {
					foreach ($rdn as $i => $attr) {
						$attr = &$rdn[$i];
						if (is_array($attr['value'])) {
							foreach ($attr['value'] as $type => $v) {
								$type = array_search($type, ASN1::ANY_MAP, true);
								if ($type !== false && array_key_exists($type, ASN1::STRING_TYPE_SIZE)) {
									$v = ASN1::convert($v, $type);
									if ($v !== false) {
										$v = preg_replace('/\s+/', ' ', $v);
										$attr['value'] = strtolower(trim($v));
										break;
									}
								}
							}
						}
					}
					$result .= ASN1::encodeDER($rdn, Maps\RelativeDistinguishedName::MAP);
				}
				return $result;
			case self::DN_HASH:
				$dn = $this->getDN(self::DN_CANON, $dn);
				$hash = new Hash('sha1');
				$hash = $hash->hash($dn);
				extract(unpack('Vhash', $hash));
				return strtolower(Strings::bin2hex(pack('N', $hash)));
		}

		$start = true;
		$output = '';

		$result = [];
		$filters = [];
		$filters['rdnSequence']['value'] = ['type' => ASN1::TYPE_UTF8_STRING];
		ASN1::setFilters($filters);
		$this->mapOutDNs($dn, 'rdnSequence');

		foreach ($dn['rdnSequence'] as $field) {
			$prop = $field[0]['type'];
			$value = $field[0]['value'];

			$delim = ', ';
			switch ($prop) {
				case 'id-at-countryName':
					$desc = 'C';
					break;
				case 'id-at-stateOrProvinceName':
					$desc = 'ST';
					break;
				case 'id-at-organizationName':
					$desc = 'O';
					break;
				case 'id-at-organizationalUnitName':
					$desc = 'OU';
					break;
				case 'id-at-commonName':
					$desc = 'CN';
					break;
				case 'id-at-localityName':
					$desc = 'L';
					break;
				case 'id-at-surname':
					$desc = 'SN';
					break;
				case 'id-at-uniqueIdentifier':
					$delim = '/';
					$desc = 'x500UniqueIdentifier';
					break;
				case 'id-at-postalAddress':
					$delim = '/';
					$desc = 'postalAddress';
					break;
				default:
					$delim = '/';
					$desc = preg_replace('#.+-([^-]+)$#', '$1', $prop);
			}

			if (!$start) {
				$output .= $delim;
			}
			if (is_array($value)) {
				foreach ($value as $type => $v) {
					$type = array_search($type, ASN1::ANY_MAP, true);
					if ($type !== false && array_key_exists($type, ASN1::STRING_TYPE_SIZE)) {
						$v = ASN1::convert($v, $type);
						if ($v !== false) {
							$value = $v;
							break;
						}
					}
				}
				if (is_array($value)) {
					$value = array_pop($value);
				}
			} elseif (is_object($value) && $value instanceof Element) {
				$callback = function ($x) {
					return '\x' . bin2hex($x[0]);
				};
				$value = strtoupper(preg_replace_callback('#[^\x20-\x7E]#', $callback, $value->element));
			}
			$output .= $desc . '=' . $value;
			$result[$desc] = isset($result[$desc]) ?
				array_merge((array) $result[$desc], [$value]) :
				$value;
			$start = false;
		}

		return $format == self::DN_OPENSSL ? $result : $output;
	}

	public function getIssuerDN($format = self::DN_ARRAY)
	{
		switch (true) {
			case !isset($this->currentCert) || !is_array($this->currentCert):
				break;
			case isset($this->currentCert['tbsCertificate']):
				return $this->getDN($format, $this->currentCert['tbsCertificate']['issuer']);
			case isset($this->currentCert['tbsCertList']):
				return $this->getDN($format, $this->currentCert['tbsCertList']['issuer']);
		}

		return false;
	}

	public function getSubjectDN($format = self::DN_ARRAY)
	{
		switch (true) {
			case !empty($this->dn):
				return $this->getDN($format);
			case !isset($this->currentCert) || !is_array($this->currentCert):
				break;
			case isset($this->currentCert['tbsCertificate']):
				return $this->getDN($format, $this->currentCert['tbsCertificate']['subject']);
			case isset($this->currentCert['certificationRequestInfo']):
				return $this->getDN($format, $this->currentCert['certificationRequestInfo']['subject']);
		}

		return false;
	}

	public function getIssuerDNProp($propName, $withType = false)
	{
		switch (true) {
			case !isset($this->currentCert) || !is_array($this->currentCert):
				break;
			case isset($this->currentCert['tbsCertificate']):
				return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['issuer'], $withType);
			case isset($this->currentCert['tbsCertList']):
				return $this->getDNProp($propName, $this->currentCert['tbsCertList']['issuer'], $withType);
		}

		return false;
	}

	public function getSubjectDNProp($propName, $withType = false)
	{
		switch (true) {
			case !empty($this->dn):
				return $this->getDNProp($propName, null, $withType);
			case !isset($this->currentCert) || !is_array($this->currentCert):
				break;
			case isset($this->currentCert['tbsCertificate']):
				return $this->getDNProp($propName, $this->currentCert['tbsCertificate']['subject'], $withType);
			case isset($this->currentCert['certificationRequestInfo']):
				return $this->getDNProp($propName, $this->currentCert['certificationRequestInfo']['subject'], $withType);
		}

		return false;
	}

	public function getChain()
	{
		$chain = [$this->currentCert];

		if (!is_array($this->currentCert) || !isset($this->currentCert['tbsCertificate'])) {
			return false;
		}
		while (true) {
			$currentCert = $chain[count($chain) - 1];
			for ($i = 0; $i < count($this->CAs); $i++) {
				$ca = $this->CAs[$i];
				if ($currentCert['tbsCertificate']['issuer'] === $ca['tbsCertificate']['subject']) {
					$authorityKey = $this->getExtension('id-ce-authorityKeyIdentifier', $currentCert);
					$subjectKeyID = $this->getExtension('id-ce-subjectKeyIdentifier', $ca);
					switch (true) {
						case !is_array($authorityKey):
						case is_array($authorityKey) && isset($authorityKey['keyIdentifier']) && $authorityKey['keyIdentifier'] === $subjectKeyID:
							if ($currentCert === $ca) {
								break 3;
							}
							$chain[] = $ca;
							break 2;
					}
				}
			}
			if ($i == count($this->CAs)) {
				break;
			}
		}
		foreach ($chain as $key => $value) {
			$chain[$key] = new X509();
			$chain[$key]->loadX509($value);
		}
		return $chain;
	}

	public function &getCurrentCert()
	{
		return $this->currentCert;
	}

	public function setPublicKey(PublicKey $key)
	{
		$this->publicKey = $key;
	}

	public function setPrivateKey(PrivateKey $key)
	{
		$this->privateKey = $key;
	}

	public function setChallenge($challenge)
	{
		$this->challenge = $challenge;
	}

	public function getPublicKey()
	{
		if (isset($this->publicKey)) {
			return $this->publicKey;
		}

		if (isset($this->currentCert) && is_array($this->currentCert)) {
			$paths = [
				'tbsCertificate/subjectPublicKeyInfo',
				'certificationRequestInfo/subjectPKInfo',
				'publicKeyAndChallenge/spki'
			];
			foreach ($paths as $path) {
				$keyinfo = $this->subArray($this->currentCert, $path);
				if (!empty($keyinfo)) {
					break;
				}
			}
		}
		if (empty($keyinfo)) {
			return false;
		}

		$key = $keyinfo['subjectPublicKey'];

		switch ($keyinfo['algorithm']['algorithm']) {
			case 'id-RSASSA-PSS':
				return RSA::loadFormat('PSS', $key);
			case 'rsaEncryption':
				return RSA::loadFormat('PKCS8', $key)->withPadding(RSA::SIGNATURE_PKCS1);
			case 'id-ecPublicKey':
			case 'id-Ed25519':
			case 'id-Ed448':
				return EC::loadFormat('PKCS8', $key);
			case 'id-dsa':
				return DSA::loadFormat('PKCS8', $key);
		}

		return false;
	}

	public function loadCSR($csr, $mode = self::FORMAT_AUTO_DETECT)
	{
		if (is_array($csr) && isset($csr['certificationRequestInfo'])) {
			unset($this->currentCert);
			unset($this->currentKeyIdentifier);
			unset($this->signatureSubject);
			$this->dn = $csr['certificationRequestInfo']['subject'];
			if (!isset($this->dn)) {
				return false;
			}

			$this->currentCert = $csr;
			return $csr;
		}

		if ($mode != self::FORMAT_DER) {
			$newcsr = ASN1::extractBER($csr);
			if ($mode == self::FORMAT_PEM && $csr == $newcsr) {
				return false;
			}
			$csr = $newcsr;
		}
		$orig = $csr;

		if ($csr === false) {
			$this->currentCert = false;
			return false;
		}

		$decoded = ASN1::decodeBER($csr);

		if (!$decoded) {
			$this->currentCert = false;
			return false;
		}

		$csr = ASN1::asn1map($decoded[0], Maps\CertificationRequest::MAP);
		if (!isset($csr) || $csr === false) {
			$this->currentCert = false;
			return false;
		}

		$this->mapInAttributes($csr, 'certificationRequestInfo/attributes');
		$this->mapInDNs($csr, 'certificationRequestInfo/subject/rdnSequence');

		$this->dn = $csr['certificationRequestInfo']['subject'];

		$this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

		$key = $csr['certificationRequestInfo']['subjectPKInfo'];
		$key = ASN1::encodeDER($key, Maps\SubjectPublicKeyInfo::MAP);
		$csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'] =
			"-----BEGIN PUBLIC KEY-----\r\n" .
			chunk_split(base64_encode($key), 64) .
			"-----END PUBLIC KEY-----";

		$this->currentKeyIdentifier = null;
		$this->currentCert = $csr;

		$this->publicKey = null;
		$this->publicKey = $this->getPublicKey();

		return $csr;
	}

	public function saveCSR(array $csr, $format = self::FORMAT_PEM)
	{
		if (!is_array($csr) || !isset($csr['certificationRequestInfo'])) {
			return false;
		}

		switch (true) {
			case !($algorithm = $this->subArray($csr, 'certificationRequestInfo/subjectPKInfo/algorithm/algorithm')):
			case is_object($csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']):
				break;
			default:
				$csr['certificationRequestInfo']['subjectPKInfo'] = new Element(
					base64_decode(preg_replace('#-.+-|[\r\n]#', '', $csr['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']))
				);
		}

		$filters = [];
		$filters['certificationRequestInfo']['subject']['rdnSequence']['value']
			= ['type' => ASN1::TYPE_UTF8_STRING];

		ASN1::setFilters($filters);

		$this->mapOutDNs($csr, 'certificationRequestInfo/subject/rdnSequence');
		$this->mapOutAttributes($csr, 'certificationRequestInfo/attributes');
		$csr = ASN1::encodeDER($csr, Maps\CertificationRequest::MAP);

		switch ($format) {
			case self::FORMAT_DER:
				return $csr;

			default:
				return "-----BEGIN CERTIFICATE REQUEST-----\r\n" . chunk_split(Strings::base64_encode($csr), 64) . '-----END CERTIFICATE REQUEST-----';
		}
	}

	public function loadSPKAC($spkac)
	{
		if (is_array($spkac) && isset($spkac['publicKeyAndChallenge'])) {
			unset($this->currentCert);
			unset($this->currentKeyIdentifier);
			unset($this->signatureSubject);
			$this->currentCert = $spkac;
			return $spkac;
		}

		$temp = preg_replace('#(?:SPKAC=)|[ \r\n\\\]#', '', $spkac);
		$temp = preg_match('#^[a-zA-Z\d/+]*={0,2}$#', $temp) ? Strings::base64_decode($temp) : false;
		if ($temp != false) {
			$spkac = $temp;
		}
		$orig = $spkac;

		if ($spkac === false) {
			$this->currentCert = false;
			return false;
		}

		$decoded = ASN1::decodeBER($spkac);

		if (!$decoded) {
			$this->currentCert = false;
			return false;
		}

		$spkac = ASN1::asn1map($decoded[0], Maps\SignedPublicKeyAndChallenge::MAP);

		if (!isset($spkac) || !is_array($spkac)) {
			$this->currentCert = false;
			return false;
		}

		$this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

		$key = $spkac['publicKeyAndChallenge']['spki'];
		$key = ASN1::encodeDER($key, Maps\SubjectPublicKeyInfo::MAP);
		$spkac['publicKeyAndChallenge']['spki']['subjectPublicKey'] =
			"-----BEGIN PUBLIC KEY-----\r\n" .
			chunk_split(base64_encode($key), 64) .
			"-----END PUBLIC KEY-----";

		$this->currentKeyIdentifier = null;
		$this->currentCert = $spkac;

		$this->publicKey = null;
		$this->publicKey = $this->getPublicKey();

		return $spkac;
	}

	public function saveSPKAC(array $spkac, $format = self::FORMAT_PEM)
	{
		if (!is_array($spkac) || !isset($spkac['publicKeyAndChallenge'])) {
			return false;
		}

		$algorithm = $this->subArray($spkac, 'publicKeyAndChallenge/spki/algorithm/algorithm');
		switch (true) {
			case !$algorithm:
			case is_object($spkac['publicKeyAndChallenge']['spki']['subjectPublicKey']):
				break;
			default:
				$spkac['publicKeyAndChallenge']['spki'] = new Element(
					base64_decode(preg_replace('#-.+-|[\r\n]#', '', $spkac['publicKeyAndChallenge']['spki']['subjectPublicKey']))
				);
		}

		$spkac = ASN1::encodeDER($spkac, Maps\SignedPublicKeyAndChallenge::MAP);

		switch ($format) {
			case self::FORMAT_DER:
				return $spkac;

			default:

				return 'SPKAC=' . Strings::base64_encode($spkac);
		}
	}

	public function loadCRL($crl, $mode = self::FORMAT_AUTO_DETECT)
	{
		if (is_array($crl) && isset($crl['tbsCertList'])) {
			$this->currentCert = $crl;
			unset($this->signatureSubject);
			return $crl;
		}

		if ($mode != self::FORMAT_DER) {
			$newcrl = ASN1::extractBER($crl);
			if ($mode == self::FORMAT_PEM && $crl == $newcrl) {
				return false;
			}
			$crl = $newcrl;
		}
		$orig = $crl;

		if ($crl === false) {
			$this->currentCert = false;
			return false;
		}

		$decoded = ASN1::decodeBER($crl);

		if (!$decoded) {
			$this->currentCert = false;
			return false;
		}

		$crl = ASN1::asn1map($decoded[0], Maps\CertificateList::MAP);
		if (!isset($crl) || $crl === false) {
			$this->currentCert = false;
			return false;
		}

		$this->signatureSubject = substr($orig, $decoded[0]['content'][0]['start'], $decoded[0]['content'][0]['length']);

		$this->mapInDNs($crl, 'tbsCertList/issuer/rdnSequence');
		if ($this->isSubArrayValid($crl, 'tbsCertList/crlExtensions')) {
			$this->mapInExtensions($crl, 'tbsCertList/crlExtensions');
		}
		if ($this->isSubArrayValid($crl, 'tbsCertList/revokedCertificates')) {
			$rclist_ref = &$this->subArrayUnchecked($crl, 'tbsCertList/revokedCertificates');
			if ($rclist_ref) {
				$rclist = $crl['tbsCertList']['revokedCertificates'];
				foreach ($rclist as $i => $extension) {
					if ($this->isSubArrayValid($rclist, "$i/crlEntryExtensions")) {
						$this->mapInExtensions($rclist_ref, "$i/crlEntryExtensions");
					}
				}
			}
		}

		$this->currentKeyIdentifier = null;
		$this->currentCert = $crl;

		return $crl;
	}

	public function saveCRL(array $crl, $format = self::FORMAT_PEM)
	{
		if (!is_array($crl) || !isset($crl['tbsCertList'])) {
			return false;
		}

		$filters = [];
		$filters['tbsCertList']['issuer']['rdnSequence']['value']
			= ['type' => ASN1::TYPE_UTF8_STRING];
		$filters['tbsCertList']['signature']['parameters']
			= ['type' => ASN1::TYPE_UTF8_STRING];
		$filters['signatureAlgorithm']['parameters']
			= ['type' => ASN1::TYPE_UTF8_STRING];

		if (empty($crl['tbsCertList']['signature']['parameters'])) {
			$filters['tbsCertList']['signature']['parameters']
				= ['type' => ASN1::TYPE_NULL];
		}

		if (empty($crl['signatureAlgorithm']['parameters'])) {
			$filters['signatureAlgorithm']['parameters']
				= ['type' => ASN1::TYPE_NULL];
		}

		ASN1::setFilters($filters);

		$this->mapOutDNs($crl, 'tbsCertList/issuer/rdnSequence');
		$this->mapOutExtensions($crl, 'tbsCertList/crlExtensions');
		$rclist = &$this->subArray($crl, 'tbsCertList/revokedCertificates');
		if (is_array($rclist)) {
			foreach ($rclist as $i => $extension) {
				$this->mapOutExtensions($rclist, "$i/crlEntryExtensions");
			}
		}

		$crl = ASN1::encodeDER($crl, Maps\CertificateList::MAP);

		switch ($format) {
			case self::FORMAT_DER:
				return $crl;

			default:
				return "-----BEGIN X509 CRL-----\r\n" . chunk_split(Strings::base64_encode($crl), 64) . '-----END X509 CRL-----';
		}
	}

	private function timeField($date)
	{
		if ($date instanceof Element) {
			return $date;
		}
		$dateObj = new \DateTimeImmutable($date, new \DateTimeZone('GMT'));
		$year = $dateObj->format('Y');
		if ($year < 2050) {
			return ['utcTime' => $date];
		} else {
			return ['generalTime' => $date];
		}
	}

	public function sign(X509 $issuer, X509 $subject)
	{
		if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
			return false;
		}

		if (isset($subject->publicKey) && !($subjectPublicKey = $subject->formatSubjectPublicKey())) {
			return false;
		}

		$currentCert = isset($this->currentCert) ? $this->currentCert : null;
		$signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject : null;
		$signatureAlgorithm = self::identifySignatureAlgorithm($issuer->privateKey);

		if (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertificate'])) {
			$this->currentCert = $subject->currentCert;
			$this->currentCert['tbsCertificate']['signature'] = $signatureAlgorithm;
			$this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;

			if (!empty($this->startDate)) {
				$this->currentCert['tbsCertificate']['validity']['notBefore'] = $this->timeField($this->startDate);
			}
			if (!empty($this->endDate)) {
				$this->currentCert['tbsCertificate']['validity']['notAfter'] = $this->timeField($this->endDate);
			}
			if (!empty($this->serialNumber)) {
				$this->currentCert['tbsCertificate']['serialNumber'] = $this->serialNumber;
			}
			if (!empty($subject->dn)) {
				$this->currentCert['tbsCertificate']['subject'] = $subject->dn;
			}
			if (!empty($subject->publicKey)) {
				$this->currentCert['tbsCertificate']['subjectPublicKeyInfo'] = $subjectPublicKey;
			}
			$this->removeExtension('id-ce-authorityKeyIdentifier');
			if (isset($subject->domains)) {
				$this->removeExtension('id-ce-subjectAltName');
			}
		} elseif (isset($subject->currentCert) && is_array($subject->currentCert) && isset($subject->currentCert['tbsCertList'])) {
			return false;
		} else {
			if (!isset($subject->publicKey)) {
				return false;
			}

			$startDate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
			$startDate = !empty($this->startDate) ? $this->startDate : $startDate->format('D, d M Y H:i:s O');

			$endDate = new \DateTimeImmutable('+1 year', new \DateTimeZone(@date_default_timezone_get()));
			$endDate = !empty($this->endDate) ? $this->endDate : $endDate->format('D, d M Y H:i:s O');

			$serialNumber = !empty($this->serialNumber) ?
				$this->serialNumber :
				new BigInteger(Random::string(20) & ("\x7F" . str_repeat("\xFF", 19)), 256);

			$this->currentCert = [
				'tbsCertificate' =>
					[
						'version' => 'v3',
						'serialNumber' => $serialNumber,
						'signature' => $signatureAlgorithm,
						'issuer' => false,
						'validity' => [
							'notBefore' => $this->timeField($startDate),
							'notAfter' => $this->timeField($endDate)
						],
						'subject' => $subject->dn,
						'subjectPublicKeyInfo' => $subjectPublicKey
					],
					'signatureAlgorithm' => $signatureAlgorithm,
					'signature'			=> false
			];

			$csrexts = $subject->getAttribute('pkcs-9-at-extensionRequest', 0);

			if (!empty($csrexts)) {
				$this->currentCert['tbsCertificate']['extensions'] = $csrexts;
			}
		}

		$this->currentCert['tbsCertificate']['issuer'] = $issuer->dn;

		if (isset($issuer->currentKeyIdentifier)) {
			$this->setExtension('id-ce-authorityKeyIdentifier', [

					'keyIdentifier' => $issuer->currentKeyIdentifier
				]);

		}

		if (isset($subject->currentKeyIdentifier)) {
			$this->setExtension('id-ce-subjectKeyIdentifier', $subject->currentKeyIdentifier);
		}

		$altName = [];

		if (isset($subject->domains) && count($subject->domains)) {
			$altName = array_map(['\phpseclib3\File\X509', 'dnsName'], $subject->domains);
		}

		if (isset($subject->ipAddresses) && count($subject->ipAddresses)) {

			$ipAddresses = [];
			foreach ($subject->ipAddresses as $ipAddress) {
				$encoded = $subject->ipAddress($ipAddress);
				if ($encoded !== false) {
					$ipAddresses[] = $encoded;
				}
			}
			if (count($ipAddresses)) {
				$altName = array_merge($altName, $ipAddresses);
			}
		}

		if (!empty($altName)) {
			$this->setExtension('id-ce-subjectAltName', $altName);
		}

		if ($this->caFlag) {
			$keyUsage = $this->getExtension('id-ce-keyUsage');
			if (!$keyUsage) {
				$keyUsage = [];
			}

			$this->setExtension(
				'id-ce-keyUsage',
				array_values(array_unique(array_merge($keyUsage, ['cRLSign', 'keyCertSign'])))
			);

			$basicConstraints = $this->getExtension('id-ce-basicConstraints');
			if (!$basicConstraints) {
				$basicConstraints = [];
			}

			$this->setExtension(
				'id-ce-basicConstraints',
				array_merge(['cA' => true], $basicConstraints),
				true
			);

			if (!isset($subject->currentKeyIdentifier)) {
				$this->setExtension('id-ce-subjectKeyIdentifier', $this->computeKeyIdentifier($this->currentCert), false, false);
			}
		}

		$tbsCertificate = $this->currentCert['tbsCertificate'];
		$this->loadX509($this->saveX509($this->currentCert));

		$result = $this->currentCert;
		$this->currentCert['signature'] = $result['signature'] = "\0" . $issuer->privateKey->sign($this->signatureSubject);
		$result['tbsCertificate'] = $tbsCertificate;

		$this->currentCert = $currentCert;
		$this->signatureSubject = $signatureSubject;

		return $result;
	}

	public function signCSR()
	{
		if (!is_object($this->privateKey) || empty($this->dn)) {
			return false;
		}

		$origPublicKey = $this->publicKey;
		$this->publicKey = $this->privateKey->getPublicKey();
		$publicKey = $this->formatSubjectPublicKey();
		$this->publicKey = $origPublicKey;

		$currentCert = isset($this->currentCert) ? $this->currentCert : null;
		$signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject : null;
		$signatureAlgorithm = self::identifySignatureAlgorithm($this->privateKey);

		if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['certificationRequestInfo'])) {
			$this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
			if (!empty($this->dn)) {
				$this->currentCert['certificationRequestInfo']['subject'] = $this->dn;
			}
			$this->currentCert['certificationRequestInfo']['subjectPKInfo'] = $publicKey;
		} else {
			$this->currentCert = [
				'certificationRequestInfo' =>
					[
						'version' => 'v1',
						'subject' => $this->dn,
						'subjectPKInfo' => $publicKey,
						'attributes' => []
					],
					'signatureAlgorithm' => $signatureAlgorithm,
					'signature'			=> false
			];
		}

		$certificationRequestInfo = $this->currentCert['certificationRequestInfo'];
		$this->loadCSR($this->saveCSR($this->currentCert));

		$result = $this->currentCert;
		$this->currentCert['signature'] = $result['signature'] = "\0" . $this->privateKey->sign($this->signatureSubject);
		$result['certificationRequestInfo'] = $certificationRequestInfo;

		$this->currentCert = $currentCert;
		$this->signatureSubject = $signatureSubject;

		return $result;
	}

	public function signSPKAC()
	{
		if (!is_object($this->privateKey)) {
			return false;
		}

		$origPublicKey = $this->publicKey;
		$this->publicKey = $this->privateKey->getPublicKey();
		$publicKey = $this->formatSubjectPublicKey();
		$this->publicKey = $origPublicKey;

		$currentCert = isset($this->currentCert) ? $this->currentCert : null;
		$signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject : null;
		$signatureAlgorithm = self::identifySignatureAlgorithm($this->privateKey);

		if (isset($this->currentCert) && is_array($this->currentCert) && isset($this->currentCert['publicKeyAndChallenge'])) {
			$this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
			$this->currentCert['publicKeyAndChallenge']['spki'] = $publicKey;
			if (!empty($this->challenge)) {

				$this->currentCert['publicKeyAndChallenge']['challenge'] = $this->challenge & str_repeat("\x7F", strlen($this->challenge));
			}
		} else {
			$this->currentCert = [
				'publicKeyAndChallenge' =>
					[
						'spki' => $publicKey,

						'challenge' => !empty($this->challenge) ? $this->challenge : ''
					],
					'signatureAlgorithm' => $signatureAlgorithm,
					'signature'			=> false
			];
		}

		$publicKeyAndChallenge = $this->currentCert['publicKeyAndChallenge'];
		$this->loadSPKAC($this->saveSPKAC($this->currentCert));

		$result = $this->currentCert;
		$this->currentCert['signature'] = $result['signature'] = "\0" . $this->privateKey->sign($this->signatureSubject);
		$result['publicKeyAndChallenge'] = $publicKeyAndChallenge;

		$this->currentCert = $currentCert;
		$this->signatureSubject = $signatureSubject;

		return $result;
	}

	public function signCRL(X509 $issuer, X509 $crl)
	{
		if (!is_object($issuer->privateKey) || empty($issuer->dn)) {
			return false;
		}

		$currentCert = isset($this->currentCert) ? $this->currentCert : null;
		$signatureSubject = isset($this->signatureSubject) ? $this->signatureSubject : null;
		$signatureAlgorithm = self::identifySignatureAlgorithm($issuer->privateKey);

		$thisUpdate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
		$thisUpdate = !empty($this->startDate) ? $this->startDate : $thisUpdate->format('D, d M Y H:i:s O');

		if (isset($crl->currentCert) && is_array($crl->currentCert) && isset($crl->currentCert['tbsCertList'])) {
			$this->currentCert = $crl->currentCert;
			$this->currentCert['tbsCertList']['signature'] = $signatureAlgorithm;
			$this->currentCert['signatureAlgorithm'] = $signatureAlgorithm;
		} else {
			$this->currentCert = [
				'tbsCertList' =>
					[
						'version' => 'v2',
						'signature' => $signatureAlgorithm,
						'issuer' => false,
						'thisUpdate' => $this->timeField($thisUpdate)
					],
					'signatureAlgorithm' => $signatureAlgorithm,
					'signature'			=> false
			];
		}

		$tbsCertList = &$this->currentCert['tbsCertList'];
		$tbsCertList['issuer'] = $issuer->dn;
		$tbsCertList['thisUpdate'] = $this->timeField($thisUpdate);

		if (!empty($this->endDate)) {
			$tbsCertList['nextUpdate'] = $this->timeField($this->endDate);
		} else {
			unset($tbsCertList['nextUpdate']);
		}

		if (!empty($this->serialNumber)) {
			$crlNumber = $this->serialNumber;
		} else {
			$crlNumber = $this->getExtension('id-ce-cRLNumber');

			$crlNumber = $crlNumber !== false ? $crlNumber->add(new BigInteger(1)) : null;
		}

		$this->removeExtension('id-ce-authorityKeyIdentifier');
		$this->removeExtension('id-ce-issuerAltName');

		$version = isset($tbsCertList['version']) ? $tbsCertList['version'] : 0;
		if (!$version) {
			if (!empty($tbsCertList['crlExtensions'])) {
				$version = 'v2';
			} elseif (!empty($tbsCertList['revokedCertificates'])) {
				foreach ($tbsCertList['revokedCertificates'] as $cert) {
					if (!empty($cert['crlEntryExtensions'])) {
						$version = 'v2';
					}
				}
			}

			if ($version) {
				$tbsCertList['version'] = $version;
			}
		}

		if (!empty($tbsCertList['version'])) {
			if (!empty($crlNumber)) {
				$this->setExtension('id-ce-cRLNumber', $crlNumber);
			}

			if (isset($issuer->currentKeyIdentifier)) {
				$this->setExtension('id-ce-authorityKeyIdentifier', [

						'keyIdentifier' => $issuer->currentKeyIdentifier
					]);

			}

			$issuerAltName = $this->getExtension('id-ce-subjectAltName', $issuer->currentCert);

			if ($issuerAltName !== false) {
				$this->setExtension('id-ce-issuerAltName', $issuerAltName);
			}
		}

		if (empty($tbsCertList['revokedCertificates'])) {
			unset($tbsCertList['revokedCertificates']);
		}

		unset($tbsCertList);

		$tbsCertList = $this->currentCert['tbsCertList'];
		$this->loadCRL($this->saveCRL($this->currentCert));

		$result = $this->currentCert;
		$this->currentCert['signature'] = $result['signature'] = "\0" . $issuer->privateKey->sign($this->signatureSubject);
		$result['tbsCertList'] = $tbsCertList;

		$this->currentCert = $currentCert;
		$this->signatureSubject = $signatureSubject;

		return $result;
	}

	private static function identifySignatureAlgorithm(PrivateKey $key)
	{
		if ($key instanceof RSA) {
			if ($key->getPadding() & RSA::SIGNATURE_PSS) {
				$r = PSS::load($key->withPassword()->toString('PSS'));
				return [
					'algorithm' => 'id-RSASSA-PSS',
					'parameters' => PSS::savePSSParams($r)
				];
			}
			switch ($key->getHash()) {
				case 'md2':
				case 'md5':
				case 'sha1':
				case 'sha224':
				case 'sha256':
				case 'sha384':
				case 'sha512':
					return [
						'algorithm' => $key->getHash() . 'WithRSAEncryption',
						'parameters' => null
					];
			}
			throw new UnsupportedAlgorithmException('The only supported hash algorithms for RSA are: md2, md5, sha1, sha224, sha256, sha384, sha512');
		}

		if ($key instanceof DSA) {
			switch ($key->getHash()) {
				case 'sha1':
				case 'sha224':
				case 'sha256':
					return ['algorithm' => 'id-dsa-with-' . $key->getHash()];
			}
			throw new UnsupportedAlgorithmException('The only supported hash algorithms for DSA are: sha1, sha224, sha256');
		}

		if ($key instanceof EC) {
			switch ($key->getCurve()) {
				case 'Ed25519':
				case 'Ed448':
					return ['algorithm' => 'id-' . $key->getCurve()];
			}
			switch ($key->getHash()) {
				case 'sha1':
				case 'sha224':
				case 'sha256':
				case 'sha384':
				case 'sha512':
					return ['algorithm' => 'ecdsa-with-' . strtoupper($key->getHash())];
			}
			throw new UnsupportedAlgorithmException('The only supported hash algorithms for EC are: sha1, sha224, sha256, sha384, sha512');
		}

		throw new UnsupportedAlgorithmException('The only supported public key classes are: RSA, DSA, EC');
	}

	public function setStartDate($date)
	{
		if (!is_object($date) || !($date instanceof \DateTimeInterface)) {
			$date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
		}

		$this->startDate = $date->format('D, d M Y H:i:s O');
	}

	public function setEndDate($date)
	{

		if (is_string($date) && strtolower($date) === 'lifetime') {
			$temp = '99991231235959Z';
			$temp = chr(ASN1::TYPE_GENERALIZED_TIME) . ASN1::encodeLength(strlen($temp)) . $temp;
			$this->endDate = new Element($temp);
		} else {
			if (!is_object($date) || !($date instanceof \DateTimeInterface)) {
				$date = new \DateTimeImmutable($date, new \DateTimeZone(@date_default_timezone_get()));
			}

			$this->endDate = $date->format('D, d M Y H:i:s O');
		}
	}

	public function setSerialNumber($serial, $base = -256)
	{
		$this->serialNumber = new BigInteger($serial, $base);
	}

	public function makeCA()
	{
		$this->caFlag = true;
	}

	private function isSubArrayValid(array $root, $path)
	{
		if (!is_array($root)) {
			return false;
		}

		foreach (explode('/', $path) as $i) {
			if (!is_array($root)) {
				return false;
			}

			if (!isset($root[$i])) {
				return true;
			}

			$root = $root[$i];
		}

		return true;
	}

	private function &subArrayUnchecked(array &$root, $path, $create = false)
	{
		$false = false;

		foreach (explode('/', $path) as $i) {
			if (!isset($root[$i])) {
				if (!$create) {
					return $false;
				}

				$root[$i] = [];
			}

			$root = &$root[$i];
		}

		return $root;
	}

	private function &subArray(&$root, $path, $create = false)
	{
		$false = false;

		if (!is_array($root)) {
			return $false;
		}

		foreach (explode('/', $path) as $i) {
			if (!is_array($root)) {
				return $false;
			}

			if (!isset($root[$i])) {
				if (!$create) {
					return $false;
				}

				$root[$i] = [];
			}

			$root = &$root[$i];
		}

		return $root;
	}

	private function &extensions(&$root, $path = null, $create = false)
	{
		if (!isset($root)) {
			$root = $this->currentCert;
		}

		switch (true) {
			case !empty($path):
			case !is_array($root):
				break;
			case isset($root['tbsCertificate']):
				$path = 'tbsCertificate/extensions';
				break;
			case isset($root['tbsCertList']):
				$path = 'tbsCertList/crlExtensions';
				break;
			case isset($root['certificationRequestInfo']):
				$pth = 'certificationRequestInfo/attributes';
				$attributes = &$this->subArray($root, $pth, $create);

				if (is_array($attributes)) {
					foreach ($attributes as $key => $value) {
						if ($value['type'] == 'pkcs-9-at-extensionRequest') {
							$path = "$pth/$key/value/0";
							break 2;
						}
					}
					if ($create) {
						$key = count($attributes);
						$attributes[] = ['type' => 'pkcs-9-at-extensionRequest', 'value' => []];
						$path = "$pth/$key/value/0";
					}
				}
				break;
		}

		$extensions = &$this->subArray($root, $path, $create);

		if (!is_array($extensions)) {
			$false = false;
			return $false;
		}

		return $extensions;
	}

	private function removeExtensionHelper($id, $path = null)
	{
		$extensions = &$this->extensions($this->currentCert, $path);

		if (!is_array($extensions)) {
			return false;
		}

		$result = false;
		foreach ($extensions as $key => $value) {
			if ($value['extnId'] == $id) {
				unset($extensions[$key]);
				$result = true;
			}
		}

		$extensions = array_values($extensions);

		if (!isset($extensions[0])) {
			$extensions = array_splice($extensions, 0, 0);
		}
		return $result;
	}

	private function getExtensionHelper($id, $cert = null, $path = null)
	{
		$extensions = $this->extensions($cert, $path);

		if (!is_array($extensions)) {
			return false;
		}

		foreach ($extensions as $key => $value) {
			if ($value['extnId'] == $id) {
				return $value['extnValue'];
			}
		}

		return false;
	}

	private function getExtensionsHelper($cert = null, $path = null)
	{
		$exts = $this->extensions($cert, $path);
		$extensions = [];

		if (is_array($exts)) {
			foreach ($exts as $extension) {
				$extensions[] = $extension['extnId'];
			}
		}

		return $extensions;
	}

	private function setExtensionHelper($id, $value, $critical = false, $replace = true, $path = null)
	{
		$extensions = &$this->extensions($this->currentCert, $path, true);

		if (!is_array($extensions)) {
			return false;
		}

		$newext = ['extnId'	=> $id, 'critical' => $critical, 'extnValue' => $value];

		foreach ($extensions as $key => $value) {
			if ($value['extnId'] == $id) {
				if (!$replace) {
					return false;
				}

				$extensions[$key] = $newext;
				return true;
			}
		}

		$extensions[] = $newext;
		return true;
	}

	public function removeExtension($id)
	{
		return $this->removeExtensionHelper($id);
	}

	public function getExtension($id, $cert = null, $path = null)
	{
		return $this->getExtensionHelper($id, $cert, $path);
	}

	public function getExtensions($cert = null, $path = null)
	{
		return $this->getExtensionsHelper($cert, $path);
	}

	public function setExtension($id, $value, $critical = false, $replace = true)
	{
		return $this->setExtensionHelper($id, $value, $critical, $replace);
	}

	public function removeAttribute($id, $disposition = self::ATTR_ALL)
	{
		$attributes = &$this->subArray($this->currentCert, 'certificationRequestInfo/attributes');

		if (!is_array($attributes)) {
			return false;
		}

		$result = false;
		foreach ($attributes as $key => $attribute) {
			if ($attribute['type'] == $id) {
				$n = count($attribute['value']);
				switch (true) {
					case $disposition == self::ATTR_APPEND:
					case $disposition == self::ATTR_REPLACE:
						return false;
					case $disposition >= $n:
						$disposition -= $n;
						break;
					case $disposition == self::ATTR_ALL:
					case $n == 1:
						unset($attributes[$key]);
						$result = true;
						break;
					default:
						unset($attributes[$key]['value'][$disposition]);
						$attributes[$key]['value'] = array_values($attributes[$key]['value']);
						$result = true;
						break;
				}
				if ($result && $disposition != self::ATTR_ALL) {
					break;
				}
			}
		}

		$attributes = array_values($attributes);
		return $result;
	}

	public function getAttribute($id, $disposition = self::ATTR_ALL, $csr = null)
	{
		if (empty($csr)) {
			$csr = $this->currentCert;
		}

		$attributes = $this->subArray($csr, 'certificationRequestInfo/attributes');

		if (!is_array($attributes)) {
			return false;
		}

		foreach ($attributes as $key => $attribute) {
			if ($attribute['type'] == $id) {
				$n = count($attribute['value']);
				switch (true) {
					case $disposition == self::ATTR_APPEND:
					case $disposition == self::ATTR_REPLACE:
						return false;
					case $disposition == self::ATTR_ALL:
						return $attribute['value'];
					case $disposition >= $n:
						$disposition -= $n;
						break;
					default:
						return $attribute['value'][$disposition];
				}
			}
		}

		return false;
	}

	public function getRequestedCertificateExtensions($csr = null)
	{
		if (empty($csr)) {
			$csr = $this->currentCert;
		}

		$requestedExtensions = $this->getAttribute('pkcs-9-at-extensionRequest');
		if ($requestedExtensions === false) {
			return false;
		}

		return $this->getAttribute('pkcs-9-at-extensionRequest')[0];
	}

	public function getAttributes($csr = null)
	{
		if (empty($csr)) {
			$csr = $this->currentCert;
		}

		$attributes = $this->subArray($csr, 'certificationRequestInfo/attributes');
		$attrs = [];

		if (is_array($attributes)) {
			foreach ($attributes as $attribute) {
				$attrs[] = $attribute['type'];
			}
		}

		return $attrs;
	}

	public function setAttribute($id, $value, $disposition = self::ATTR_ALL)
	{
		$attributes = &$this->subArray($this->currentCert, 'certificationRequestInfo/attributes', true);

		if (!is_array($attributes)) {
			return false;
		}

		switch ($disposition) {
			case self::ATTR_REPLACE:
				$disposition = self::ATTR_APPEND;

			case self::ATTR_ALL:
				$this->removeAttribute($id);
				break;
		}

		foreach ($attributes as $key => $attribute) {
			if ($attribute['type'] == $id) {
				$n = count($attribute['value']);
				switch (true) {
					case $disposition == self::ATTR_APPEND:
						$last = $key;
						break;
					case $disposition >= $n:
						$disposition -= $n;
						break;
					default:
						$attributes[$key]['value'][$disposition] = $value;
						return true;
				}
			}
		}

		switch (true) {
			case $disposition >= 0:
				return false;
			case isset($last):
				$attributes[$last]['value'][] = $value;
				break;
			default:
				$attributes[] = ['type' => $id, 'value' => $disposition == self::ATTR_ALL ? $value : [$value]];
				break;
		}

		return true;
	}

	public function setKeyIdentifier($value)
	{
		if (empty($value)) {
			unset($this->currentKeyIdentifier);
		} else {
			$this->currentKeyIdentifier = $value;
		}
	}

	public function computeKeyIdentifier($key = null, $method = 1)
	{
		if (is_null($key)) {
			$key = $this;
		}

		switch (true) {
			case is_string($key):
				break;
			case is_array($key) && isset($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey']):
				return $this->computeKeyIdentifier($key['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'], $method);
			case is_array($key) && isset($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey']):
				return $this->computeKeyIdentifier($key['certificationRequestInfo']['subjectPKInfo']['subjectPublicKey'], $method);
			case !is_object($key):
				return false;
			case $key instanceof Element:

				$decoded = ASN1::decodeBER($key->element);
				if (!$decoded) {
					return false;
				}
				$raw = ASN1::asn1map($decoded[0], ['type' => ASN1::TYPE_BIT_STRING]);
				if (empty($raw)) {
					return false;
				}

				$key = PublicKeyLoader::load($raw);
				if ($key instanceof PrivateKey) {
					return $this->computeKeyIdentifier($key, $method);
				}
				$key = $raw;
				break;
			case $key instanceof X509:
				if (isset($key->publicKey)) {
					return $this->computeKeyIdentifier($key->publicKey, $method);
				}
				if (isset($key->privateKey)) {
					return $this->computeKeyIdentifier($key->privateKey, $method);
				}
				if (isset($key->currentCert['tbsCertificate']) || isset($key->currentCert['certificationRequestInfo'])) {
					return $this->computeKeyIdentifier($key->currentCert, $method);
				}
				return false;
			default:
				$key = $key->getPublicKey();
				break;
		}

		$key = ASN1::extractBER($key);

		$hash = new Hash('sha1');
		$hash = $hash->hash($key);

		if ($method == 2) {
			$hash = substr($hash, -8);
			$hash[0] = chr((ord($hash[0]) & 0x0F) | 0x40);
		}

		return $hash;
	}

	private function formatSubjectPublicKey()
	{
		$format = $this->publicKey instanceof RSA && ($this->publicKey->getPadding() & RSA::SIGNATURE_PSS) ?
			'PSS' :
			'PKCS8';

		$publicKey = base64_decode(preg_replace('#-.+-|[\r\n]#', '', $this->publicKey->toString($format)));

		$decoded = ASN1::decodeBER($publicKey);
		if (!$decoded) {
			return false;
		}
		$mapped = ASN1::asn1map($decoded[0], Maps\SubjectPublicKeyInfo::MAP);
		if (!is_array($mapped)) {
			return false;
		}

		$mapped['subjectPublicKey'] = $this->publicKey->toString($format);

		return $mapped;
	}

	public function setDomain(...$domains)
	{
		$this->domains = $domains;
		$this->removeDNProp('id-at-commonName');
		$this->setDNProp('id-at-commonName', $this->domains[0]);
	}

	public function setIPAddress(...$ipAddresses)
	{
		$this->ipAddresses = $ipAddresses;

	}

	private static function dnsName($domain)
	{
		return ['dNSName' => $domain];
	}

	private function iPAddress($address)
	{
		return ['iPAddress' => $address];
	}

	private function revokedCertificate(array &$rclist, $serial, $create = false)
	{
		$serial = new BigInteger($serial);

		foreach ($rclist as $i => $rc) {
			if (!($serial->compare($rc['userCertificate']))) {
				return $i;
			}
		}

		if (!$create) {
			return false;
		}

		$i = count($rclist);
		$revocationDate = new \DateTimeImmutable('now', new \DateTimeZone(@date_default_timezone_get()));
		$rclist[] = ['userCertificate' => $serial,
							'revocationDate'	=> $this->timeField($revocationDate->format('D, d M Y H:i:s O'))];
		return $i;
	}

	public function revoke($serial, $date = null)
	{
		if (isset($this->currentCert['tbsCertList'])) {
			if (is_array($rclist = &$this->subArray($this->currentCert, 'tbsCertList/revokedCertificates', true))) {
				if ($this->revokedCertificate($rclist, $serial) === false) {
					if (($i = $this->revokedCertificate($rclist, $serial, true)) !== false) {
						if (!empty($date)) {
							$rclist[$i]['revocationDate'] = $this->timeField($date);
						}

						return true;
					}
				}
			}
		}

		return false;
	}

	public function unrevoke($serial)
	{
		if (is_array($rclist = &$this->subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
			if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
				unset($rclist[$i]);
				$rclist = array_values($rclist);
				return true;
			}
		}

		return false;
	}

	public function getRevoked($serial)
	{
		if (is_array($rclist = $this->subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
			if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
				return $rclist[$i];
			}
		}

		return false;
	}

	public function listRevoked($crl = null)
	{
		if (!isset($crl)) {
			$crl = $this->currentCert;
		}

		if (!isset($crl['tbsCertList'])) {
			return false;
		}

		$result = [];

		if (is_array($rclist = $this->subArray($crl, 'tbsCertList/revokedCertificates'))) {
			foreach ($rclist as $rc) {
				$result[] = $rc['userCertificate']->toString();
			}
		}

		return $result;
	}

	public function removeRevokedCertificateExtension($serial, $id)
	{
		if (is_array($rclist = &$this->subArray($this->currentCert, 'tbsCertList/revokedCertificates'))) {
			if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
				return $this->removeExtensionHelper($id, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
			}
		}

		return false;
	}

	public function getRevokedCertificateExtension($serial, $id, $crl = null)
	{
		if (!isset($crl)) {
			$crl = $this->currentCert;
		}

		if (is_array($rclist = $this->subArray($crl, 'tbsCertList/revokedCertificates'))) {
			if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
				return $this->getExtension($id, $crl, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
			}
		}

		return false;
	}

	public function getRevokedCertificateExtensions($serial, $crl = null)
	{
		if (!isset($crl)) {
			$crl = $this->currentCert;
		}

		if (is_array($rclist = $this->subArray($crl, 'tbsCertList/revokedCertificates'))) {
			if (($i = $this->revokedCertificate($rclist, $serial)) !== false) {
				return $this->getExtensions($crl, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
			}
		}

		return false;
	}

	public function setRevokedCertificateExtension($serial, $id, $value, $critical = false, $replace = true)
	{
		if (isset($this->currentCert['tbsCertList'])) {
			if (is_array($rclist = &$this->subArray($this->currentCert, 'tbsCertList/revokedCertificates', true))) {
				if (($i = $this->revokedCertificate($rclist, $serial, true)) !== false) {
					return $this->setExtensionHelper($id, $value, $critical, $replace, "tbsCertList/revokedCertificates/$i/crlEntryExtensions");
				}
			}
		}

		return false;
	}

	public static function registerExtension($id, array $mapping)
	{
		if (isset(self::$extensions[$id]) && self::$extensions[$id] !== $mapping) {
			throw new \RuntimeException(
				'Extension ' . $id . ' has already been defined with a different mapping.'
			);
		}

		self::$extensions[$id] = $mapping;
	}

	public static function getRegisteredExtension($id)
	{
		return isset(self::$extensions[$id]) ? self::$extensions[$id] : null;
	}

	public function setExtensionValue($id, $value, $critical = false, $replace = false)
	{
		$this->extensionValues[$id] = compact('critical', 'replace', 'value');
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Random;
use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Math\BigInteger;

abstract class Engine implements \JsonSerializable
{
	 const PRIMES = [
		3,	5,	7,	11,	13,	17,	19,	23,	29,	31,	37,	41,	43,	47,	53,	59,
		61,	67,	71,	73,	79,	83,	89,	97,	101, 103, 107, 109, 113, 127, 131, 137,
		139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
		229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
		317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
		421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
		521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
		619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727,
		733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
		839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947,
		953, 967, 971, 977, 983, 991, 997,
	];

	protected static $zero = [];

	protected static $one	= [];

	protected static $two = [];

	protected static $modexpEngine;

	protected static $isValidEngine;

	protected $value;

	protected $is_negative;

	protected $precision = -1;

	protected $bitmask = false;

	protected $reduce;

	protected $hex;

	public function __construct($x = 0, $base = 10)
	{
		if (!array_key_exists(static::class, static::$zero)) {
			static::$zero[static::class] = null;
			static::$zero[static::class] = new static(0);
			static::$one[static::class] = new static(1);
			static::$two[static::class] = new static(2);
		}

		if (empty($x) && (abs($base) != 256 || $x !== '0')) {
			return;
		}

		switch ($base) {
			case -256:
			case 256:
				if ($base == -256 && (ord($x[0]) & 0x80)) {
					$this->value = ~$x;
					$this->is_negative = true;
				} else {
					$this->value = $x;
					$this->is_negative = false;
				}

				$this->initialize($base);

				if ($this->is_negative) {
					$temp = $this->add(new static('-1'));
					$this->value = $temp->value;
				}
				break;
			case -16:
			case 16:
				if ($base > 0 && $x[0] == '-') {
					$this->is_negative = true;
					$x = substr($x, 1);
				}

				$x = preg_replace('#^(?:0x)?([A-Fa-f0-9]*).*#s', '$1', $x);

				$is_negative = false;
				if ($base < 0 && hexdec($x[0]) >= 8) {
					$this->is_negative = $is_negative = true;
					$x = Strings::bin2hex(~Strings::hex2bin($x));
				}

				$this->value = $x;
				$this->initialize($base);

				if ($is_negative) {
					$temp = $this->add(new static('-1'));
					$this->value = $temp->value;
				}
				break;
			case -10:
			case 10:

				$this->value = preg_replace('#(?<!^)(?:-).*|(?<=^|-)0*|[^-0-9].*#s', '', $x);
				if (!strlen($this->value) || $this->value == '-') {
					$this->value = '0';
				}
				$this->initialize($base);
				break;
			case -2:
			case 2:
				if ($base > 0 && $x[0] == '-') {
					$this->is_negative = true;
					$x = substr($x, 1);
				}

				$x = preg_replace('#^([01]*).*#s', '$1', $x);

				$temp = new static(Strings::bits2bin($x), 128 * $base);
				$this->value = $temp->value;
				if ($temp->is_negative) {
					$this->is_negative = true;
				}

				break;
			default:

		}
	}

	public static function setModExpEngine($engine)
	{
		$fqengine = '\\phpseclib3\\Math\\BigInteger\\Engines\\' . static::ENGINE_DIR . '\\' . $engine;
		if (!class_exists($fqengine) || !method_exists($fqengine, 'isValidEngine')) {
			throw new \InvalidArgumentException("$engine is not a valid engine");
		}
		if (!$fqengine::isValidEngine()) {
			throw new BadConfigurationException("$engine is not setup correctly on this system");
		}
		static::$modexpEngine[static::class] = $fqengine;
	}

	protected function toBytesHelper()
	{
		$comparison = $this->compare(new static());
		if ($comparison == 0) {
			return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
		}

		$temp = $comparison < 0 ? $this->add(new static(1)) : $this;
		$bytes = $temp->toBytes();

		if (!strlen($bytes)) {
			$bytes = chr(0);
		}

		if (ord($bytes[0]) & 0x80) {
			$bytes = chr(0) . $bytes;
		}

		return $comparison < 0 ? ~$bytes : $bytes;
	}

	public function toHex($twos_compliment = false)
	{
		return Strings::bin2hex($this->toBytes($twos_compliment));
	}

	public function toBits($twos_compliment = false)
	{
		$hex = $this->toBytes($twos_compliment);
		$bits = Strings::bin2bits($hex);

		$result = $this->precision > 0 ? substr($bits, -$this->precision) : ltrim($bits, '0');

		if ($twos_compliment && $this->compare(new static()) > 0 && $this->precision <= 0) {
			return '0' . $result;
		}

		return $result;
	}

	protected function modInverseHelper(Engine $n)
	{

		$n = $n->abs();

		if ($this->compare(static::$zero[static::class]) < 0) {
			$temp = $this->abs();
			$temp = $temp->modInverse($n);
			return $this->normalize($n->subtract($temp));
		}

		extract($this->extendedGCD($n));

		if (!$gcd->equals(static::$one[static::class])) {
			return false;
		}

		$x = $x->compare(static::$zero[static::class]) < 0 ? $x->add($n) : $x;

		return $this->compare(static::$zero[static::class]) < 0 ? $this->normalize($n->subtract($x)) : $this->normalize($x);
	}

	public function __sleep()
	{
		$this->hex = $this->toHex(true);
		$vars = ['hex'];
		if ($this->precision > 0) {
			$vars[] = 'precision';
		}
		return $vars;
	}

	public function __wakeup()
	{
		$temp = new static($this->hex, -16);
		$this->value = $temp->value;
		$this->is_negative = $temp->is_negative;
		if ($this->precision > 0) {

			$this->setPrecision($this->precision);
		}
	}

	#[\ReturnTypeWillChange]
	public function jsonSerialize()
	{
		$result = ['hex' => $this->toHex(true)];
		if ($this->precision > 0) {
			$result['precision'] = $this->precision;
		}
		return $result;
	}

	public function __toString()
	{
		return $this->toString();
	}

	public function __debugInfo()
	{
		$result = [
			'value' => '0x' . $this->toHex(true),
			'engine' => basename(static::class)
		];
		return $this->precision > 0 ? $result + ['precision' => $this->precision] : $result;
	}

	public function setPrecision($bits)
	{
		if ($bits < 1) {
			$this->precision = -1;
			$this->bitmask = false;

			return;
		}
		$this->precision = $bits;
		$this->bitmask = static::setBitmask($bits);

		$temp = $this->normalize($this);
		$this->value = $temp->value;
	}

	public function getPrecision()
	{
		return $this->precision;
	}

	protected static function setBitmask($bits)
	{
		return new static(chr((1 << ($bits & 0x7)) - 1) . str_repeat(chr(0xFF), $bits >> 3), 256);
	}

	public function bitwise_not()
	{

		$temp = $this->toBytes();
		if ($temp == '') {
			return $this->normalize(static::$zero[static::class]);
		}
		$pre_msb = decbin(ord($temp[0]));
		$temp = ~$temp;
		$msb = decbin(ord($temp[0]));
		if (strlen($msb) == 8) {
			$msb = substr($msb, strpos($msb, '0'));
		}
		$temp[0] = chr(bindec($msb));

		$current_bits = strlen($pre_msb) + 8 * strlen($temp) - 8;
		$new_bits = $this->precision - $current_bits;
		if ($new_bits <= 0) {
			return $this->normalize(new static($temp, 256));
		}

		$leading_ones = chr((1 << ($new_bits & 0x7)) - 1) . str_repeat(chr(0xFF), $new_bits >> 3);

		self::base256_lshift($leading_ones, $current_bits);

		$temp = str_pad($temp, strlen($leading_ones), chr(0), STR_PAD_LEFT);

		return $this->normalize(new static($leading_ones | $temp, 256));
	}

	protected static function base256_lshift(&$x, $shift)
	{
		if ($shift == 0) {
			return;
		}

		$num_bytes = $shift >> 3;
		$shift &= 7;

		$carry = 0;
		for ($i = strlen($x) - 1; $i >= 0; --$i) {
			$temp = ord($x[$i]) << $shift | $carry;
			$x[$i] = chr($temp);
			$carry = $temp >> 8;
		}
		$carry = ($carry != 0) ? chr($carry) : '';
		$x = $carry . $x . str_repeat(chr(0), $num_bytes);
	}

	public function bitwise_leftRotate($shift)
	{
		$bits = $this->toBytes();

		if ($this->precision > 0) {
			$precision = $this->precision;
			if (static::FAST_BITWISE) {
				$mask = $this->bitmask->toBytes();
			} else {
				$mask = $this->bitmask->subtract(new static(1));
				$mask = $mask->toBytes();
			}
		} else {
			$temp = ord($bits[0]);
			for ($i = 0; $temp >> $i; ++$i) {
			}
			$precision = 8 * strlen($bits) - 8 + $i;
			$mask = chr((1 << ($precision & 0x7)) - 1) . str_repeat(chr(0xFF), $precision >> 3);
		}

		if ($shift < 0) {
			$shift += $precision;
		}
		$shift %= $precision;

		if (!$shift) {
			return clone $this;
		}

		$left = $this->bitwise_leftShift($shift);
		$left = $left->bitwise_and(new static($mask, 256));
		$right = $this->bitwise_rightShift($precision - $shift);
		$result = static::FAST_BITWISE ? $left->bitwise_or($right) : $left->add($right);
		return $this->normalize($result);
	}

	public function bitwise_rightRotate($shift)
	{
		return $this->bitwise_leftRotate(-$shift);
	}

	public static function minMaxBits($bits)
	{
		$bytes = $bits >> 3;
		$min = str_repeat(chr(0), $bytes);
		$max = str_repeat(chr(0xFF), $bytes);
		$msb = $bits & 7;
		if ($msb) {
			$min = chr(1 << ($msb - 1)) . $min;
			$max = chr((1 << $msb) - 1) . $max;
		} else {
			$min[0] = chr(0x80);
		}
		return [
			'min' => new static($min, 256),
			'max' => new static($max, 256)
		];
	}

	public function getLength()
	{
		return strlen($this->toBits());
	}

	public function getLengthInBytes()
	{
		return (int) ceil($this->getLength() / 8);
	}

	protected function powModOuter(Engine $e, Engine $n)
	{
		$n = $this->bitmask !== false && $this->bitmask->compare($n) < 0 ? $this->bitmask : $n->abs();

		if ($e->compare(new static()) < 0) {
			$e = $e->abs();

			$temp = $this->modInverse($n);
			if ($temp === false) {
				return false;
			}

			return $this->normalize($temp->powModInner($e, $n));
		}

		if ($this->compare($n) > 0) {
			list(, $temp) = $this->divide($n);
			return $temp->powModInner($e, $n);
		}

		return $this->powModInner($e, $n);
	}

	protected static function slidingWindow(Engine $x, Engine $e, Engine $n, $class)
	{
		static $window_ranges = [7, 25, 81, 241, 673, 1793];

		$e_bits = $e->toBits();
		$e_length = strlen($e_bits);

		for ($i = 0, $window_size = 1; $i < count($window_ranges) && $e_length > $window_ranges[$i]; ++$window_size, ++$i) {
		}

		$n_value = $n->value;

		if (method_exists(static::class, 'generateCustomReduction')) {
			static::generateCustomReduction($n, $class);
		}

		$powers = [];
		$powers[1] = static::prepareReduce($x->value, $n_value, $class);
		$powers[2] = static::squareReduce($powers[1], $n_value, $class);

		$temp = 1 << ($window_size - 1);
		for ($i = 1; $i < $temp; ++$i) {
			$i2 = $i << 1;
			$powers[$i2 + 1] = static::multiplyReduce($powers[$i2 - 1], $powers[2], $n_value, $class);
		}

		$result = new $class(1);
		$result = static::prepareReduce($result->value, $n_value, $class);

		for ($i = 0; $i < $e_length;) {
			if (!$e_bits[$i]) {
				$result = static::squareReduce($result, $n_value, $class);
				++$i;
			} else {
				for ($j = $window_size - 1; $j > 0; --$j) {
					if (!empty($e_bits[$i + $j])) {
						break;
					}
				}

				for ($k = 0; $k <= $j; ++$k) {
					$result = static::squareReduce($result, $n_value, $class);
				}

				$result = static::multiplyReduce($result, $powers[bindec(substr($e_bits, $i, $j + 1))], $n_value, $class);

				$i += $j + 1;
			}
		}

		$temp = new $class();
		$temp->value = static::reduce($result, $n_value, $class);

		return $temp;
	}

	public static function random($size)
	{
		extract(static::minMaxBits($size));

		return static::randomRange($min, $max);
	}

	public static function randomPrime($size)
	{
		extract(static::minMaxBits($size));

		return static::randomRangePrime($min, $max);
	}

	protected static function randomRangePrimeOuter(Engine $min, Engine $max)
	{
		$compare = $max->compare($min);

		if (!$compare) {
			return $min->isPrime() ? $min : false;
		} elseif ($compare < 0) {

			$temp = $max;
			$max = $min;
			$min = $temp;
		}

		$length = $max->getLength();
		if ($length > 8196) {
			throw new \RuntimeException("Generation of random prime numbers larger than 8196 has been disabled ($length)");
		}

		$x = static::randomRange($min, $max);

		return static::randomRangePrimeInner($x, $min, $max);
	}

	protected static function randomRangeHelper(Engine $min, Engine $max)
	{
		$compare = $max->compare($min);

		if (!$compare) {
			return $min;
		} elseif ($compare < 0) {

			$temp = $max;
			$max = $min;
			$min = $temp;
		}

		if (!isset(static::$one[static::class])) {
			static::$one[static::class] = new static(1);
		}

		$max = $max->subtract($min->subtract(static::$one[static::class]));

		$size = strlen(ltrim($max->toBytes(), chr(0)));

		$random_max = new static(chr(1) . str_repeat("\0", $size), 256);
		$random = new static(Random::string($size), 256);

		list($max_multiple) = $random_max->divide($max);
		$max_multiple = $max_multiple->multiply($max);

		while ($random->compare($max_multiple) >= 0) {
			$random = $random->subtract($max_multiple);
			$random_max = $random_max->subtract($max_multiple);
			$random = $random->bitwise_leftShift(8);
			$random = $random->add(new static(Random::string(1), 256));
			$random_max = $random_max->bitwise_leftShift(8);
			list($max_multiple) = $random_max->divide($max);
			$max_multiple = $max_multiple->multiply($max);
		}
		list(, $random) = $random->divide($max);

		return $random->add($min);
	}

	protected static function randomRangePrimeInner(Engine $x, Engine $min, Engine $max)
	{
		if (!isset(static::$two[static::class])) {
			static::$two[static::class] = new static('2');
		}

		$x->make_odd();
		if ($x->compare($max) > 0) {

			if ($min->equals($max)) {
				return false;
			}
			$x = clone $min;
			$x->make_odd();
		}

		$initial_x = clone $x;

		while (true) {
			if ($x->isPrime()) {
				return $x;
			}

			$x = $x->add(static::$two[static::class]);

			if ($x->compare($max) > 0) {
				$x = clone $min;
				if ($x->equals(static::$two[static::class])) {
					return $x;
				}
				$x->make_odd();
			}

			if ($x->equals($initial_x)) {
				return false;
			}
		}
	}

	protected function setupIsPrime()
	{
		$length = $this->getLengthInBytes();

			 if ($length >= 163) { $t =	2; }
		else if ($length >= 106) { $t =	3; }
		else if ($length >= 81 ) { $t =	4; }
		else if ($length >= 68 ) { $t =	5; }
		else if ($length >= 56 ) { $t =	6; }
		else if ($length >= 50 ) { $t =	7; }
		else if ($length >= 43 ) { $t =	8; }
		else if ($length >= 37 ) { $t =	9; }
		else if ($length >= 31 ) { $t = 12; }
		else if ($length >= 25 ) { $t = 15; }
		else if ($length >= 18 ) { $t = 18; }
		else					 { $t = 27; }

		return $t;
	}

	protected function testPrimality($t)
	{
		if (!$this->testSmallPrimes()) {
			return false;
		}

		$n	= clone $this;
		$n_1 = $n->subtract(static::$one[static::class]);
		$n_2 = $n->subtract(static::$two[static::class]);

		$r = clone $n_1;
		$s = static::scan1divide($r);

		for ($i = 0; $i < $t; ++$i) {
			$a = static::randomRange(static::$two[static::class], $n_2);
			$y = $a->modPow($r, $n);

			if (!$y->equals(static::$one[static::class]) && !$y->equals($n_1)) {
				for ($j = 1; $j < $s && !$y->equals($n_1); ++$j) {
					$y = $y->modPow(static::$two[static::class], $n);
					if ($y->equals(static::$one[static::class])) {
						return false;
					}
				}

				if (!$y->equals($n_1)) {
					return false;
				}
			}
		}

		return true;
	}

	public function isPrime($t = false)
	{

		$length = $this->getLength();
		if ($length > 8196) {
			throw new \RuntimeException("Primality testing is not supported for numbers larger than 8196 bits ($length)");
		}

		if (!$t) {
			$t = $this->setupIsPrime();
		}
		return $this->testPrimality($t);
	}

	protected function rootHelper($n)
	{
		if ($n < 1) {
			return clone static::$zero[static::class];
		}
		if ($this->compare(static::$one[static::class]) < 0) {
			return clone static::$zero[static::class];
		}
		if ($this->compare(static::$two[static::class]) < 0) {
			return clone static::$one[static::class];
		}

		return $this->rootInner($n);
	}

	protected function rootInner($n)
	{
		$n = new static($n);

		$g = static::$two[static::class];

		while ($g->pow($n)->compare($this) < 0) {
			$g = $g->multiply(static::$two[static::class]);
		}

		if ($g->pow($n)->equals($this) > 0) {
			$root = $g;
			return $this->normalize($root);
		}

		$og = $g;
		$g = $g->divide(static::$two[static::class])[0];
		$step = $og->subtract($g)->divide(static::$two[static::class])[0];
		$g = $g->add($step);

		while ($step->compare(static::$one[static::class]) == 1) {
			$guess = $g->pow($n);
			$step = $step->divide(static::$two[static::class])[0];
			$comp = $guess->compare($this);
			switch ($comp) {
				case -1:
					$g = $g->add($step);
					break;
				case 1:
					$g = $g->subtract($step);
					break;
				case 0:
					$root = $g;
					break 2;
			}
		}

		if ($comp == 1) {
			$g = $g->subtract($step);
		}

		$root = $g;

		return $this->normalize($root);
	}

	public function root($n = 2)
	{
		return $this->rootHelper($n);
	}

	protected static function minHelper(array $nums)
	{
		if (count($nums) == 1) {
			return $nums[0];
		}
		$min = $nums[0];
		for ($i = 1; $i < count($nums); $i++) {
			$min = $min->compare($nums[$i]) > 0 ? $nums[$i] : $min;
		}
		return $min;
	}

	protected static function maxHelper(array $nums)
	{
		if (count($nums) == 1) {
			return $nums[0];
		}
		$max = $nums[0];
		for ($i = 1; $i < count($nums); $i++) {
			$max = $max->compare($nums[$i]) < 0 ? $nums[$i] : $max;
		}
		return $max;
	}

	public function createRecurringModuloFunction()
	{
		$class = static::class;

		$fqengine = !method_exists(static::$modexpEngine[static::class], 'reduce') ?
			'\\phpseclib3\\Math\\BigInteger\\Engines\\' . static::ENGINE_DIR . '\\DefaultEngine' :
			static::$modexpEngine[static::class];
		if (method_exists($fqengine, 'generateCustomReduction')) {
			$func = $fqengine::generateCustomReduction($this, static::class);
			return eval('return function(' . static::class . ' $x) use ($func, $class) {
                $r = new $class();
                $r->value = $func($x->value);
                return $r;
            };');
		}
		$n = $this->value;
		return eval('return function(' . static::class . ' $x) use ($n, $fqengine, $class) {
            $r = new $class();
            $r->value = $fqengine::reduce($x->value, $n, $class);
            return $r;
        };');
	}

	protected function extendedGCDHelper(Engine $n)
	{
		$u = clone $this;
		$v = clone $n;

		$one = new static(1);
		$zero = new static();

		$a = clone $one;
		$b = clone $zero;
		$c = clone $zero;
		$d = clone $one;

		while (!$v->equals($zero)) {
			list($q) = $u->divide($v);

			$temp = $u;
			$u = $v;
			$v = $temp->subtract($v->multiply($q));

			$temp = $a;
			$a = $c;
			$c = $temp->subtract($a->multiply($q));

			$temp = $b;
			$b = $d;
			$d = $temp->subtract($b->multiply($q));
		}

		return [
			'gcd' => $u,
			'x' => $a,
			'y' => $b
		];
	}

	public function bitwise_split($split)
	{
		if ($split < 1) {
			throw new \RuntimeException('Offset must be greater than 1');
		}

		$mask = static::$one[static::class]->bitwise_leftShift($split)->subtract(static::$one[static::class]);

		$num = clone $this;

		$vals = [];
		while (!$num->equals(static::$zero[static::class])) {
			$vals[] = $num->bitwise_and($mask);
			$num = $num->bitwise_rightShift($split);
		}

		return array_reverse($vals);
	}

	protected function bitwiseAndHelper(Engine $x)
	{
		$left = $this->toBytes(true);
		$right = $x->toBytes(true);

		$length = max(strlen($left), strlen($right));

		$left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
		$right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

		return $this->normalize(new static($left & $right, -256));
	}

	protected function bitwiseOrHelper(Engine $x)
	{
		$left = $this->toBytes(true);
		$right = $x->toBytes(true);

		$length = max(strlen($left), strlen($right));

		$left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
		$right = str_pad($right, $length, chr(0), STR_PAD_LEFT);

		return $this->normalize(new static($left | $right, -256));
	}

	protected function bitwiseXorHelper(Engine $x)
	{
		$left = $this->toBytes(true);
		$right = $x->toBytes(true);

		$length = max(strlen($left), strlen($right));

		$left = str_pad($left, $length, chr(0), STR_PAD_LEFT);
		$right = str_pad($right, $length, chr(0), STR_PAD_LEFT);
		return $this->normalize(new static($left ^ $right, -256));
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\BadConfigurationException;

class BCMath extends Engine
{

	const FAST_BITWISE = false;

	const ENGINE_DIR = 'BCMath';

	public static function isValidEngine()
	{
		return extension_loaded('bcmath');
	}

	public function __construct($x = 0, $base = 10)
	{
		if (!isset(static::$isValidEngine[static::class])) {
			static::$isValidEngine[static::class] = self::isValidEngine();
		}
		if (!static::$isValidEngine[static::class]) {
			throw new BadConfigurationException('BCMath is not setup correctly on this system');
		}

		$this->value = '0';

		parent::__construct($x, $base);
	}

	protected function initialize($base)
	{
		switch (abs($base)) {
			case 256:

				$len = (strlen($this->value) + 3) & ~3;

				$x = str_pad($this->value, $len, chr(0), STR_PAD_LEFT);

				$this->value = '0';
				for ($i = 0; $i < $len; $i += 4) {
					$this->value = bcmul($this->value, '4294967296', 0);
					$this->value = bcadd(
						$this->value,
						0x1000000 * ord($x[$i]) + ((ord($x[$i + 1]) << 16) | (ord(
							$x[$i + 2]
						) << 8) | ord($x[$i + 3])),
						0
					);
				}

				if ($this->is_negative) {
					$this->value = '-' . $this->value;
				}
				break;
			case 16:
				$x = (strlen($this->value) & 1) ? '0' . $this->value : $this->value;
				$temp = new self(Strings::hex2bin($x), 256);
				$this->value = $this->is_negative ? '-' . $temp->value : $temp->value;
				$this->is_negative = false;
				break;
			case 10:

				$this->value = $this->value === '-' ? '0' : (string)$this->value;
		}
	}

	public function toString()
	{
		if ($this->value === '0') {
			return '0';
		}

		return ltrim($this->value, '0');
	}

	public function toBytes($twos_compliment = false)
	{
		if ($twos_compliment) {
			return $this->toBytesHelper();
		}

		$value = '';
		$current = $this->value;

		if ($current[0] == '-') {
			$current = substr($current, 1);
		}

		while (bccomp($current, '0', 0) > 0) {
			$temp = bcmod($current, '16777216');
			$value = chr($temp >> 16) . chr($temp >> 8) . chr($temp) . $value;
			$current = bcdiv($current, '16777216', 0);
		}

		return $this->precision > 0 ?
			substr(str_pad($value, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
			ltrim($value, chr(0));
	}

	public function add(BCMath $y)
	{
		$temp = new self();
		$temp->value = bcadd($this->value, $y->value);

		return $this->normalize($temp);
	}

	public function subtract(BCMath $y)
	{
		$temp = new self();
		$temp->value = bcsub($this->value, $y->value);

		return $this->normalize($temp);
	}

	public function multiply(BCMath $x)
	{
		$temp = new self();
		$temp->value = bcmul($this->value, $x->value);

		return $this->normalize($temp);
	}

	public function divide(BCMath $y)
	{
		$quotient = new self();
		$remainder = new self();

		$quotient->value = bcdiv($this->value, $y->value, 0);
		$remainder->value = bcmod($this->value, $y->value);

		if ($remainder->value[0] == '-') {
			$remainder->value = bcadd($remainder->value, $y->value[0] == '-' ? substr($y->value, 1) : $y->value, 0);
		}

		return [$this->normalize($quotient), $this->normalize($remainder)];
	}

	public function modInverse(BCMath $n)
	{
		return $this->modInverseHelper($n);
	}

	public function extendedGCD(BCMath $n)
	{

		$u = $this->value;
		$v = $n->value;

		$a = '1';
		$b = '0';
		$c = '0';
		$d = '1';

		while (bccomp($v, '0', 0) != 0) {
			$q = bcdiv($u, $v, 0);

			$temp = $u;
			$u = $v;
			$v = bcsub($temp, bcmul($v, $q, 0), 0);

			$temp = $a;
			$a = $c;
			$c = bcsub($temp, bcmul($a, $q, 0), 0);

			$temp = $b;
			$b = $d;
			$d = bcsub($temp, bcmul($b, $q, 0), 0);
		}

		return [
			'gcd' => $this->normalize(new static($u)),
			'x' => $this->normalize(new static($a)),
			'y' => $this->normalize(new static($b))
		];
	}

	public function gcd(BCMath $n)
	{
		extract($this->extendedGCD($n));

		return $gcd;
	}

	public function abs()
	{
		$temp = new static();
		$temp->value = strlen($this->value) && $this->value[0] == '-' ?
			substr($this->value, 1) :
			$this->value;

		return $temp;
	}

	public function bitwise_and(BCMath $x)
	{
		return $this->bitwiseAndHelper($x);
	}

	public function bitwise_or(BCMath $x)
	{
		return $this->bitwiseOrHelper($x);
	}

	public function bitwise_xor(BCMath $x)
	{
		return $this->bitwiseXorHelper($x);
	}

	public function bitwise_rightShift($shift)
	{
		$temp = new static();
		$temp->value = bcdiv($this->value, bcpow('2', $shift, 0), 0);

		return $this->normalize($temp);
	}

	public function bitwise_leftShift($shift)
	{
		$temp = new static();
		$temp->value = bcmul($this->value, bcpow('2', $shift, 0), 0);

		return $this->normalize($temp);
	}

	public function compare(BCMath $y)
	{
		return bccomp($this->value, $y->value, 0);
	}

	public function equals(BCMath $x)
	{
		return $this->value == $x->value;
	}

	public function modPow(BCMath $e, BCMath $n)
	{
		return $this->powModOuter($e, $n);
	}

	public function powMod(BCMath $e, BCMath $n)
	{
		return $this->powModOuter($e, $n);
	}

	protected function powModInner(BCMath $e, BCMath $n)
	{
		try {
			$class = static::$modexpEngine[static::class];
			return $class::powModHelper($this, $e, $n, static::class);
		} catch (\Exception $err) {
			return BCMath\DefaultEngine::powModHelper($this, $e, $n, static::class);
		}
	}

	protected function normalize(BCMath $result)
	{
		$result->precision = $this->precision;
		$result->bitmask = $this->bitmask;

		if ($result->bitmask !== false) {
			$result->value = bcmod($result->value, $result->bitmask->value);
		}

		return $result;
	}

	public static function randomRangePrime(BCMath $min, BCMath $max)
	{
		return self::randomRangePrimeOuter($min, $max);
	}

	public static function randomRange(BCMath $min, BCMath $max)
	{
		return self::randomRangeHelper($min, $max);
	}

	protected function make_odd()
	{
		if (!$this->isOdd()) {
			$this->value = bcadd($this->value, '1');
		}
	}

	protected function testSmallPrimes()
	{
		if ($this->value === '1') {
			return false;
		}
		if ($this->value === '2') {
			return true;
		}
		if ($this->value[strlen($this->value) - 1] % 2 == 0) {
			return false;
		}

		$value = $this->value;

		foreach (self::PRIMES as $prime) {
			$r = bcmod($this->value, $prime);
			if ($r == '0') {
				return $this->value == $prime;
			}
		}

		return true;
	}

	public static function scan1divide(BCMath $r)
	{
		$r_value = &$r->value;
		$s = 0;

		while ($r_value[strlen($r_value) - 1] % 2 == 0) {
			$r_value = bcdiv($r_value, '2', 0);
			++$s;
		}

		return $s;
	}

	public function pow(BCMath $n)
	{
		$temp = new self();
		$temp->value = bcpow($this->value, $n->value);

		return $this->normalize($temp);
	}

	public static function min(BCMath ...$nums)
	{
		return self::minHelper($nums);
	}

	public static function max(BCMath ...$nums)
	{
		return self::maxHelper($nums);
	}

	public function between(BCMath $min, BCMath $max)
	{
		return $this->compare($min) >= 0 && $this->compare($max) <= 0;
	}

	protected static function setBitmask($bits)
	{
		$temp = parent::setBitmask($bits);
		return $temp->add(static::$one[static::class]);
	}

	public function isOdd()
	{
		return $this->value[strlen($this->value) - 1] % 2 == 1;
	}

	public function testBit($x)
	{
		return bccomp(
			bcmod($this->value, bcpow('2', $x + 1, 0)),
			bcpow('2', $x, 0),
			0
		) >= 0;
	}

	public function isNegative()
	{
		return strlen($this->value) && $this->value[0] == '-';
	}

	public function negate()
	{
		$temp = clone $this;

		if (!strlen($temp->value)) {
			return $temp;
		}

		$temp->value = $temp->value[0] == '-' ?
			substr($this->value, 1) :
			'-' . $this->value;

		return $temp;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath {

use phpseclib3\Math\BigInteger\Engines\BCMath;

abstract class Base extends BCMath
{

	const VARIABLE = 0;

	const DATA = 1;

	public static function isValidEngine()
	{
		return static::class != __CLASS__;
	}

	protected static function powModHelper(BCMath $x, BCMath $e, BCMath $n, $class)
	{
		if (empty($e->value)) {
			$temp = new $class();
			$temp->value = '1';
			return $x->normalize($temp);
		}

		return $x->normalize(static::slidingWindow($x, $e, $n, $class));
	}

	protected static function prepareReduce($x, $n, $class)
	{
		return static::reduce($x, $n);
	}

	protected static function multiplyReduce($x, $y, $n, $class)
	{
		return static::reduce(bcmul($x, $y), $n);
	}

	protected static function squareReduce($x, $n, $class)
	{
		return static::reduce(bcmul($x, $x), $n);
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath {

use phpseclib3\Math\BigInteger\Engines\BCMath;

abstract class BuiltIn extends BCMath
{

	protected static function powModHelper(BCMath $x, BCMath $e, BCMath $n)
	{
		$temp = new BCMath();
		$temp->value = bcpowmod($x->value, $e->value, $n->value);

		return $x->normalize($temp);
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath\Reductions {

use phpseclib3\Math\BigInteger\Engines\BCMath\Base;

abstract class Barrett extends Base
{

	const VARIABLE = 0;

	const DATA = 1;

	protected static function reduce($n, $m)
	{
		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		$m_length = strlen($m);

		if (strlen($n) > 2 * $m_length) {
			return bcmod($n, $m);
		}

		if ($m_length < 5) {
			return self::regularBarrett($n, $m);
		}

		$correctionNeeded = false;
		if ($m_length & 1) {
			$correctionNeeded = true;
			$n .= '0';
			$m .= '0';
			$m_length++;
		}

		if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $m;

			$lhs = '1' . str_repeat('0', $m_length + ($m_length >> 1));
			$u = bcdiv($lhs, $m, 0);
			$m1 = bcsub($lhs, bcmul($u, $m));

			$cache[self::DATA][] = [
				'u' => $u,
				'm1' => $m1
			];
		} else {
			extract($cache[self::DATA][$key]);
		}

		$cutoff = $m_length + ($m_length >> 1);

		$lsd = substr($n, -$cutoff);
		$msd = substr($n, 0, -$cutoff);

		$temp = bcmul($msd, $m1);
		$n = bcadd($lsd, $temp);

		$temp = substr($n, 0, -$m_length + 1);

		$temp = bcmul($temp, $u);

		$temp = substr($temp, 0, -($m_length >> 1) - 1);

		$temp = bcmul($temp, $m);

		$result = bcsub($n, $temp);

		if ($result[0] == '-') {
			$temp = '1' . str_repeat('0', $m_length + 1);
			$result = bcadd($result, $temp);
		}

		while (bccomp($result, $m) >= 0) {
			$result = bcsub($result, $m);
		}

		return $correctionNeeded ? substr($result, 0, -1) : $result;
	}

	private static function regularBarrett($x, $n)
	{
		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		$n_length = strlen($n);

		if (strlen($x) > 2 * $n_length) {
			return bcmod($x, $n);
		}

		if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $n;
			$lhs = '1' . str_repeat('0', 2 * $n_length);
			$cache[self::DATA][] = bcdiv($lhs, $n, 0);
		}

		$temp = substr($x, 0, -$n_length + 1);
		$temp = bcmul($temp, $cache[self::DATA][$key]);
		$temp = substr($temp, 0, -$n_length - 1);

		$r1 = substr($x, -$n_length - 1);
		$r2 = substr(bcmul($temp, $n), -$n_length - 1);
		$result = bcsub($r1, $r2);

		if ($result[0] == '-') {
			$q = '1' . str_repeat('0', $n_length + 1);
			$result = bcadd($result, $q);
		}

		while (bccomp($result, $n) >= 0) {
			$result = bcsub($result, $n);
		}

		return $result;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath {

use phpseclib3\Math\BigInteger\Engines\BCMath\Reductions\Barrett;

abstract class DefaultEngine extends Barrett
{
}
}

namespace phpseclib3\Math\BigInteger\Engines {

use phpseclib3\Crypt\RSA\Formats\Keys\PKCS8;
use phpseclib3\Math\BigInteger;

abstract class OpenSSL
{

	public static function isValidEngine()
	{
		return extension_loaded('openssl') && static::class != __CLASS__;
	}

	public static function powModHelper(Engine $x, Engine $e, Engine $n)
	{
		if ($n->getLengthInBytes() < 31 || $n->getLengthInBytes() > 16384) {
			throw new \OutOfRangeException('Only modulo between 31 and 16384 bits are accepted');
		}

		$key = PKCS8::savePublicKey(
			new BigInteger($n),
			new BigInteger($e)
		);

		$plaintext = str_pad($x->toBytes(), $n->getLengthInBytes(), "\0", STR_PAD_LEFT);

		if (!openssl_public_encrypt($plaintext, $result, $key, OPENSSL_NO_PADDING)) {
			throw new \UnexpectedValueException(openssl_error_string());
		}

		$class = get_class($x);
		return new $class($result, 256);
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath {

use phpseclib3\Math\BigInteger\Engines\OpenSSL as Progenitor;

abstract class OpenSSL extends Progenitor
{
}
}

namespace phpseclib3\Math\BigInteger\Engines\BCMath\Reductions {

use phpseclib3\Math\BigInteger\Engines\BCMath;
use phpseclib3\Math\BigInteger\Engines\BCMath\Base;

abstract class EvalBarrett extends Base
{

	private static $custom_reduction;

	protected static function reduce($n, $m)
	{
		$inline = self::$custom_reduction;
		return $inline($n);
	}

	protected static function generateCustomReduction(BCMath $m, $class)
	{
		$m_length = strlen($m);

		if ($m_length < 5) {
			$code = 'return bcmod($x, $n);';
			eval('$func = function ($n) { ' . $code . '};');
			self::$custom_reduction = $func;
			return;
		}

		$lhs = '1' . str_repeat('0', $m_length + ($m_length >> 1));
		$u = bcdiv($lhs, $m, 0);
		$m1 = bcsub($lhs, bcmul($u, $m));

		$cutoff = $m_length + ($m_length >> 1);

		$m = "'$m'";
		$u = "'$u'";
		$m1 = "'$m1'";

		$code = '
            $lsd = substr($n, -' . $cutoff . ');
            $msd = substr($n, 0, -' . $cutoff . ');

            $temp = bcmul($msd, ' . $m1 . ');
            $n = bcadd($lsd, $temp);

            $temp = substr($n, 0, ' . (-$m_length + 1) . ');
            $temp = bcmul($temp, ' . $u . ');
            $temp = substr($temp, 0, ' . (-($m_length >> 1) - 1) . ');
            $temp = bcmul($temp, ' . $m . ');

            $result = bcsub($n, $temp);

            if ($result[0] == \'-\') {
                $temp = \'1' . str_repeat('0', $m_length + 1) . '\';
                $result = bcadd($result, $temp);
            }

            while (bccomp($result, ' . $m . ') >= 0) {
                $result = bcsub($result, ' . $m . ');
            }

            return $result;';

		eval('$func = function ($n) { ' . $code . '};');

		self::$custom_reduction = $func;

		return $func;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

use phpseclib3\Exception\BadConfigurationException;

class GMP extends Engine
{

	const FAST_BITWISE = true;

	const ENGINE_DIR = 'GMP';

	public static function isValidEngine()
	{
		return extension_loaded('gmp');
	}

	public function __construct($x = 0, $base = 10)
	{
		if (!isset(static::$isValidEngine[static::class])) {
			static::$isValidEngine[static::class] = self::isValidEngine();
		}
		if (!static::$isValidEngine[static::class]) {
			throw new BadConfigurationException('GMP is not setup correctly on this system');
		}

		if ($x instanceof \GMP) {
			$this->value = $x;
			return;
		}

		$this->value = gmp_init(0);

		parent::__construct($x, $base);
	}

	protected function initialize($base)
	{
		switch (abs($base)) {
			case 256:
				$this->value = gmp_import($this->value);
				if ($this->is_negative) {
					$this->value = -$this->value;
				}
				break;
			case 16:
				$temp = $this->is_negative ? '-0x' . $this->value : '0x' . $this->value;
				$this->value = gmp_init($temp);
				break;
			case 10:
				$this->value = gmp_init(isset($this->value) ? $this->value : '0');
		}
	}

	public function toString()
	{
		return (string)$this->value;
	}

	public function toBits($twos_compliment = false)
	{
		$hex = $this->toHex($twos_compliment);

		$bits = gmp_strval(gmp_init($hex, 16), 2);

		if ($this->precision > 0) {
			$bits = substr($bits, -$this->precision);
		}

		if ($twos_compliment && $this->compare(new static()) > 0 && $this->precision <= 0) {
			return '0' . $bits;
		}

		return $bits;
	}

	public function toBytes($twos_compliment = false)
	{
		if ($twos_compliment) {
			return $this->toBytesHelper();
		}

		if (gmp_cmp($this->value, gmp_init(0)) == 0) {
			return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
		}

		$temp = gmp_export($this->value);

		return $this->precision > 0 ?
			substr(str_pad($temp, $this->precision >> 3, chr(0), STR_PAD_LEFT), -($this->precision >> 3)) :
			ltrim($temp, chr(0));
	}

	public function add(GMP $y)
	{
		$temp = new self();
		$temp->value = $this->value + $y->value;

		return $this->normalize($temp);
	}

	public function subtract(GMP $y)
	{
		$temp = new self();
		$temp->value = $this->value - $y->value;

		return $this->normalize($temp);
	}

	public function multiply(GMP $x)
	{
		$temp = new self();
		$temp->value = $this->value * $x->value;

		return $this->normalize($temp);
	}

	public function divide(GMP $y)
	{
		$quotient = new self();
		$remainder = new self();

		list($quotient->value, $remainder->value) = gmp_div_qr($this->value, $y->value);

		if (gmp_sign($remainder->value) < 0) {
			$remainder->value = $remainder->value + gmp_abs($y->value);
		}

		return [$this->normalize($quotient), $this->normalize($remainder)];
	}

	public function compare(GMP $y)
	{
		$r = gmp_cmp($this->value, $y->value);
		if ($r < -1) {
			$r = -1;
		}
		if ($r > 1) {
			$r = 1;
		}
		return $r;
	}

	public function equals(GMP $x)
	{
		return $this->value == $x->value;
	}

	public function modInverse(GMP $n)
	{
		$temp = new self();
		$temp->value = gmp_invert($this->value, $n->value);

		return $temp->value === false ? false : $this->normalize($temp);
	}

	public function extendedGCD(GMP $n)
	{
		extract(gmp_gcdext($this->value, $n->value));

		return [
			'gcd' => $this->normalize(new self($g)),
			'x' => $this->normalize(new self($s)),
			'y' => $this->normalize(new self($t))
		];
	}

	public function gcd(GMP $n)
	{
		$r = gmp_gcd($this->value, $n->value);
		return $this->normalize(new self($r));
	}

	public function abs()
	{
		$temp = new self();
		$temp->value = gmp_abs($this->value);

		return $temp;
	}

	public function bitwise_and(GMP $x)
	{
		$temp = new self();
		$temp->value = $this->value & $x->value;

		return $this->normalize($temp);
	}

	public function bitwise_or(GMP $x)
	{
		$temp = new self();
		$temp->value = $this->value | $x->value;

		return $this->normalize($temp);
	}

	public function bitwise_xor(GMP $x)
	{
		$temp = new self();
		$temp->value = $this->value ^ $x->value;

		return $this->normalize($temp);
	}

	public function bitwise_rightShift($shift)
	{

		$temp = new self();
		$temp->value = $this->value >> $shift;

		return $this->normalize($temp);
	}

	public function bitwise_leftShift($shift)
	{
		$temp = new self();
		$temp->value = $this->value << $shift;

		return $this->normalize($temp);
	}

	public function modPow(GMP $e, GMP $n)
	{
		return $this->powModOuter($e, $n);
	}

	public function powMod(GMP $e, GMP $n)
	{
		return $this->powModOuter($e, $n);
	}

	protected function powModInner(GMP $e, GMP $n)
	{
		$class = static::$modexpEngine[static::class];
		return $class::powModHelper($this, $e, $n);
	}

	protected function normalize(GMP $result)
	{
		$result->precision = $this->precision;
		$result->bitmask = $this->bitmask;

		if ($result->bitmask !== false) {
			$flip = $result->value < 0;
			if ($flip) {
				$result->value = -$result->value;
			}
			$result->value = $result->value & $result->bitmask->value;
			if ($flip) {
				$result->value = -$result->value;
			}
		}

		return $result;
	}

	protected static function randomRangePrimeInner(Engine $x, Engine $min, Engine $max)
	{
		$p = gmp_nextprime($x->value);

		if ($p <= $max->value) {
			return new self($p);
		}

		if ($min->value != $x->value) {
			$x = new self($x->value - 1);
		}

		return self::randomRangePrime($min, $x);
	}

	public static function randomRangePrime(GMP $min, GMP $max)
	{
		return self::randomRangePrimeOuter($min, $max);
	}

	public static function randomRange(GMP $min, GMP $max)
	{
		return self::randomRangeHelper($min, $max);
	}

	protected function make_odd()
	{
		gmp_setbit($this->value, 0);
	}

	protected function testPrimality($t)
	{
		return gmp_prob_prime($this->value, $t) != 0;
	}

	protected function rootInner($n)
	{
		$root = new self();
		$root->value = gmp_root($this->value, $n);
		return $this->normalize($root);
	}

	public function pow(GMP $n)
	{
		$temp = new self();
		$temp->value = $this->value ** $n->value;

		return $this->normalize($temp);
	}

	public static function min(GMP ...$nums)
	{
		return self::minHelper($nums);
	}

	public static function max(GMP ...$nums)
	{
		return self::maxHelper($nums);
	}

	public function between(GMP $min, GMP $max)
	{
		return $this->compare($min) >= 0 && $this->compare($max) <= 0;
	}

	public function createRecurringModuloFunction()
	{
		$temp = $this->value;
		return function (GMP $x) use ($temp) {
			return new GMP($x->value % $temp);
		};
	}

	public static function scan1divide(GMP $r)
	{
		$s = gmp_scan1($r->value, 0);
		$r->value >>= $s;
		return $s;
	}

	public function isOdd()
	{
		return gmp_testbit($this->value, 0);
	}

	public function testBit($x)
	{
		return gmp_testbit($this->value, $x);
	}

	public function isNegative()
	{
		return gmp_sign($this->value) == -1;
	}

	public function negate()
	{
		$temp = clone $this;
		$temp->value = -$this->value;

		return $temp;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\GMP {

use phpseclib3\Math\BigInteger\Engines\GMP;

abstract class DefaultEngine extends GMP
{

	protected static function powModHelper(GMP $x, GMP $e, GMP $n)
	{
		$temp = new GMP();
		$temp->value = gmp_powm($x->value, $e->value, $n->value);

		return $x->normalize($temp);
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Exception\BadConfigurationException;

abstract class PHP extends Engine
{

	const VALUE = 0;

	const SIGN = 1;

	const KARATSUBA_CUTOFF = 25;

	const FAST_BITWISE = true;

	const ENGINE_DIR = 'PHP';

	public function __construct($x = 0, $base = 10)
	{
		if (!isset(static::$isValidEngine[static::class])) {
			static::$isValidEngine[static::class] = static::isValidEngine();
		}
		if (!static::$isValidEngine[static::class]) {
			throw new BadConfigurationException(static::class . ' is not setup correctly on this system');
		}

		$this->value = [];
		parent::__construct($x, $base);
	}

	protected function initialize($base)
	{
		switch (abs($base)) {
			case 16:
				$x = (strlen($this->value) & 1) ? '0' . $this->value : $this->value;
				$temp = new static(Strings::hex2bin($x), 256);
				$this->value = $temp->value;
				break;
			case 10:
				$temp = new static();

				$multiplier = new static();
				$multiplier->value = [static::MAX10];

				$x = $this->value;

				if ($x[0] == '-') {
					$this->is_negative = true;
					$x = substr($x, 1);
				}

				$x = str_pad(
					$x,
					strlen($x) + ((static::MAX10LEN - 1) * strlen($x)) % static::MAX10LEN,
					0,
					STR_PAD_LEFT
				);
				while (strlen($x)) {
					$temp = $temp->multiply($multiplier);
					$temp = $temp->add(new static($this->int2bytes(substr($x, 0, static::MAX10LEN)), 256));
					$x = substr($x, static::MAX10LEN);
				}

				$this->value = $temp->value;
		}
	}

	protected function pad($str)
	{
		$length = strlen($str);

		$pad = 4 - (strlen($str) % 4);

		return str_pad($str, $length + $pad, "\0", STR_PAD_LEFT);
	}

	public function toString()
	{
		if (!count($this->value)) {
			return '0';
		}

		$temp = clone $this;
		$temp->bitmask = false;
		$temp->is_negative = false;

		$divisor = new static();
		$divisor->value = [static::MAX10];
		$result = '';
		while (count($temp->value)) {
			list($temp, $mod) = $temp->divide($divisor);
			$result = str_pad(
				isset($mod->value[0]) ? $mod->value[0] : '',
				static::MAX10LEN,
				'0',
				STR_PAD_LEFT
			) . $result;
		}
		$result = ltrim($result, '0');
		if (empty($result)) {
			$result = '0';
		}

		if ($this->is_negative) {
			$result = '-' . $result;
		}

		return $result;
	}

	public function toBytes($twos_compliment = false)
	{
		if ($twos_compliment) {
			return $this->toBytesHelper();
		}

		if (!count($this->value)) {
			return $this->precision > 0 ? str_repeat(chr(0), ($this->precision + 1) >> 3) : '';
		}

		$result = $this->bitwise_small_split(8);
		$result = implode('', array_map('chr', $result));

		return $this->precision > 0 ?
			str_pad(
				substr($result, -(($this->precision + 7) >> 3)),
				($this->precision + 7) >> 3,
				chr(0),
				STR_PAD_LEFT
			) :
			$result;
	}

	protected static function addHelper(array $x_value, $x_negative, array $y_value, $y_negative)
	{
		$x_size = count($x_value);
		$y_size = count($y_value);

		if ($x_size == 0) {
			return [
				self::VALUE => $y_value,
				self::SIGN => $y_negative
			];
		} elseif ($y_size == 0) {
			return [
				self::VALUE => $x_value,
				self::SIGN => $x_negative
			];
		}

		if ($x_negative != $y_negative) {
			if ($x_value == $y_value) {
				return [
					self::VALUE => [],
					self::SIGN => false
				];
			}

			$temp = self::subtractHelper($x_value, false, $y_value, false);
			$temp[self::SIGN] = self::compareHelper($x_value, false, $y_value, false) > 0 ?
				$x_negative : $y_negative;

			return $temp;
		}

		if ($x_size < $y_size) {
			$size = $x_size;
			$value = $y_value;
		} else {
			$size = $y_size;
			$value = $x_value;
		}

		$value[count($value)] = 0;

		$carry = 0;
		for ($i = 0, $j = 1; $j < $size; $i += 2, $j += 2) {

			$sum = ($x_value[$j] + $y_value[$j]) * static::BASE_FULL + $x_value[$i] + $y_value[$i] + $carry;
			$carry = $sum >= static::MAX_DIGIT2;
			$sum = $carry ? $sum - static::MAX_DIGIT2 : $sum;

			$temp = static::BASE === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

			$value[$i] = (int)($sum - static::BASE_FULL * $temp);
			$value[$j] = $temp;
		}

		if ($j == $size) {
			$sum = $x_value[$i] + $y_value[$i] + $carry;
			$carry = $sum >= static::BASE_FULL;
			$value[$i] = $carry ? $sum - static::BASE_FULL : $sum;
			++$i;
		}

		if ($carry) {
			for (; $value[$i] == static::MAX_DIGIT; ++$i) {
				$value[$i] = 0;
			}
			++$value[$i];
		}

		return [
			self::VALUE => self::trim($value),
			self::SIGN => $x_negative
		];
	}

	public static function subtractHelper(array $x_value, $x_negative, array $y_value, $y_negative)
	{
		$x_size = count($x_value);
		$y_size = count($y_value);

		if ($x_size == 0) {
			return [
				self::VALUE => $y_value,
				self::SIGN => !$y_negative
			];
		} elseif ($y_size == 0) {
			return [
				self::VALUE => $x_value,
				self::SIGN => $x_negative
			];
		}

		if ($x_negative != $y_negative) {
			$temp = self::addHelper($x_value, false, $y_value, false);
			$temp[self::SIGN] = $x_negative;

			return $temp;
		}

		$diff = self::compareHelper($x_value, $x_negative, $y_value, $y_negative);

		if (!$diff) {
			return [
				self::VALUE => [],
				self::SIGN => false
			];
		}

		if ((!$x_negative && $diff < 0) || ($x_negative && $diff > 0)) {
			$temp = $x_value;
			$x_value = $y_value;
			$y_value = $temp;

			$x_negative = !$x_negative;

			$x_size = count($x_value);
			$y_size = count($y_value);
		}

		$carry = 0;
		for ($i = 0, $j = 1; $j < $y_size; $i += 2, $j += 2) {
			$sum = ($x_value[$j] - $y_value[$j]) * static::BASE_FULL + $x_value[$i] - $y_value[$i] - $carry;

			$carry = $sum < 0;
			$sum = $carry ? $sum + static::MAX_DIGIT2 : $sum;

			$temp = static::BASE === 26 ? intval($sum / 0x4000000) : ($sum >> 31);

			$x_value[$i] = (int)($sum - static::BASE_FULL * $temp);
			$x_value[$j] = $temp;
		}

		if ($j == $y_size) {
			$sum = $x_value[$i] - $y_value[$i] - $carry;
			$carry = $sum < 0;
			$x_value[$i] = $carry ? $sum + static::BASE_FULL : $sum;
			++$i;
		}

		if ($carry) {
			for (; !$x_value[$i]; ++$i) {
				$x_value[$i] = static::MAX_DIGIT;
			}
			--$x_value[$i];
		}

		return [
			self::VALUE => self::trim($x_value),
			self::SIGN => $x_negative
		];
	}

	protected static function multiplyHelper(array $x_value, $x_negative, array $y_value, $y_negative)
	{

		$x_length = count($x_value);
		$y_length = count($y_value);

		if (!$x_length || !$y_length) {
			return [
				self::VALUE => [],
				self::SIGN => false
			];
		}

		return [
			self::VALUE => min($x_length, $y_length) < 2 * self::KARATSUBA_CUTOFF ?
				self::trim(self::regularMultiply($x_value, $y_value)) :
				self::trim(self::karatsuba($x_value, $y_value)),
			self::SIGN => $x_negative != $y_negative
		];
	}

	private static function karatsuba(array $x_value, array $y_value)
	{
		$m = min(count($x_value) >> 1, count($y_value) >> 1);

		if ($m < self::KARATSUBA_CUTOFF) {
			return self::regularMultiply($x_value, $y_value);
		}

		$x1 = array_slice($x_value, $m);
		$x0 = array_slice($x_value, 0, $m);
		$y1 = array_slice($y_value, $m);
		$y0 = array_slice($y_value, 0, $m);

		$z2 = self::karatsuba($x1, $y1);
		$z0 = self::karatsuba($x0, $y0);

		$z1 = self::addHelper($x1, false, $x0, false);
		$temp = self::addHelper($y1, false, $y0, false);
		$z1 = self::karatsuba($z1[self::VALUE], $temp[self::VALUE]);
		$temp = self::addHelper($z2, false, $z0, false);
		$z1 = self::subtractHelper($z1, false, $temp[self::VALUE], false);

		$z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
		$z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

		$xy = self::addHelper($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
		$xy = self::addHelper($xy[self::VALUE], $xy[self::SIGN], $z0, false);

		return $xy[self::VALUE];
	}

	protected static function regularMultiply(array $x_value, array $y_value)
	{
		$x_length = count($x_value);
		$y_length = count($y_value);

		if (!$x_length || !$y_length) {
			return [];
		}

		$product_value = self::array_repeat(0, $x_length + $y_length);

		$carry = 0;
		for ($j = 0; $j < $x_length; ++$j) {
			$temp = $x_value[$j] * $y_value[0] + $carry;
			$carry = static::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
			$product_value[$j] = (int)($temp - static::BASE_FULL * $carry);
		}

		$product_value[$j] = $carry;

		for ($i = 1; $i < $y_length; ++$i) {
			$carry = 0;

			for ($j = 0, $k = $i; $j < $x_length; ++$j, ++$k) {
				$temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
				$carry = static::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
				$product_value[$k] = (int)($temp - static::BASE_FULL * $carry);
			}

			$product_value[$k] = $carry;
		}

		return $product_value;
	}

	protected function divideHelper(PHP $y)
	{
		if (count($y->value) == 1) {
			list($q, $r) = $this->divide_digit($this->value, $y->value[0]);
			$quotient = new static();
			$remainder = new static();
			$quotient->value = $q;
			$remainder->value = [$r];
			$quotient->is_negative = $this->is_negative != $y->is_negative;
			return [$this->normalize($quotient), $this->normalize($remainder)];
		}

		$x = clone $this;
		$y = clone $y;

		$x_sign = $x->is_negative;
		$y_sign = $y->is_negative;

		$x->is_negative = $y->is_negative = false;

		$diff = $x->compare($y);

		if (!$diff) {
			$temp = new static();
			$temp->value = [1];
			$temp->is_negative = $x_sign != $y_sign;
			return [$this->normalize($temp), $this->normalize(static::$zero[static::class])];
		}

		if ($diff < 0) {

			if ($x_sign) {
				$x = $y->subtract($x);
			}
			return [$this->normalize(static::$zero[static::class]), $this->normalize($x)];
		}

		$msb = $y->value[count($y->value) - 1];
		for ($shift = 0; !($msb & static::MSB); ++$shift) {
			$msb <<= 1;
		}
		$x->lshift($shift);
		$y->lshift($shift);
		$y_value = &$y->value;

		$x_max = count($x->value) - 1;
		$y_max = count($y->value) - 1;

		$quotient = new static();
		$quotient_value = &$quotient->value;
		$quotient_value = self::array_repeat(0, $x_max - $y_max + 1);

		static $temp, $lhs, $rhs;
		if (!isset($temp)) {
			$temp = new static();
			$lhs = new static();
			$rhs = new static();
		}
		if (static::class != get_class($temp)) {
			$temp = new static();
			$lhs = new static();
			$rhs = new static();
		}
		$temp_value = &$temp->value;
		$rhs_value =	&$rhs->value;

		$temp_value = array_merge(self::array_repeat(0, $x_max - $y_max), $y_value);

		while ($x->compare($temp) >= 0) {

			++$quotient_value[$x_max - $y_max];
			$x = $x->subtract($temp);
			$x_max = count($x->value) - 1;
		}

		for ($i = $x_max; $i >= $y_max + 1; --$i) {
			$x_value = &$x->value;
			$x_window = [
				isset($x_value[$i]) ? $x_value[$i] : 0,
				isset($x_value[$i - 1]) ? $x_value[$i - 1] : 0,
				isset($x_value[$i - 2]) ? $x_value[$i - 2] : 0
			];
			$y_window = [
				$y_value[$y_max],
				($y_max > 0) ? $y_value[$y_max - 1] : 0
			];

			$q_index = $i - $y_max - 1;
			if ($x_window[0] == $y_window[0]) {
				$quotient_value[$q_index] = static::MAX_DIGIT;
			} else {
				$quotient_value[$q_index] = self::safe_divide(
					$x_window[0] * static::BASE_FULL + $x_window[1],
					$y_window[0]
				);
			}

			$temp_value = [$y_window[1], $y_window[0]];

			$lhs->value = [$quotient_value[$q_index]];
			$lhs = $lhs->multiply($temp);

			$rhs_value = [$x_window[2], $x_window[1], $x_window[0]];

			while ($lhs->compare($rhs) > 0) {
				--$quotient_value[$q_index];

				$lhs->value = [$quotient_value[$q_index]];
				$lhs = $lhs->multiply($temp);
			}

			$adjust = self::array_repeat(0, $q_index);
			$temp_value = [$quotient_value[$q_index]];
			$temp = $temp->multiply($y);
			$temp_value = &$temp->value;
			if (count($temp_value)) {
				$temp_value = array_merge($adjust, $temp_value);
			}

			$x = $x->subtract($temp);

			if ($x->compare(static::$zero[static::class]) < 0) {
				$temp_value = array_merge($adjust, $y_value);
				$x = $x->add($temp);

				--$quotient_value[$q_index];
			}

			$x_max = count($x_value) - 1;
		}

		$x->rshift($shift);

		$quotient->is_negative = $x_sign != $y_sign;

		if ($x_sign) {
			$y->rshift($shift);
			$x = $y->subtract($x);
		}

		return [$this->normalize($quotient), $this->normalize($x)];
	}

	private static function divide_digit(array $dividend, $divisor)
	{
		$carry = 0;
		$result = [];

		for ($i = count($dividend) - 1; $i >= 0; --$i) {
			$temp = static::BASE_FULL * $carry + $dividend[$i];
			$result[$i] = self::safe_divide($temp, $divisor);
			$carry = (int)($temp - $divisor * $result[$i]);
		}

		return [$result, $carry];
	}

	private static function safe_divide($x, $y)
	{
		if (static::BASE === 26) {
			return (int)($x / $y);
		}

		return ($x - ($x % $y)) / $y;
	}

	protected function convertToObj(array $arr)
	{
		$result = new static();
		$result->value = $arr[self::VALUE];
		$result->is_negative = $arr[self::SIGN];

		return $this->normalize($result);
	}

	protected function normalize(PHP $result)
	{
		$result->precision = $this->precision;
		$result->bitmask = $this->bitmask;

		$value = &$result->value;

		if (!count($value)) {
			$result->is_negative = false;
			return $result;
		}

		$value = static::trim($value);

		if (!empty($result->bitmask->value)) {
			$length = min(count($value), count($result->bitmask->value));
			$value = array_slice($value, 0, $length);

			for ($i = 0; $i < $length; ++$i) {
				$value[$i] = $value[$i] & $result->bitmask->value[$i];
			}

			$value = static::trim($value);
		}

		return $result;
	}

	protected static function compareHelper(array $x_value, $x_negative, array $y_value, $y_negative)
	{
		if ($x_negative != $y_negative) {
			return (!$x_negative && $y_negative) ? 1 : -1;
		}

		$result = $x_negative ? -1 : 1;

		if (count($x_value) != count($y_value)) {
			return (count($x_value) > count($y_value)) ? $result : -$result;
		}
		$size = max(count($x_value), count($y_value));

		$x_value = array_pad($x_value, $size, 0);
		$y_value = array_pad($y_value, $size, 0);

		for ($i = count($x_value) - 1; $i >= 0; --$i) {
			if ($x_value[$i] != $y_value[$i]) {
				return ($x_value[$i] > $y_value[$i]) ? $result : -$result;
			}
		}

		return 0;
	}

	public function abs()
	{
		$temp = new static();
		$temp->value = $this->value;

		return $temp;
	}

	protected static function trim(array $value)
	{
		for ($i = count($value) - 1; $i >= 0; --$i) {
			if ($value[$i]) {
				break;
			}
			unset($value[$i]);
		}

		return $value;
	}

	public function bitwise_rightShift($shift)
	{
		$temp = new static();

		$temp->value = $this->value;
		$temp->rshift($shift);

		return $this->normalize($temp);
	}

	public function bitwise_leftShift($shift)
	{
		$temp = new static();

		$temp->value = $this->value;
		$temp->lshift($shift);

		return $this->normalize($temp);
	}

	private static function int2bytes($x)
	{
		return ltrim(pack('N', $x), chr(0));
	}

	protected static function array_repeat($input, $multiplier)
	{
		return $multiplier ? array_fill(0, $multiplier, $input) : [];
	}

	protected function lshift($shift)
	{
		if ($shift == 0) {
			return;
		}

		$num_digits = (int)($shift / static::BASE);
		$shift %= static::BASE;
		$shift = 1 << $shift;

		$carry = 0;

		for ($i = 0; $i < count($this->value); ++$i) {
			$temp = $this->value[$i] * $shift + $carry;
			$carry = static::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
			$this->value[$i] = (int)($temp - $carry * static::BASE_FULL);
		}

		if ($carry) {
			$this->value[count($this->value)] = $carry;
		}

		while ($num_digits--) {
			array_unshift($this->value, 0);
		}
	}

	protected function rshift($shift)
	{
		if ($shift == 0) {
			return;
		}

		$num_digits = (int)($shift / static::BASE);
		$shift %= static::BASE;
		$carry_shift = static::BASE - $shift;
		$carry_mask = (1 << $shift) - 1;

		if ($num_digits) {
			$this->value = array_slice($this->value, $num_digits);
		}

		$carry = 0;

		for ($i = count($this->value) - 1; $i >= 0; --$i) {
			$temp = $this->value[$i] >> $shift | $carry;
			$carry = ($this->value[$i] & $carry_mask) << $carry_shift;
			$this->value[$i] = $temp;
		}

		$this->value = static::trim($this->value);
	}

	protected function powModInner(PHP $e, PHP $n)
	{
		try {
			$class = static::$modexpEngine[static::class];
			return $class::powModHelper($this, $e, $n, static::class);
		} catch (\Exception $err) {
			return PHP\DefaultEngine::powModHelper($this, $e, $n, static::class);
		}
	}

	protected static function square(array $x)
	{
		return count($x) < 2 * self::KARATSUBA_CUTOFF ?
			self::trim(self::baseSquare($x)) :
			self::trim(self::karatsubaSquare($x));
	}

	protected static function baseSquare(array $value)
	{
		if (empty($value)) {
			return [];
		}
		$square_value = self::array_repeat(0, 2 * count($value));

		for ($i = 0, $max_index = count($value) - 1; $i <= $max_index; ++$i) {
			$i2 = $i << 1;

			$temp = $square_value[$i2] + $value[$i] * $value[$i];
			$carry = static::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
			$square_value[$i2] = (int)($temp - static::BASE_FULL * $carry);

			for ($j = $i + 1, $k = $i2 + 1; $j <= $max_index; ++$j, ++$k) {
				$temp = $square_value[$k] + 2 * $value[$j] * $value[$i] + $carry;
				$carry = static::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
				$square_value[$k] = (int)($temp - static::BASE_FULL * $carry);
			}

			$square_value[$i + $max_index + 1] = $carry;
		}

		return $square_value;
	}

	protected static function karatsubaSquare(array $value)
	{
		$m = count($value) >> 1;

		if ($m < self::KARATSUBA_CUTOFF) {
			return self::baseSquare($value);
		}

		$x1 = array_slice($value, $m);
		$x0 = array_slice($value, 0, $m);

		$z2 = self::karatsubaSquare($x1);
		$z0 = self::karatsubaSquare($x0);

		$z1 = self::addHelper($x1, false, $x0, false);
		$z1 = self::karatsubaSquare($z1[self::VALUE]);
		$temp = self::addHelper($z2, false, $z0, false);
		$z1 = self::subtractHelper($z1, false, $temp[self::VALUE], false);

		$z2 = array_merge(array_fill(0, 2 * $m, 0), $z2);
		$z1[self::VALUE] = array_merge(array_fill(0, $m, 0), $z1[self::VALUE]);

		$xx = self::addHelper($z2, false, $z1[self::VALUE], $z1[self::SIGN]);
		$xx = self::addHelper($xx[self::VALUE], $xx[self::SIGN], $z0, false);

		return $xx[self::VALUE];
	}

	protected function make_odd()
	{
		$this->value[0] |= 1;
	}

	protected function testSmallPrimes()
	{
		if ($this->value == [1]) {
			return false;
		}
		if ($this->value == [2]) {
			return true;
		}
		if (~$this->value[0] & 1) {
			return false;
		}

		$value = $this->value;
		foreach (static::PRIMES as $prime) {
			list(, $r) = self::divide_digit($value, $prime);
			if (!$r) {
				return count($value) == 1 && $value[0] == $prime;
			}
		}

		return true;
	}

	public static function scan1divide(PHP $r)
	{
		$r_value = &$r->value;
		for ($i = 0, $r_length = count($r_value); $i < $r_length; ++$i) {
			$temp = ~$r_value[$i] & static::MAX_DIGIT;
			for ($j = 1; ($temp >> $j) & 1; ++$j) {
			}
			if ($j <= static::BASE) {
				break;
			}
		}
		$s = static::BASE * $i + $j;
		$r->rshift($s);
		return $s;
	}

	protected function powHelper(PHP $n)
	{
		if ($n->compare(static::$zero[static::class]) == 0) {
			return new static(1);
		}

		$temp = clone $this;
		while (!$n->equals(static::$one[static::class])) {
			$temp = $temp->multiply($this);
			$n = $n->subtract(static::$one[static::class]);
		}

		return $temp;
	}

	public function isOdd()
	{
		return (bool)($this->value[0] & 1);
	}

	public function testBit($x)
	{
		$digit = (int) floor($x / static::BASE);
		$bit = $x % static::BASE;

		if (!isset($this->value[$digit])) {
			return false;
		}

		return (bool)($this->value[$digit] & (1 << $bit));
	}

	public function isNegative()
	{
		return $this->is_negative;
	}

	public function negate()
	{
		$temp = clone $this;
		$temp->is_negative = !$temp->is_negative;

		return $temp;
	}

	public function bitwise_split($split)
	{
		if ($split < 1) {
			throw new \RuntimeException('Offset must be greater than 1');
		}

		$width = (int)($split / static::BASE);
		if (!$width) {
			$arr = $this->bitwise_small_split($split);
			return array_map(function ($digit) {
				$temp = new static();
				$temp->value = $digit != 0 ? [$digit] : [];
				return $temp;
			}, $arr);
		}

		$vals = [];
		$val = $this->value;

		$i = $overflow = 0;
		$len = count($val);
		while ($i < $len) {
			$digit = [];
			if (!$overflow) {
				$digit = array_slice($val, $i, $width);
				$i += $width;
				$overflow = $split % static::BASE;
				if ($overflow) {
					$mask = (1 << $overflow) - 1;
					$temp = isset($val[$i]) ? $val[$i] : 0;
					$digit[] = $temp & $mask;
				}
			} else {
				$remaining = static::BASE - $overflow;
				$tempsplit = $split - $remaining;
				$tempwidth = (int)($tempsplit / static::BASE + 1);
				$digit = array_slice($val, $i, $tempwidth);
				$i += $tempwidth;
				$tempoverflow = $tempsplit % static::BASE;
				if ($tempoverflow) {
					$tempmask = (1 << $tempoverflow) - 1;
					$temp = isset($val[$i]) ? $val[$i] : 0;
					$digit[] = $temp & $tempmask;
				}
				$newbits = 0;
				for ($j = count($digit) - 1; $j >= 0; $j--) {
					$temp = $digit[$j] & $mask;
					$digit[$j] = ($digit[$j] >> $overflow) | ($newbits << $remaining);
					$newbits = $temp;
				}
				$overflow = $tempoverflow;
				$mask = $tempmask;
			}
			$temp = new static();
			$temp->value = static::trim($digit);
			$vals[] = $temp;
		}

		return array_reverse($vals);
	}

	private function bitwise_small_split($split)
	{
		$vals = [];
		$val = $this->value;

		$mask = (1 << $split) - 1;

		$i = $overflow = 0;
		$len = count($val);
		$val[] = 0;
		$remaining = static::BASE;
		while ($i != $len) {
			$digit = $val[$i] & $mask;
			$val[$i] >>= $split;
			if (!$overflow) {
				$remaining -= $split;
				$overflow = $split <= $remaining ? 0 : $split - $remaining;

				if (!$remaining) {
					$i++;
					$remaining = static::BASE;
					$overflow = 0;
				}
			} elseif (++$i != $len) {
				$tempmask = (1 << $overflow) - 1;
				$digit |= ($val[$i] & $tempmask) << $remaining;
				$val[$i] >>= $overflow;
				$remaining = static::BASE - $overflow;
				$overflow = $split <= $remaining ? 0 : $split - $remaining;
			}

			$vals[] = $digit;
		}

		while ($vals[count($vals) - 1] == 0) {
			unset($vals[count($vals) - 1]);
		}

		return array_reverse($vals);
	}

	protected static function testJITOnWindows()
	{

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && function_exists('opcache_get_status') && PHP_VERSION_ID < 80213 && !defined('PHPSECLIB_ALLOW_JIT')) {
			$status = opcache_get_status();
			if ($status && isset($status['jit']) && $status['jit']['enabled'] && $status['jit']['on']) {
				return true;
			}
		}
		return false;
	}

	public function getLength()
	{
		$max = count($this->value) - 1;
		return $max != -1 ?
			$max * static::BASE + intval(ceil(log($this->value[$max] + 1, 2))) :
			0;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP {

use phpseclib3\Math\BigInteger\Engines\PHP;

abstract class Base extends PHP
{

	const VARIABLE = 0;

	const DATA = 1;

	public static function isValidEngine()
	{
		return static::class != __CLASS__;
	}

	protected static function powModHelper(PHP $x, PHP $e, PHP $n, $class)
	{
		if (empty($e->value)) {
			$temp = new $class();
			$temp->value = [1];
			return $x->normalize($temp);
		}

		if ($e->value == [1]) {
			list(, $temp) = $x->divide($n);
			return $x->normalize($temp);
		}

		if ($e->value == [2]) {
			$temp = new $class();
			$temp->value = $class::square($x->value);
			list(, $temp) = $temp->divide($n);
			return $x->normalize($temp);
		}

		return $x->normalize(static::slidingWindow($x, $e, $n, $class));
	}

	protected static function prepareReduce(array $x, array $n, $class)
	{
		return static::reduce($x, $n, $class);
	}

	protected static function multiplyReduce(array $x, array $y, array $n, $class)
	{
		$temp = $class::multiplyHelper($x, false, $y, false);
		return static::reduce($temp[self::VALUE], $n, $class);
	}

	protected static function squareReduce(array $x, array $n, $class)
	{
		return static::reduce($class::square($x), $n, $class);
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP;
use phpseclib3\Math\BigInteger\Engines\PHP\Base;

abstract class EvalBarrett extends Base
{

	private static $custom_reduction;

	protected static function reduce(array $n, array $m, $class)
	{
		$inline = self::$custom_reduction;
		return $inline($n);
	}

	protected static function generateCustomReduction(PHP $m, $class)
	{
		$m_length = count($m->value);

		if ($m_length < 5) {
			$code = '
                $lhs = new ' . $class . '();
                $lhs->value = $x;
                $rhs = new ' . $class . '();
                $rhs->value = [' .
				implode(',', array_map(self::class . '::float2string', $m->value)) . '];
                list(, $temp) = $lhs->divide($rhs);
                return $temp->value;
            ';
			eval('$func = function ($x) { ' . $code . '};');
			self::$custom_reduction = $func;

			return $func;
		}

		$correctionNeeded = false;
		if ($m_length & 1) {
			$correctionNeeded = true;
			$m = clone $m;
			array_unshift($m->value, 0);
			$m_length++;
		}

		$lhs = new $class();
		$lhs_value = &$lhs->value;

		$lhs_value = self::array_repeat(0, $m_length + ($m_length >> 1));
		$lhs_value[] = 1;
		$rhs = new $class();

		list($u, $m1) = $lhs->divide($m);

		if ($class::BASE != 26) {
			$u = $u->value;
		} else {
			$lhs_value = self::array_repeat(0, 2 * $m_length);
			$lhs_value[] = 1;
			$rhs = new $class();

			list($u) = $lhs->divide($m);
			$u = $u->value;
		}

		$m = $m->value;
		$m1 = $m1->value;

		$cutoff = count($m) + (count($m) >> 1);

		$code = $correctionNeeded ?
			'array_unshift($n, 0);' :
			'';

		$code .= '
            if (count($n) > ' . (2 * count($m)) . ') {
                $lhs = new ' . $class . '();
                $rhs = new ' . $class . '();
                $lhs->value = $n;
                $rhs->value = [' .
				implode(',', array_map(self::class . '::float2string', $m)) . '];
                list(, $temp) = $lhs->divide($rhs);
                return $temp->value;
            }

            $lsd = array_slice($n, 0, ' . $cutoff . ');
            $msd = array_slice($n, ' . $cutoff . ');';

		$code .= self::generateInlineTrim('msd');
		$code .= self::generateInlineMultiply('msd', $m1, 'temp', $class);
		$code .= self::generateInlineAdd('lsd', 'temp', 'n', $class);

		$code .= '$temp = array_slice($n, ' . (count($m) - 1) . ');';
		$code .= self::generateInlineMultiply('temp', $u, 'temp2', $class);
		$code .= self::generateInlineTrim('temp2');

		$code .= $class::BASE == 26 ?
			'$temp = array_slice($temp2, ' . (count($m) + 1) . ');' :
			'$temp = array_slice($temp2, ' . ((count($m) >> 1) + 1) . ');';
		$code .= self::generateInlineMultiply('temp', $m, 'temp2', $class);
		$code .= self::generateInlineTrim('temp2');

		$code .= self::generateInlineSubtract2('n', 'temp2', 'temp', $class);

		$subcode = self::generateInlineSubtract1('temp', $m, 'temp2', $class);
		$subcode .= '$temp = $temp2;';

		$code .= self::generateInlineCompare($m, 'temp', $subcode);

		if ($correctionNeeded) {
			$code .= 'array_shift($temp);';
		}

		$code .= 'return $temp;';

		eval('$func = function ($n) { ' . $code . '};');

		self::$custom_reduction = $func;

		return $func;

	}

	private static function generateInlineTrim($name)
	{
		return '
            for ($i = count($' . $name . ') - 1; $i >= 0; --$i) {
                if ($' . $name . '[$i]) {
                    break;
                }
                unset($' . $name . '[$i]);
            }';
	}

	private static function generateInlineMultiply($input, array $arr, $output, $class)
	{
		if (!count($arr)) {
			return 'return [];';
		}

		$regular = '
            $length = count($' . $input . ');
            if (!$length) {
                $' . $output . ' = [];
            }else{
            $' . $output . ' = array_fill(0, $length + ' . count($arr) . ', 0);
            $carry = 0;';

		for ($i = 0; $i < count($arr); $i++) {
			$regular .= '
                $subtemp = $' . $input . '[0] * ' . $arr[$i];
			$regular .= $i ? ' + $carry;' : ';';

			$regular .= '$carry = ';
			$regular .= $class::BASE === 26 ?
			'intval($subtemp / 0x4000000);' :
			'$subtemp >> 31;';
			$regular .=
			'$' . $output . '[' . $i . '] = ';
			if ($class::BASE === 26) {
				$regular .= '(int) (';
			}
			$regular .= '$subtemp - ' . $class::BASE_FULL . ' * $carry';
			$regular .= $class::BASE === 26 ? ');' : ';';
		}

		$regular .= '$' . $output . '[' . count($arr) . '] = $carry;';

		$regular .= '
            for ($i = 1; $i < $length; ++$i) {';

		for ($j = 0; $j < count($arr); $j++) {
			$regular .= $j ? '$k++;' : '$k = $i;';
			$regular .= '
                $subtemp = $' . $output . '[$k] + $' . $input . '[$i] * ' . $arr[$j];
			$regular .= $j ? ' + $carry;' : ';';

			$regular .= '$carry = ';
			$regular .= $class::BASE === 26 ?
				'intval($subtemp / 0x4000000);' :
				'$subtemp >> 31;';
			$regular .=
				'$' . $output . '[$k] = ';
			if ($class::BASE === 26) {
				$regular .= '(int) (';
			}
			$regular .= '$subtemp - ' . $class::BASE_FULL . ' * $carry';
			$regular .= $class::BASE === 26 ? ');' : ';';
		}

		$regular .= '$' . $output . '[++$k] = $carry; $carry = 0;';

		$regular .= '}}';

		return $regular;
	}

	private static function generateInlineAdd($x, $y, $result, $class)
	{
		$code = '
            $length = max(count($' . $x . '), count($' . $y . '));
            $' . $result . ' = array_pad($' . $x . ', $length + 1, 0);
            $_' . $y . ' = array_pad($' . $y . ', $length, 0);
            $carry = 0;
            for ($i = 0, $j = 1; $j < $length; $i+=2, $j+=2) {
                $sum = ($' . $result . '[$j] + $_' . $y . '[$j]) * ' . $class::BASE_FULL . '
                           + $' . $result . '[$i] + $_' . $y . '[$i] +
                           $carry;
                $carry = $sum >= ' . self::float2string($class::MAX_DIGIT2) . ';
                $sum = $carry ? $sum - ' . self::float2string($class::MAX_DIGIT2) . ' : $sum;';

			$code .= $class::BASE === 26 ?
				'$upper = intval($sum / 0x4000000); $' . $result . '[$i] = (int) ($sum - ' . $class::BASE_FULL . ' * $upper);' :
				'$upper = $sum >> 31; $' . $result . '[$i] = $sum - ' . $class::BASE_FULL . ' * $upper;';
			$code .= '
                $' . $result . '[$j] = $upper;
            }
            if ($j == $length) {
                $sum = $' . $result . '[$i] + $_' . $y . '[$i] + $carry;
                $carry = $sum >= ' . self::float2string($class::BASE_FULL) . ';
                $' . $result . '[$i] = $carry ? $sum - ' . self::float2string($class::BASE_FULL) . ' : $sum;
                ++$i;
            }
            if ($carry) {
                for (; $' . $result . '[$i] == ' . $class::MAX_DIGIT . '; ++$i) {
                    $' . $result . '[$i] = 0;
                }
                ++$' . $result . '[$i];
            }';
			$code .= self::generateInlineTrim($result);

			return $code;
	}

	private static function generateInlineSubtract2($known, $unknown, $result, $class)
	{
		$code = '
            $' . $result . ' = $' . $known . ';
            $carry = 0;
            $size = count($' . $unknown . ');
            for ($i = 0, $j = 1; $j < $size; $i+= 2, $j+= 2) {
                $sum = ($' . $known . '[$j] - $' . $unknown . '[$j]) * ' . $class::BASE_FULL . ' + $' . $known . '[$i]
                    - $' . $unknown . '[$i]
                    - $carry;
                $carry = $sum < 0;
                if ($carry) {
                    $sum+= ' . self::float2string($class::MAX_DIGIT2) . ';
                }
                $subtemp = ';
		$code .= $class::BASE === 26 ?
			'intval($sum / 0x4000000);' :
			'$sum >> 31;';
		$code .= '$' . $result . '[$i] = ';
		if ($class::BASE === 26) {
			$code .= '(int) (';
		}
		$code .= '$sum - ' . $class::BASE_FULL . ' * $subtemp';
		if ($class::BASE === 26) {
			$code .= ')';
		}
		$code .= ';
                $' . $result . '[$j] = $subtemp;
            }
            if ($j == $size) {
                $sum = $' . $known . '[$i] - $' . $unknown . '[$i] - $carry;
                $carry = $sum < 0;
                $' . $result . '[$i] = $carry ? $sum + ' . $class::BASE_FULL . ' : $sum;
                ++$i;
            }

            if ($carry) {
                for (; !$' . $result . '[$i]; ++$i) {
                    $' . $result . '[$i] = ' . $class::MAX_DIGIT . ';
                }
                --$' . $result . '[$i];
            }';

		$code .= self::generateInlineTrim($result);

		return $code;
	}

	private static function generateInlineSubtract1($unknown, array $known, $result, $class)
	{
		$code = '$' . $result . ' = $' . $unknown . ';';
		for ($i = 0, $j = 1; $j < count($known); $i += 2, $j += 2) {
			$code .= '$sum = $' . $unknown . '[' . $j . '] * ' . $class::BASE_FULL . ' + $' . $unknown . '[' . $i . '] - ';
			$code .= self::float2string($known[$j] * $class::BASE_FULL + $known[$i]);
			if ($i != 0) {
				$code .= ' - $carry';
			}

			$code .= ';
                if ($carry = $sum < 0) {
                    $sum+= ' . self::float2string($class::MAX_DIGIT2) . ';
                }
                $subtemp = ';
			$code .= $class::BASE === 26 ?
				'intval($sum / 0x4000000);' :
				'$sum >> 31;';
			$code .= '
                $' . $result . '[' . $i . '] = ';
			if ($class::BASE === 26) {
				$code .= ' (int) (';
			}
			$code .= '$sum - ' . $class::BASE_FULL . ' * $subtemp';
			if ($class::BASE === 26) {
				$code .= ')';
			}
			$code .= ';
                $' . $result . '[' . $j . '] = $subtemp;';
		}

		$code .= '$i = ' . $i . ';';

		if ($j == count($known)) {
			$code .= '
                $sum = $' . $unknown . '[' . $i . '] - ' . $known[$i] . ' - $carry;
                $carry = $sum < 0;
                $' . $result . '[' . $i . '] = $carry ? $sum + ' . $class::BASE_FULL . ' : $sum;
                ++$i;';
		}

		$code .= '
            if ($carry) {
                for (; !$' . $result . '[$i]; ++$i) {
                    $' . $result . '[$i] = ' . $class::MAX_DIGIT . ';
                }
                --$' . $result . '[$i];
            }';
		$code .= self::generateInlineTrim($result);

		return $code;
	}

	private static function generateInlineCompare(array $known, $unknown, $subcode)
	{
		$uniqid = uniqid();
		$code = 'loop_' . $uniqid . ':
            $clength = count($' . $unknown . ');
            switch (true) {
                case $clength < ' . count($known) . ':
                    goto end_' . $uniqid . ';
                case $clength > ' . count($known) . ':';
		for ($i = count($known) - 1; $i >= 0; $i--) {
			$code .= '
                case $' . $unknown . '[' . $i . '] > ' . $known[$i] . ':
                    goto subcode_' . $uniqid . ';
                case $' . $unknown . '[' . $i . '] < ' . $known[$i] . ':
                    goto end_' . $uniqid . ';';
		}
		$code .= '
                default:
                    // do subcode
            }

            subcode_' . $uniqid . ':' . $subcode . '
            goto loop_' . $uniqid . ';

            end_' . $uniqid . ':';

		return $code;
	}

	private static function float2string($num)
	{
		if (!is_float($num)) {
			return (string) $num;
		}

		if ($num < 0) {
			return '-' . self::float2string(abs($num));
		}

		$temp = '';
		while ($num) {
			$temp = fmod($num, 10) . $temp;
			$num = floor($num / 10);
		}

		return $temp;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP {

use phpseclib3\Math\BigInteger\Engines\PHP\Reductions\EvalBarrett;

abstract class DefaultEngine extends EvalBarrett
{
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP {

use phpseclib3\Math\BigInteger\Engines\Engine;
use phpseclib3\Math\BigInteger\Engines\PHP;
use phpseclib3\Math\BigInteger\Engines\PHP\Reductions\PowerOfTwo;

abstract class Montgomery extends Base
{

	public static function isValidEngine()
	{
		return static::class != __CLASS__;
	}

	protected static function slidingWindow(Engine $x, Engine $e, Engine $n, $class)
	{

		if ($n->value[0] & 1) {
			return parent::slidingWindow($x, $e, $n, $class);
		}

		for ($i = 0; $i < count($n->value); ++$i) {
			if ($n->value[$i]) {
				$temp = decbin($n->value[$i]);
				$j = strlen($temp) - strrpos($temp, '1') - 1;
				$j += $class::BASE * $i;
				break;
			}
		}

		$mod1 = clone $n;
		$mod1->rshift($j);
		$mod2 = new $class();
		$mod2->value = [1];
		$mod2->lshift($j);

		$part1 = $mod1->value != [1] ? parent::slidingWindow($x, $e, $mod1, $class) : new $class();
		$part2 = PowerOfTwo::slidingWindow($x, $e, $mod2, $class);

		$y1 = $mod2->modInverse($mod1);
		$y2 = $mod1->modInverse($mod2);

		$result = $part1->multiply($mod2);
		$result = $result->multiply($y1);

		$temp = $part2->multiply($mod1);
		$temp = $temp->multiply($y2);

		$result = $result->add($temp);
		list(, $result) = $result->divide($n);

		return $result;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP {

use phpseclib3\Math\BigInteger\Engines\OpenSSL as Progenitor;

abstract class OpenSSL extends Progenitor
{
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP;
use phpseclib3\Math\BigInteger\Engines\PHP\Base;

abstract class Barrett extends Base
{

	protected static function reduce(array $n, array $m, $class)
	{
		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		$m_length = count($m);

		if (count($n) > 2 * $m_length) {
			$lhs = new $class();
			$rhs = new $class();
			$lhs->value = $n;
			$rhs->value = $m;
			list(, $temp) = $lhs->divide($rhs);
			return $temp->value;
		}

		if ($m_length < 5) {
			return self::regularBarrett($n, $m, $class);
		}

		$correctionNeeded = false;
		if ($m_length & 1) {
			$correctionNeeded = true;
			array_unshift($n, 0);
			array_unshift($m, 0);
			$m_length++;
		}

		if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $m;

			$lhs = new $class();
			$lhs_value = &$lhs->value;
			$lhs_value = self::array_repeat(0, $m_length + ($m_length >> 1));
			$lhs_value[] = 1;
			$rhs = new $class();
			$rhs->value = $m;

			list($u, $m1) = $lhs->divide($rhs);
			$u = $u->value;
			$m1 = $m1->value;

			$cache[self::DATA][] = [
				'u' => $u,
				'm1' => $m1
			];
		} else {
			extract($cache[self::DATA][$key]);
		}

		$cutoff = $m_length + ($m_length >> 1);
		$lsd = array_slice($n, 0, $cutoff);
		$msd = array_slice($n, $cutoff);

		$lsd = self::trim($lsd);
		$temp = $class::multiplyHelper($msd, false, $m1, false);
		$n = $class::addHelper($lsd, false, $temp[self::VALUE], false);

		$temp = array_slice($n[self::VALUE], $m_length - 1);

		$temp = $class::multiplyHelper($temp, false, $u, false);

		$temp = array_slice($temp[self::VALUE], ($m_length >> 1) + 1);

		$temp = $class::multiplyHelper($temp, false, $m, false);

		$result = $class::subtractHelper($n[self::VALUE], false, $temp[self::VALUE], false);

		while (self::compareHelper($result[self::VALUE], $result[self::SIGN], $m, false) >= 0) {
			$result = $class::subtractHelper($result[self::VALUE], $result[self::SIGN], $m, false);
		}

		if ($correctionNeeded) {
			array_shift($result[self::VALUE]);
		}

		return $result[self::VALUE];
	}

	private static function regularBarrett(array $x, array $n, $class)
	{
		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		$n_length = count($n);

		if (count($x) > 2 * $n_length) {
			$lhs = new $class();
			$rhs = new $class();
			$lhs->value = $x;
			$rhs->value = $n;
			list(, $temp) = $lhs->divide($rhs);
			return $temp->value;
		}

		if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $n;
			$lhs = new $class();
			$lhs_value = &$lhs->value;
			$lhs_value = self::array_repeat(0, 2 * $n_length);
			$lhs_value[] = 1;
			$rhs = new $class();
			$rhs->value = $n;
			list($temp, ) = $lhs->divide($rhs);
			$cache[self::DATA][] = $temp->value;
		}

		$temp = array_slice($x, $n_length - 1);

		$temp = $class::multiplyHelper($temp, false, $cache[self::DATA][$key], false);

		$temp = array_slice($temp[self::VALUE], $n_length + 1);

		$result = array_slice($x, 0, $n_length + 1);

		$temp = self::multiplyLower($temp, false, $n, false, $n_length + 1, $class);

		if (self::compareHelper($result, false, $temp[self::VALUE], $temp[self::SIGN]) < 0) {
			$corrector_value = self::array_repeat(0, $n_length + 1);
			$corrector_value[count($corrector_value)] = 1;
			$result = $class::addHelper($result, false, $corrector_value, false);
			$result = $result[self::VALUE];
		}

		$result = $class::subtractHelper($result, false, $temp[self::VALUE], $temp[self::SIGN]);
		while (self::compareHelper($result[self::VALUE], $result[self::SIGN], $n, false) > 0) {
			$result = $class::subtractHelper($result[self::VALUE], $result[self::SIGN], $n, false);
		}

		return $result[self::VALUE];
	}

	private static function multiplyLower(array $x_value, $x_negative, array $y_value, $y_negative, $stop, $class)
	{
		$x_length = count($x_value);
		$y_length = count($y_value);

		if (!$x_length || !$y_length) {
			return [
				self::VALUE => [],
				self::SIGN => false
			];
		}

		if ($x_length < $y_length) {
			$temp = $x_value;
			$x_value = $y_value;
			$y_value = $temp;

			$x_length = count($x_value);
			$y_length = count($y_value);
		}

		$product_value = self::array_repeat(0, $x_length + $y_length);

		$carry = 0;

		for ($j = 0; $j < $x_length; ++$j) {
			$temp = $x_value[$j] * $y_value[0] + $carry;
			$carry = $class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
			$product_value[$j] = (int) ($temp - $class::BASE_FULL * $carry);
		}

		if ($j < $stop) {
			$product_value[$j] = $carry;
		}

		for ($i = 1; $i < $y_length; ++$i) {
			$carry = 0;

			for ($j = 0, $k = $i; $j < $x_length && $k < $stop; ++$j, ++$k) {
				$temp = $product_value[$k] + $x_value[$j] * $y_value[$i] + $carry;
				$carry = $class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31);
				$product_value[$k] = (int) ($temp - $class::BASE_FULL * $carry);
			}

			if ($k < $stop) {
				$product_value[$k] = $carry;
			}
		}

		return [
			self::VALUE => self::trim($product_value),
			self::SIGN => $x_negative != $y_negative
		];
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP\Base;

abstract class Classic extends Base
{

	protected static function reduce(array $x, array $n, $class)
	{
		$lhs = new $class();
		$lhs->value = $x;
		$rhs = new $class();
		$rhs->value = $n;
		list(, $temp) = $lhs->divide($rhs);
		return $temp->value;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP\Montgomery as Progenitor;

abstract class Montgomery extends Progenitor
{

	protected static function prepareReduce(array $x, array $n, $class)
	{
		$lhs = new $class();
		$lhs->value = array_merge(self::array_repeat(0, count($n)), $x);
		$rhs = new $class();
		$rhs->value = $n;

		list(, $temp) = $lhs->divide($rhs);
		return $temp->value;
	}

	protected static function reduce(array $x, array $n, $class)
	{
		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		if (($key = array_search($n, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $x;
			$cache[self::DATA][] = self::modInverse67108864($n, $class);
		}

		$k = count($n);

		$result = [self::VALUE => $x];

		for ($i = 0; $i < $k; ++$i) {
			$temp = $result[self::VALUE][$i] * $cache[self::DATA][$key];
			$temp = $temp - $class::BASE_FULL * ($class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
			$temp = $class::regularMultiply([$temp], $n);
			$temp = array_merge(self::array_repeat(0, $i), $temp);
			$result = $class::addHelper($result[self::VALUE], false, $temp, false);
		}

		$result[self::VALUE] = array_slice($result[self::VALUE], $k);

		if (self::compareHelper($result, false, $n, false) >= 0) {
			$result = $class::subtractHelper($result[self::VALUE], false, $n, false);
		}

		return $result[self::VALUE];
	}

	protected static function modInverse67108864(array $x, $class)
	{
		$x = -$x[0];
		$result = $x & 0x3;
		$result = ($result * (2 - $x * $result)) & 0xF;
		$result = ($result * (2 - ($x & 0xFF) * $result))	& 0xFF;
		$result = ($result * ((2 - ($x & 0xFFFF) * $result) & 0xFFFF)) & 0xFFFF;
		$result = $class::BASE == 26 ?
			fmod($result * (2 - fmod($x * $result, $class::BASE_FULL)), $class::BASE_FULL) :
			($result * (2 - ($x * $result) % $class::BASE_FULL)) % $class::BASE_FULL;
		return $result & $class::MAX_DIGIT;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP;

abstract class MontgomeryMult extends Montgomery
{

	public static function multiplyReduce(array $x, array $y, array $m, $class)
	{

		static $cache = [
			self::VARIABLE => [],
			self::DATA => []
		];

		if (($key = array_search($m, $cache[self::VARIABLE])) === false) {
			$key = count($cache[self::VARIABLE]);
			$cache[self::VARIABLE][] = $m;
			$cache[self::DATA][] = self::modInverse67108864($m, $class);
		}

		$n = max(count($x), count($y), count($m));
		$x = array_pad($x, $n, 0);
		$y = array_pad($y, $n, 0);
		$m = array_pad($m, $n, 0);
		$a = [self::VALUE => self::array_repeat(0, $n + 1)];
		for ($i = 0; $i < $n; ++$i) {
			$temp = $a[self::VALUE][0] + $x[$i] * $y[0];
			$temp = $temp - $class::BASE_FULL * ($class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
			$temp = $temp * $cache[self::DATA][$key];
			$temp = $temp - $class::BASE_FULL * ($class::BASE === 26 ? intval($temp / 0x4000000) : ($temp >> 31));
			$temp = $class::addHelper($class::regularMultiply([$x[$i]], $y), false, $class::regularMultiply([$temp], $m), false);
			$a = $class::addHelper($a[self::VALUE], false, $temp[self::VALUE], false);
			$a[self::VALUE] = array_slice($a[self::VALUE], 1);
		}
		if (self::compareHelper($a[self::VALUE], false, $m, false) >= 0) {
			$a = $class::subtractHelper($a[self::VALUE], false, $m, false);
		}
		return $a[self::VALUE];
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines\PHP\Reductions {

use phpseclib3\Math\BigInteger\Engines\PHP\Base;

abstract class PowerOfTwo extends Base
{

	protected static function prepareReduce(array $x, array $n, $class)
	{
		return self::reduce($x, $n, $class);
	}

	protected static function reduce(array $x, array $n, $class)
	{
		$lhs = new $class();
		$lhs->value = $x;
		$rhs = new $class();
		$rhs->value = $n;

		$temp = new $class();
		$temp->value = [1];

		$result = $lhs->bitwise_and($rhs->subtract($temp));
		return $result->value;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

class PHP32 extends PHP
{

	const BASE = 26;
	const BASE_FULL = 0x4000000;
	const MAX_DIGIT = 0x3FFFFFF;
	const MSB = 0x2000000;

	const MAX10 = 10000000;

	const MAX10LEN = 7;
	const MAX_DIGIT2 = 4503599627370496;

	protected function initialize($base)
	{
		if ($base != 256 && $base != -256) {
			return parent::initialize($base);
		}

		$val = $this->value;
		$this->value = [];
		$vals = &$this->value;
		$i = strlen($val);
		if (!$i) {
			return;
		}

		while (true) {
			$i -= 4;
			if ($i < 0) {
				if ($i == -4) {
					break;
				}
				$val = substr($val, 0, 4 + $i);
				$val = str_pad($val, 4, "\0", STR_PAD_LEFT);
				if ($val == "\0\0\0\0") {
					break;
				}
				$i = 0;
			}
			list(, $digit) = unpack('N', substr($val, $i, 4));
			if ($digit < 0) {
				$digit += 0xFFFFFFFF + 1;
			}
			$step = count($vals) & 3;
			if ($step) {
				$digit = (int) floor($digit / pow(2, 2 * $step));
			}
			if ($step != 3) {
				$digit = (int) fmod($digit, static::BASE_FULL);
				$i++;
			}
			$vals[] = $digit;
		}
		while (end($vals) === 0) {
			array_pop($vals);
		}
		reset($vals);
	}

	public static function isValidEngine()
	{
		return PHP_INT_SIZE >= 4 && !self::testJITOnWindows();
	}

	public function add(PHP32 $y)
	{
		$temp = self::addHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function subtract(PHP32 $y)
	{
		$temp = self::subtractHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function multiply(PHP32 $y)
	{
		$temp = self::multiplyHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function divide(PHP32 $y)
	{
		return $this->divideHelper($y);
	}

	public function modInverse(PHP32 $n)
	{
		return $this->modInverseHelper($n);
	}

	public function extendedGCD(PHP32 $n)
	{
		return $this->extendedGCDHelper($n);
	}

	public function gcd(PHP32 $n)
	{
		return $this->extendedGCD($n)['gcd'];
	}

	public function bitwise_and(PHP32 $x)
	{
		return $this->bitwiseAndHelper($x);
	}

	public function bitwise_or(PHP32 $x)
	{
		return $this->bitwiseOrHelper($x);
	}

	public function bitwise_xor(PHP32 $x)
	{
		return $this->bitwiseXorHelper($x);
	}

	public function compare(PHP32 $y)
	{
		return $this->compareHelper($this->value, $this->is_negative, $y->value, $y->is_negative);
	}

	public function equals(PHP32 $x)
	{
		return $this->value === $x->value && $this->is_negative == $x->is_negative;
	}

	public function modPow(PHP32 $e, PHP32 $n)
	{
		return $this->powModOuter($e, $n);
	}

	public function powMod(PHP32 $e, PHP32 $n)
	{
		return $this->powModOuter($e, $n);
	}

	public static function randomRangePrime(PHP32 $min, PHP32 $max)
	{
		return self::randomRangePrimeOuter($min, $max);
	}

	public static function randomRange(PHP32 $min, PHP32 $max)
	{
		return self::randomRangeHelper($min, $max);
	}

	public function pow(PHP32 $n)
	{
		return $this->powHelper($n);
	}

	public static function min(PHP32 ...$nums)
	{
		return self::minHelper($nums);
	}

	public static function max(PHP32 ...$nums)
	{
		return self::maxHelper($nums);
	}

	public function between(PHP32 $min, PHP32 $max)
	{
		return $this->compare($min) >= 0 && $this->compare($max) <= 0;
	}
}
}

namespace phpseclib3\Math\BigInteger\Engines {

class PHP64 extends PHP
{

	const BASE = 31;
	const BASE_FULL = 0x80000000;
	const MAX_DIGIT = 0x7FFFFFFF;
	const MSB = 0x40000000;

	const MAX10 = 1000000000;

	const MAX10LEN = 9;
	const MAX_DIGIT2 = 4611686018427387904;

	protected function initialize($base)
	{
		if ($base != 256 && $base != -256) {
			return parent::initialize($base);
		}

		$val = $this->value;
		$this->value = [];
		$vals = &$this->value;
		$i = strlen($val);
		if (!$i) {
			return;
		}

		while (true) {
			$i -= 4;
			if ($i < 0) {
				if ($i == -4) {
					break;
				}
				$val = substr($val, 0, 4 + $i);
				$val = str_pad($val, 4, "\0", STR_PAD_LEFT);
				if ($val == "\0\0\0\0") {
					break;
				}
				$i = 0;
			}
			list(, $digit) = unpack('N', substr($val, $i, 4));
			$step = count($vals) & 7;
			if (!$step) {
				$digit &= static::MAX_DIGIT;
				$i++;
			} else {
				$shift = 8 - $step;
				$digit >>= $shift;
				$shift = 32 - $shift;
				$digit &= (1 << $shift) - 1;
				$temp = $i > 0 ? ord($val[$i - 1]) : 0;
				$digit |= ($temp << $shift) & 0x7F000000;
			}
			$vals[] = $digit;
		}
		while (end($vals) === 0) {
			array_pop($vals);
		}
		reset($vals);
	}

	public static function isValidEngine()
	{
		return PHP_INT_SIZE >= 8 && !self::testJITOnWindows();
	}

	public function add(PHP64 $y)
	{
		$temp = self::addHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function subtract(PHP64 $y)
	{
		$temp = self::subtractHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function multiply(PHP64 $y)
	{
		$temp = self::multiplyHelper($this->value, $this->is_negative, $y->value, $y->is_negative);

		return $this->convertToObj($temp);
	}

	public function divide(PHP64 $y)
	{
		return $this->divideHelper($y);
	}

	public function modInverse(PHP64 $n)
	{
		return $this->modInverseHelper($n);
	}

	public function extendedGCD(PHP64 $n)
	{
		return $this->extendedGCDHelper($n);
	}

	public function gcd(PHP64 $n)
	{
		return $this->extendedGCD($n)['gcd'];
	}

	public function bitwise_and(PHP64 $x)
	{
		return $this->bitwiseAndHelper($x);
	}

	public function bitwise_or(PHP64 $x)
	{
		return $this->bitwiseOrHelper($x);
	}

	public function bitwise_xor(PHP64 $x)
	{
		return $this->bitwiseXorHelper($x);
	}

	public function compare(PHP64 $y)
	{
		return parent::compareHelper($this->value, $this->is_negative, $y->value, $y->is_negative);
	}

	public function equals(PHP64 $x)
	{
		return $this->value === $x->value && $this->is_negative == $x->is_negative;
	}

	public function modPow(PHP64 $e, PHP64 $n)
	{
		return $this->powModOuter($e, $n);
	}

	public function powMod(PHP64 $e, PHP64 $n)
	{
		return $this->powModOuter($e, $n);
	}

	public static function randomRangePrime(PHP64 $min, PHP64 $max)
	{
		return self::randomRangePrimeOuter($min, $max);
	}

	public static function randomRange(PHP64 $min, PHP64 $max)
	{
		return self::randomRangeHelper($min, $max);
	}

	public function pow(PHP64 $n)
	{
		return $this->powHelper($n);
	}

	public static function min(PHP64 ...$nums)
	{
		return self::minHelper($nums);
	}

	public static function max(PHP64 ...$nums)
	{
		return self::maxHelper($nums);
	}

	public function between(PHP64 $min, PHP64 $max)
	{
		return $this->compare($min) >= 0 && $this->compare($max) <= 0;
	}
}
}

namespace phpseclib3\Math {

use phpseclib3\Exception\BadConfigurationException;
use phpseclib3\Math\BigInteger\Engines\Engine;

class BigInteger implements \JsonSerializable
{

	private static $mainEngine;

	private static $engines;

	private $value;

	private $hex;

	private $precision;

	public static function setEngine($main, array $modexps = ['DefaultEngine'])
	{
		self::$engines = [];

		$fqmain = 'phpseclib3\\Math\\BigInteger\\Engines\\' . $main;
		if (!class_exists($fqmain) || !method_exists($fqmain, 'isValidEngine')) {
			throw new \InvalidArgumentException("$main is not a valid engine");
		}
		if (!$fqmain::isValidEngine()) {
			throw new BadConfigurationException("$main is not setup correctly on this system");
		}

		self::$mainEngine = $fqmain;

		$found = false;
		foreach ($modexps as $modexp) {
			try {
				$fqmain::setModExpEngine($modexp);
				$found = true;
				break;
			} catch (\Exception $e) {
			}
		}

		if (!$found) {
			throw new BadConfigurationException("No valid modular exponentiation engine found for $main");
		}

		self::$engines = [$main, $modexp];
	}

	public static function getEngine()
	{
		self::initialize_static_variables();

		return self::$engines;
	}

	private static function initialize_static_variables()
	{
		if (!isset(self::$mainEngine)) {
			$engines = [
				['GMP', ['DefaultEngine']],
				['PHP64', ['OpenSSL']],
				['BCMath', ['OpenSSL']],
				['PHP32', ['OpenSSL']],
				['PHP64', ['DefaultEngine']],
				['PHP32', ['DefaultEngine']]
			];

			foreach ($engines as $engine) {
				try {
					self::setEngine($engine[0], $engine[1]);
					return;
				} catch (\Exception $e) {
				}
			}

			throw new \UnexpectedValueException('No valid BigInteger found. This is only possible when JIT is enabled on Windows and neither the GMP or BCMath extensions are available so either disable JIT or install GMP / BCMath');
		}
	}

	public function __construct($x = 0, $base = 10)
	{
		self::initialize_static_variables();

		if ($x instanceof self::$mainEngine) {
			$this->value = clone $x;
		} elseif ($x instanceof Engine) {
			$this->value = new static("$x");
			$this->value->setPrecision($x->getPrecision());
		} else {
			$this->value = new self::$mainEngine($x, $base);
		}
	}

	public function toString()
	{
		return $this->value->toString();
	}

	public function __toString()
	{
		return (string)$this->value;
	}

	public function __debugInfo()
	{
		return $this->value->__debugInfo();
	}

	public function toBytes($twos_compliment = false)
	{
		return $this->value->toBytes($twos_compliment);
	}

	public function toHex($twos_compliment = false)
	{
		return $this->value->toHex($twos_compliment);
	}

	public function toBits($twos_compliment = false)
	{
		return $this->value->toBits($twos_compliment);
	}

	public function add(BigInteger $y)
	{
		return new static($this->value->add($y->value));
	}

	public function subtract(BigInteger $y)
	{
		return new static($this->value->subtract($y->value));
	}

	public function multiply(BigInteger $x)
	{
		return new static($this->value->multiply($x->value));
	}

	public function divide(BigInteger $y)
	{
		list($q, $r) = $this->value->divide($y->value);
		return [
			new static($q),
			new static($r)
		];
	}

	public function modInverse(BigInteger $n)
	{
		return new static($this->value->modInverse($n->value));
	}

	public function extendedGCD(BigInteger $n)
	{
		extract($this->value->extendedGCD($n->value));

		return [
			'gcd' => new static($gcd),
			'x' => new static($x),
			'y' => new static($y)
		];
	}

	public function gcd(BigInteger $n)
	{
		return new static($this->value->gcd($n->value));
	}

	public function abs()
	{
		return new static($this->value->abs());
	}

	public function setPrecision($bits)
	{
		$this->value->setPrecision($bits);
	}

	public function getPrecision()
	{
		return $this->value->getPrecision();
	}

	public function __sleep()
	{
		$this->hex = $this->toHex(true);
		$vars = ['hex'];
		if ($this->getPrecision() > 0) {
			$vars[] = 'precision';
		}
		return $vars;
	}

	public function __wakeup()
	{
		$temp = new static($this->hex, -16);
		$this->value = $temp->value;
		if ($this->precision > 0) {

			$this->setPrecision($this->precision);
		}
	}

	#[\ReturnTypeWillChange]
	public function jsonSerialize()
	{
		$result = ['hex' => $this->toHex(true)];
		if ($this->precision > 0) {
			$result['precision'] = $this->getPrecision();
		}
		return $result;
	}

	public function powMod(BigInteger $e, BigInteger $n)
	{
		return new static($this->value->powMod($e->value, $n->value));
	}

	public function modPow(BigInteger $e, BigInteger $n)
	{
		return new static($this->value->modPow($e->value, $n->value));
	}

	public function compare(BigInteger $y)
	{
		return $this->value->compare($y->value);
	}

	public function equals(BigInteger $x)
	{
		return $this->value->equals($x->value);
	}

	public function bitwise_not()
	{
		return new static($this->value->bitwise_not());
	}

	public function bitwise_and(BigInteger $x)
	{
		return new static($this->value->bitwise_and($x->value));
	}

	public function bitwise_or(BigInteger $x)
	{
		return new static($this->value->bitwise_or($x->value));
	}

	public function bitwise_xor(BigInteger $x)
	{
		return new static($this->value->bitwise_xor($x->value));
	}

	public function bitwise_rightShift($shift)
	{
		return new static($this->value->bitwise_rightShift($shift));
	}

	public function bitwise_leftShift($shift)
	{
		return new static($this->value->bitwise_leftShift($shift));
	}

	public function bitwise_leftRotate($shift)
	{
		return new static($this->value->bitwise_leftRotate($shift));
	}

	public function bitwise_rightRotate($shift)
	{
		return new static($this->value->bitwise_rightRotate($shift));
	}

	public static function minMaxBits($bits)
	{
		self::initialize_static_variables();

		$class = self::$mainEngine;
		extract($class::minMaxBits($bits));

		return [
			'min' => new static($min),
			'max' => new static($max)
		];
	}

	public function getLength()
	{
		return $this->value->getLength();
	}

	public function getLengthInBytes()
	{
		return $this->value->getLengthInBytes();
	}

	public static function random($size)
	{
		self::initialize_static_variables();

		$class = self::$mainEngine;
		return new static($class::random($size));
	}

	public static function randomPrime($size)
	{
		self::initialize_static_variables();

		$class = self::$mainEngine;
		return new static($class::randomPrime($size));
	}

	public static function randomRangePrime(BigInteger $min, BigInteger $max)
	{
		$class = self::$mainEngine;
		return new static($class::randomRangePrime($min->value, $max->value));
	}

	public static function randomRange(BigInteger $min, BigInteger $max)
	{
		$class = self::$mainEngine;
		return new static($class::randomRange($min->value, $max->value));
	}

	public function isPrime($t = false)
	{
		return $this->value->isPrime($t);
	}

	public function root($n = 2)
	{
		return new static($this->value->root($n));
	}

	public function pow(BigInteger $n)
	{
		return new static($this->value->pow($n->value));
	}

	public static function min(BigInteger ...$nums)
	{
		$class = self::$mainEngine;
		$nums = array_map(function ($num) {
			return $num->value;
		}, $nums);
		return new static($class::min(...$nums));
	}

	public static function max(BigInteger ...$nums)
	{
		$class = self::$mainEngine;
		$nums = array_map(function ($num) {
			return $num->value;
		}, $nums);
		return new static($class::max(...$nums));
	}

	public function between(BigInteger $min, BigInteger $max)
	{
		return $this->value->between($min->value, $max->value);
	}

	public function __clone()
	{
		$this->value = clone $this->value;
	}

	public function isOdd()
	{
		return $this->value->isOdd();
	}

	public function testBit($x)
	{
		return $this->value->testBit($x);
	}

	public function isNegative()
	{
		return $this->value->isNegative();
	}

	public function negate()
	{
		return new static($this->value->negate());
	}

	public static function scan1divide(BigInteger $r)
	{
		$class = self::$mainEngine;
		return $class::scan1divide($r->value);
	}

	public function createRecurringModuloFunction()
	{
		$func = $this->value->createRecurringModuloFunction();
		return function (BigInteger $x) use ($func) {
			return new static($func($x->value));
		};
	}

	public function bitwise_split($split)
	{
		return array_map(function ($val) {
			return new static($val);
		}, $this->value->bitwise_split($split));
	}
}
}

namespace phpseclib3\Math\Common\FiniteField {

abstract class Integer implements \JsonSerializable
{

	#[\ReturnTypeWillChange]
	public function jsonSerialize()
	{
		return ['hex' => $this->toHex(true)];
	}

	abstract public function toHex();
}
}

namespace phpseclib3\Math\BinaryField {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\BinaryField;
use phpseclib3\Math\Common\FiniteField\Integer as Base;

class Integer extends Base
{

	protected $value;

	protected $instanceID;

	protected static $modulo;

	protected static $reduce;

	public function __construct($instanceID, $num = '')
	{
		$this->instanceID = $instanceID;
		if (!strlen($num)) {
			$this->value = '';
		} else {
			$reduce = static::$reduce[$instanceID];
			$this->value = $reduce($num);
		}
	}

	public static function setModulo($instanceID, $modulo)
	{
		static::$modulo[$instanceID] = $modulo;
	}

	public static function setRecurringModuloFunction($instanceID, callable $function)
	{
		static::$reduce[$instanceID] = $function;
	}

	private static function checkInstance(self $x, self $y)
	{
		if ($x->instanceID != $y->instanceID) {
			throw new \UnexpectedValueException('The instances of the two BinaryField\Integer objects do not match');
		}
	}

	public function equals(self $x)
	{
		static::checkInstance($this, $x);

		return $this->value == $x->value;
	}

	public function compare(self $x)
	{
		static::checkInstance($this, $x);

		$a = $this->value;
		$b = $x->value;

		$length = max(strlen($a), strlen($b));

		$a = str_pad($a, $length, "\0", STR_PAD_LEFT);
		$b = str_pad($b, $length, "\0", STR_PAD_LEFT);

		return strcmp($a, $b);
	}

	private static function deg($x)
	{
		$x = ltrim($x, "\0");
		$xbit = decbin(ord($x[0]));
		$xlen = $xbit == '0' ? 0 : strlen($xbit);
		$len = strlen($x);
		if (!$len) {
			return -1;
		}
		return 8 * strlen($x) - 9 + $xlen;
	}

	private static function polynomialDivide($x, $y)
	{

		$q = chr(0);
		$d = static::deg($y);
		$r = $x;
		while (($degr = static::deg($r)) >= $d) {
			$s = '1' . str_repeat('0', $degr - $d);
			$s = BinaryField::base2ToBase256($s);
			$length = max(strlen($s), strlen($q));
			$q = !isset($q) ? $s :
				str_pad($q, $length, "\0", STR_PAD_LEFT) ^
				str_pad($s, $length, "\0", STR_PAD_LEFT);
			$s = static::polynomialMultiply($s, $y);
			$length = max(strlen($r), strlen($s));
			$r = str_pad($r, $length, "\0", STR_PAD_LEFT) ^
				 str_pad($s, $length, "\0", STR_PAD_LEFT);
		}

		return [ltrim($q, "\0"), ltrim($r, "\0")];
	}

	private static function regularPolynomialMultiply($x, $y)
	{
		$precomputed = [ltrim($x, "\0")];
		$x = strrev(BinaryField::base256ToBase2($x));
		$y = strrev(BinaryField::base256ToBase2($y));
		if (strlen($x) == strlen($y)) {
			$length = strlen($x);
		} else {
			$length = max(strlen($x), strlen($y));
			$x = str_pad($x, $length, '0');
			$y = str_pad($y, $length, '0');
		}
		$result = str_repeat('0', 2 * $length - 1);
		$result = BinaryField::base2ToBase256($result);
		$size = strlen($result);
		$x = strrev($x);

		for ($i = 1; $i < 8; $i++) {
			$precomputed[$i] = BinaryField::base2ToBase256($x . str_repeat('0', $i));
		}
		for ($i = 0; $i < strlen($y); $i++) {
			if ($y[$i] == '1') {
				$temp = $precomputed[$i & 7] . str_repeat("\0", $i >> 3);
				$result ^= str_pad($temp, $size, "\0", STR_PAD_LEFT);
			}
		}

		return $result;
	}

	private static function polynomialMultiply($x, $y)
	{
		if (strlen($x) == strlen($y)) {
			$length = strlen($x);
		} else {
			$length = max(strlen($x), strlen($y));
			$x = str_pad($x, $length, "\0", STR_PAD_LEFT);
			$y = str_pad($y, $length, "\0", STR_PAD_LEFT);
		}

		switch (true) {
			case PHP_INT_SIZE == 8 && $length <= 4:
				return $length != 4 ?
					self::subMultiply(str_pad($x, 4, "\0", STR_PAD_LEFT), str_pad($y, 4, "\0", STR_PAD_LEFT)) :
					self::subMultiply($x, $y);
			case PHP_INT_SIZE == 4 || $length > 32:
				return self::regularPolynomialMultiply($x, $y);
		}

		$m = $length >> 1;

		$x1 = substr($x, 0, -$m);
		$x0 = substr($x, -$m);
		$y1 = substr($y, 0, -$m);
		$y0 = substr($y, -$m);

		$z2 = self::polynomialMultiply($x1, $y1);
		$z0 = self::polynomialMultiply($x0, $y0);
		$z1 = self::polynomialMultiply(
			self::subAdd2($x1, $x0),
			self::subAdd2($y1, $y0)
		);

		$z1 = self::subAdd3($z1, $z2, $z0);

		$xy = self::subAdd3(
			$z2 . str_repeat("\0", 2 * $m),
			$z1 . str_repeat("\0", $m),
			$z0
		);

		return ltrim($xy, "\0");
	}

	private static function subMultiply($x, $y)
	{
		$x = unpack('N', $x)[1];
		$y = unpack('N', $y)[1];

		$x0 = $x & 0x11111111;
		$x1 = $x & 0x22222222;
		$x2 = $x & 0x44444444;
		$x3 = $x & 0x88888888;

		$y0 = $y & 0x11111111;
		$y1 = $y & 0x22222222;
		$y2 = $y & 0x44444444;
		$y3 = $y & 0x88888888;

		$z0 = ($x0 * $y0) ^ ($x1 * $y3) ^ ($x2 * $y2) ^ ($x3 * $y1);
		$z1 = ($x0 * $y1) ^ ($x1 * $y0) ^ ($x2 * $y3) ^ ($x3 * $y2);
		$z2 = ($x0 * $y2) ^ ($x1 * $y1) ^ ($x2 * $y0) ^ ($x3 * $y3);
		$z3 = ($x0 * $y3) ^ ($x1 * $y2) ^ ($x2 * $y1) ^ ($x3 * $y0);

		$z0 &= 0x1111111111111111;
		$z1 &= 0x2222222222222222;
		$z2 &= 0x4444444444444444;
		$z3 &= -8608480567731124088;

		$z = $z0 | $z1 | $z2 | $z3;

		return pack('J', $z);
	}

	private static function subAdd2($x, $y)
	{
		$length = max(strlen($x), strlen($y));
		$x = str_pad($x, $length, "\0", STR_PAD_LEFT);
		$y = str_pad($y, $length, "\0", STR_PAD_LEFT);
		return $x ^ $y;
	}

	private static function subAdd3($x, $y, $z)
	{
		$length = max(strlen($x), strlen($y), strlen($z));
		$x = str_pad($x, $length, "\0", STR_PAD_LEFT);
		$y = str_pad($y, $length, "\0", STR_PAD_LEFT);
		$z = str_pad($z, $length, "\0", STR_PAD_LEFT);
		return $x ^ $y ^ $z;
	}

	public function add(self $y)
	{
		static::checkInstance($this, $y);

		$length = strlen(static::$modulo[$this->instanceID]);

		$x = str_pad($this->value, $length, "\0", STR_PAD_LEFT);
		$y = str_pad($y->value, $length, "\0", STR_PAD_LEFT);

		return new static($this->instanceID, $x ^ $y);
	}

	public function subtract(self $x)
	{
		return $this->add($x);
	}

	public function multiply(self $y)
	{
		static::checkInstance($this, $y);

		return new static($this->instanceID, static::polynomialMultiply($this->value, $y->value));
	}

	public function modInverse()
	{
		$remainder0 = static::$modulo[$this->instanceID];
		$remainder1 = $this->value;

		if ($remainder1 == '') {
			return new static($this->instanceID);
		}

		$aux0 = "\0";
		$aux1 = "\1";
		while ($remainder1 != "\1") {
			list($q, $r) = static::polynomialDivide($remainder0, $remainder1);
			$remainder0 = $remainder1;
			$remainder1 = $r;

			$temp = static::polynomialMultiply($aux1, $q);
			$aux = str_pad($aux0, strlen($temp), "\0", STR_PAD_LEFT) ^
					str_pad($temp, strlen($aux0), "\0", STR_PAD_LEFT);
			$aux0 = $aux1;
			$aux1 = $aux;
		}

		$temp = new static($this->instanceID);
		$temp->value = ltrim($aux1, "\0");
		return $temp;
	}

	public function divide(self $x)
	{
		static::checkInstance($this, $x);

		$x = $x->modInverse();
		return $this->multiply($x);
	}

	public function negate()
	{
		$x = str_pad($this->value, strlen(static::$modulo[$this->instanceID]), "\0", STR_PAD_LEFT);

		return new static($this->instanceID, $x ^ static::$modulo[$this->instanceID]);
	}

	public static function getModulo($instanceID)
	{
		return static::$modulo[$instanceID];
	}

	public function toBytes()
	{
		return str_pad($this->value, strlen(static::$modulo[$this->instanceID]), "\0", STR_PAD_LEFT);
	}

	public function toHex()
	{
		return Strings::bin2hex($this->toBytes());
	}

	public function toBits()
	{

		return BinaryField::base256ToBase2($this->value);
	}

	public function toBigInteger()
	{
		return new BigInteger($this->value, 256);
	}

	public function __toString()
	{
		return (string) $this->toBigInteger();
	}

	public function __debugInfo()
	{
		return ['value' => $this->toHex()];
	}
}
}

namespace phpseclib3\Math\Common {

abstract class FiniteField
{
}
}

namespace phpseclib3\Math {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BinaryField\Integer;
use phpseclib3\Math\Common\FiniteField;

class BinaryField extends FiniteField
{

	private static $instanceCounter = 0;

	protected $instanceID;

	private $randomMax;

	public function __construct(...$indices)
	{
		$m = array_shift($indices);
		if ($m > 571) {

			throw new \OutOfBoundsException('Degrees larger than 571 are not supported');
		}
		$val = str_repeat('0', $m) . '1';
		foreach ($indices as $index) {
			$val[$index] = '1';
		}
		$modulo = static::base2ToBase256(strrev($val));

		$mStart = 2 * $m - 2;
		$t = ceil($m / 8);
		$finalMask = chr((1 << ($m % 8)) - 1);
		if ($finalMask == "\0") {
			$finalMask = "\xFF";
		}
		$bitLen = $mStart + 1;
		$pad = ceil($bitLen / 8);
		$h = $bitLen & 7;
		$h = $h ? 8 - $h : 0;

		$r = rtrim(substr($val, 0, -1), '0');
		$u = [static::base2ToBase256(strrev($r))];
		for ($i = 1; $i < 8; $i++) {
			$u[] = static::base2ToBase256(strrev(str_repeat('0', $i) . $r));
		}

		$reduce = function ($c) use ($u, $mStart, $m, $t, $finalMask, $pad, $h) {
			$c = str_pad($c, $pad, "\0", STR_PAD_LEFT);
			for ($i = $mStart; $i >= $m;) {
				$g = $h >> 3;
				$mask = $h & 7;
				$mask = $mask ? 1 << (7 - $mask) : 0x80;
				for (; $mask > 0; $mask >>= 1, $i--, $h++) {
					if (ord($c[$g]) & $mask) {
						$temp = $i - $m;
						$j = $temp >> 3;
						$k = $temp & 7;
						$t1 = $j ? substr($c, 0, -$j) : $c;
						$length = strlen($t1);
						if ($length) {
							$t2 = str_pad($u[$k], $length, "\0", STR_PAD_LEFT);
							$temp = $t1 ^ $t2;
							$c = $j ? substr_replace($c, $temp, 0, $length) : $temp;
						}
					}
				}
			}
			$c = substr($c, -$t);
			if (strlen($c) == $t) {
				$c[0] = $c[0] & $finalMask;
			}
			return ltrim($c, "\0");
		};

		$this->instanceID = self::$instanceCounter++;
		Integer::setModulo($this->instanceID, $modulo);
		Integer::setRecurringModuloFunction($this->instanceID, $reduce);

		$this->randomMax = new BigInteger($modulo, 2);
	}

	public function newInteger($num)
	{
		return new Integer($this->instanceID, $num instanceof BigInteger ? $num->toBytes() : $num);
	}

	public function randomInteger()
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		return new Integer($this->instanceID, BigInteger::randomRange($one, $this->randomMax)->toBytes());
	}

	public function getLengthInBytes()
	{
		return strlen(Integer::getModulo($this->instanceID));
	}

	public function getLength()
	{
		return strlen(Integer::getModulo($this->instanceID)) << 3;
	}

	public static function base2ToBase256($x, $size = null)
	{
		$str = Strings::bits2bin($x);

		$pad = strlen($x) >> 3;
		if (strlen($x) & 3) {
			$pad++;
		}
		$str = str_pad($str, $pad, "\0", STR_PAD_LEFT);
		if (isset($size)) {
			$str = str_pad($str, $size, "\0", STR_PAD_LEFT);
		}

		return $str;
	}

	public static function base256ToBase2($x)
	{
		if (function_exists('gmp_import')) {
			return gmp_strval(gmp_import($x), 2);
		}

		return Strings::bin2bits($x);
	}
}
}

namespace phpseclib3\Math\PrimeField {

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Math\BigInteger;
use phpseclib3\Math\Common\FiniteField\Integer as Base;

class Integer extends Base
{

	protected $value;

	protected $instanceID;

	protected static $modulo;

	protected static $reduce;

	protected static $zero;

	public function __construct($instanceID, $num = null)
	{
		$this->instanceID = $instanceID;
		if (!isset($num)) {
			$this->value = clone static::$zero[static::class];
		} else {
			$reduce = static::$reduce[$instanceID];
			$this->value = $reduce($num);
		}
	}

	public static function setModulo($instanceID, BigInteger $modulo)
	{
		static::$modulo[$instanceID] = $modulo;
	}

	public static function setRecurringModuloFunction($instanceID, callable $function)
	{
		static::$reduce[$instanceID] = $function;
		if (!isset(static::$zero[static::class])) {
			static::$zero[static::class] = new BigInteger();
		}
	}

	public static function cleanupCache($instanceID)
	{
		unset(static::$modulo[$instanceID]);
		unset(static::$reduce[$instanceID]);
	}

	public static function getModulo($instanceID)
	{
		return static::$modulo[$instanceID];
	}

	public static function checkInstance(self $x, self $y)
	{
		if ($x->instanceID != $y->instanceID) {
			throw new \UnexpectedValueException('The instances of the two PrimeField\Integer objects do not match');
		}
	}

	public function equals(self $x)
	{
		static::checkInstance($this, $x);

		return $this->value->equals($x->value);
	}

	public function compare(self $x)
	{
		static::checkInstance($this, $x);

		return $this->value->compare($x->value);
	}

	public function add(self $x)
	{
		static::checkInstance($this, $x);

		$temp = new static($this->instanceID);
		$temp->value = $this->value->add($x->value);
		if ($temp->value->compare(static::$modulo[$this->instanceID]) >= 0) {
			$temp->value = $temp->value->subtract(static::$modulo[$this->instanceID]);
		}

		return $temp;
	}

	public function subtract(self $x)
	{
		static::checkInstance($this, $x);

		$temp = new static($this->instanceID);
		$temp->value = $this->value->subtract($x->value);
		if ($temp->value->isNegative()) {
			$temp->value = $temp->value->add(static::$modulo[$this->instanceID]);
		}

		return $temp;
	}

	public function multiply(self $x)
	{
		static::checkInstance($this, $x);

		return new static($this->instanceID, $this->value->multiply($x->value));
	}

	public function divide(self $x)
	{
		static::checkInstance($this, $x);

		$denominator = $x->value->modInverse(static::$modulo[$this->instanceID]);
		return new static($this->instanceID, $this->value->multiply($denominator));
	}

	public function pow(BigInteger $x)
	{
		$temp = new static($this->instanceID);
		$temp->value = $this->value->powMod($x, static::$modulo[$this->instanceID]);

		return $temp;
	}

	public function squareRoot()
	{
		static $one, $two;
		if (!isset($one)) {
			$one = new BigInteger(1);
			$two = new BigInteger(2);
		}
		$reduce = static::$reduce[$this->instanceID];
		$p_1 = static::$modulo[$this->instanceID]->subtract($one);
		$q = clone $p_1;
		$s = BigInteger::scan1divide($q);
		list($pow) = $p_1->divide($two);
		for ($z = $one; !$z->equals(static::$modulo[$this->instanceID]); $z = $z->add($one)) {
			$temp = $z->powMod($pow, static::$modulo[$this->instanceID]);
			if ($temp->equals($p_1)) {
				break;
			}
		}

		$m = new BigInteger($s);
		$c = $z->powMod($q, static::$modulo[$this->instanceID]);
		$t = $this->value->powMod($q, static::$modulo[$this->instanceID]);
		list($temp) = $q->add($one)->divide($two);
		$r = $this->value->powMod($temp, static::$modulo[$this->instanceID]);

		while (!$t->equals($one)) {
			for ($i = clone $one; $i->compare($m) < 0; $i = $i->add($one)) {
				if ($t->powMod($two->pow($i), static::$modulo[$this->instanceID])->equals($one)) {
					break;
				}
			}

			if ($i->compare($m) == 0) {
				return false;
			}
			$b = $c->powMod($two->pow($m->subtract($i)->subtract($one)), static::$modulo[$this->instanceID]);
			$m = $i;
			$c = $reduce($b->multiply($b));
			$t = $reduce($t->multiply($c));
			$r = $reduce($r->multiply($b));
		}

		return new static($this->instanceID, $r);
	}

	public function isOdd()
	{
		return $this->value->isOdd();
	}

	public function negate()
	{
		return new static($this->instanceID, static::$modulo[$this->instanceID]->subtract($this->value));
	}

	public function toBytes()
	{
		if (isset(static::$modulo[$this->instanceID])) {
			$length = static::$modulo[$this->instanceID]->getLengthInBytes();
			return str_pad($this->value->toBytes(), $length, "\0", STR_PAD_LEFT);
		}
		return $this->value->toBytes();
	}

	public function toHex()
	{
		return Strings::bin2hex($this->toBytes());
	}

	public function toBits()
	{

		static $length;
		if (!isset($length)) {
			$length = static::$modulo[$this->instanceID]->getLength();
		}

		return str_pad($this->value->toBits(), $length, '0', STR_PAD_LEFT);
	}

	public function getNAF($w = 1)
	{
		$w++;

		$mask = new BigInteger((1 << $w) - 1);
		$sub = new BigInteger(1 << $w);

		$d = $this->toBigInteger();
		$d_i = [];

		$i = 0;
		while ($d->compare(static::$zero[static::class]) > 0) {
			if ($d->isOdd()) {

				$bigInteger = $d->testBit($w - 1) ?
					$d->bitwise_and($mask)->subtract($sub) :

					$d->bitwise_and($mask);

				$d = $d->subtract($bigInteger);
				$d_i[$i] = (int) $bigInteger->toString();
			} else {
				$d_i[$i] = 0;
			}
			$shift = !$d->equals(static::$zero[static::class]) && $d->bitwise_and($mask)->equals(static::$zero[static::class]) ? $w : 1;
			$d = $d->bitwise_rightShift($shift);
			while (--$shift > 0) {
				$d_i[++$i] = 0;
			}
			$i++;
		}

		return $d_i;
	}

	public function toBigInteger()
	{
		return clone $this->value;
	}

	public function __toString()
	{
		return (string) $this->value;
	}

	public function __debugInfo()
	{
		return ['value' => $this->toHex()];
	}
}
}

namespace phpseclib3\Math {

use phpseclib3\Math\Common\FiniteField;
use phpseclib3\Math\PrimeField\Integer;

class PrimeField extends FiniteField
{

	private static $instanceCounter = 0;

	protected $instanceID;

	public function __construct(BigInteger $modulo)
	{
		if (!$modulo->isPrime()) {
			throw new \UnexpectedValueException('PrimeField requires a prime number be passed to the constructor');
		}

		$this->instanceID = self::$instanceCounter++;
		Integer::setModulo($this->instanceID, $modulo);
		Integer::setRecurringModuloFunction($this->instanceID, $modulo->createRecurringModuloFunction());
	}

	public function setReduction(\Closure $func)
	{
		$this->reduce = $func->bindTo($this, $this);
	}

	public function newInteger(BigInteger $num)
	{
		return new Integer($this->instanceID, $num);
	}

	public function randomInteger()
	{
		static $one;
		if (!isset($one)) {
			$one = new BigInteger(1);
		}

		return new Integer($this->instanceID, BigInteger::randomRange($one, Integer::getModulo($this->instanceID)));
	}

	public function getLengthInBytes()
	{
		return Integer::getModulo($this->instanceID)->getLengthInBytes();
	}

	public function getLength()
	{
		return Integer::getModulo($this->instanceID)->getLength();
	}

	public function __destruct()
	{
		Integer::cleanupCache($this->instanceID);
	}
}
}