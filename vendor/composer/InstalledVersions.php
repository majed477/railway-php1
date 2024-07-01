<?php

namespace Composer;

use Composer\Semver\VersionParser;






class InstalledVersions
{
private static $installed = array (
  'root' => 
  array (
    'pretty_version' => '1.0.0+no-version-set',
    'version' => '1.0.0.0',
    'aliases' => 
    array (
    ),
    'reference' => NULL,
    'name' => '__root__',
  ),
  'versions' => 
  array (
    '__root__' => 
    array (
      'pretty_version' => '1.0.0+no-version-set',
      'version' => '1.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => NULL,
    ),
    'heroku/heroku-buildpack-php' => 
    array (
      'pretty_version' => 'v121',
      'version' => '121.0.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '727aa850a02a7af94c9225237464be8e8c8ff6db',
    ),
    'monolog/monolog' => 
    array (
      'pretty_version' => '1.22.1',
      'version' => '1.22.1.0',
      'aliases' => 
      array (
      ),
      'reference' => '1e044bc4b34e91743943479f1be7a1d5eb93add0',
    ),
    'phpmailer/phpmailer' => 
    array (
      'pretty_version' => 'v6.4.0',
      'version' => '6.4.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '050d430203105c27c30efd1dce7aa421ad882d01',
    ),
    'pimple/pimple' => 
    array (
      'pretty_version' => 'v3.0.2',
      'version' => '3.0.2.0',
      'aliases' => 
      array (
      ),
      'reference' => 'a30f7d6e57565a2e1a316e1baf2a483f788b258a',
    ),
    'psr/log' => 
    array (
      'pretty_version' => '1.0.2',
      'version' => '1.0.2.0',
      'aliases' => 
      array (
      ),
      'reference' => '4ebe3a8bf773a19edfe0a84b6585ba3d401b724d',
    ),
    'psr/log-implementation' => 
    array (
      'provided' => 
      array (
        0 => '1.0.0',
      ),
    ),
    'silex/api' => 
    array (
      'replaced' => 
      array (
        0 => 'v2.0.4',
      ),
    ),
    'silex/providers' => 
    array (
      'replaced' => 
      array (
        0 => 'v2.0.4',
      ),
    ),
    'silex/silex' => 
    array (
      'pretty_version' => 'v2.0.4',
      'version' => '2.0.4.0',
      'aliases' => 
      array (
      ),
      'reference' => '49ca08d853731d1635374e5019c8696cfd53c161',
    ),
    'symfony/debug' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => '56f613406446a4a0a031475cfd0a01751de22659',
    ),
    'symfony/event-dispatcher' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => '154bb1ef7b0e42ccc792bd53edbce18ed73440ca',
    ),
    'symfony/http-foundation' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => 'cb0b6418f588952c9290b3df4ca650f1b7ab570a',
    ),
    'symfony/http-kernel' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => '8285ab5faf1306b1a5ebcf287fe91c231a6de88e',
    ),
    'symfony/polyfill-mbstring' => 
    array (
      'pretty_version' => 'v1.3.0',
      'version' => '1.3.0.0',
      'aliases' => 
      array (
      ),
      'reference' => 'e79d363049d1c2128f133a2667e4f4190904f7f4',
    ),
    'symfony/routing' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => 'd6605f9a5767bc5bc4895e1c762ba93964608aee',
    ),
    'symfony/twig-bridge' => 
    array (
      'pretty_version' => 'v3.2.7',
      'version' => '3.2.7.0',
      'aliases' => 
      array (
      ),
      'reference' => 'cb632b9a81f0262d6eff9097e46903f272070015',
    ),
    'twig/twig' => 
    array (
      'pretty_version' => 'v2.3.0',
      'version' => '2.3.0.0',
      'aliases' => 
      array (
      ),
      'reference' => '9718186a5df85a4f7917e78d3ffcabc204c75d25',
    ),
  ),
);







public static function getInstalledPackages()
{
return array_keys(self::$installed['versions']);
}









public static function isInstalled($packageName)
{
return isset(self::$installed['versions'][$packageName]);
}














public static function satisfies(VersionParser $parser, $packageName, $constraint)
{
$constraint = $parser->parseConstraints($constraint);
$provided = $parser->parseConstraints(self::getVersionRanges($packageName));

return $provided->matches($constraint);
}










public static function getVersionRanges($packageName)
{
if (!isset(self::$installed['versions'][$packageName])) {
throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}

$ranges = array();
if (isset(self::$installed['versions'][$packageName]['pretty_version'])) {
$ranges[] = self::$installed['versions'][$packageName]['pretty_version'];
}
if (array_key_exists('aliases', self::$installed['versions'][$packageName])) {
$ranges = array_merge($ranges, self::$installed['versions'][$packageName]['aliases']);
}
if (array_key_exists('replaced', self::$installed['versions'][$packageName])) {
$ranges = array_merge($ranges, self::$installed['versions'][$packageName]['replaced']);
}
if (array_key_exists('provided', self::$installed['versions'][$packageName])) {
$ranges = array_merge($ranges, self::$installed['versions'][$packageName]['provided']);
}

return implode(' || ', $ranges);
}





public static function getVersion($packageName)
{
if (!isset(self::$installed['versions'][$packageName])) {
throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}

if (!isset(self::$installed['versions'][$packageName]['version'])) {
return null;
}

return self::$installed['versions'][$packageName]['version'];
}





public static function getPrettyVersion($packageName)
{
if (!isset(self::$installed['versions'][$packageName])) {
throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}

if (!isset(self::$installed['versions'][$packageName]['pretty_version'])) {
return null;
}

return self::$installed['versions'][$packageName]['pretty_version'];
}





public static function getReference($packageName)
{
if (!isset(self::$installed['versions'][$packageName])) {
throw new \OutOfBoundsException('Package "' . $packageName . '" is not installed');
}

if (!isset(self::$installed['versions'][$packageName]['reference'])) {
return null;
}

return self::$installed['versions'][$packageName]['reference'];
}





public static function getRootPackage()
{
return self::$installed['root'];
}







public static function getRawData()
{
return self::$installed;
}



















public static function reload($data)
{
self::$installed = $data;
}
}
