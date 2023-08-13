<?php

use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mailer\Transport;
use Symfony\Component\Mime\Email;

require 'vendor/autoload.php';

$ip = "";

if($argc >= 1) {
    $ip = $argv[1];
//      echo "Running with ip " . $ip;
}

$abuseEmail = "";

$whois = shell_exec('whois ' . $ip);

if($whois === false) {
    echo "Failed to whois the ip";
    exit(1);
}

preg_match('/abuse-mailbox:\s*([^\n\r]+)/i', $whois, $matches); //RIPE & APNIC

$abuseEmail = "";

if(empty($matches)) {
    echo 'No abuse email match found.';
    if(preg_match('/OrgAbuseEmail:\s*([^\n\r]+)/i', $whois, $matches)) { //ARIN
        $abuseEmail = $matches[1];
    } else if(preg_match('/e-mail:\s*([^\n\r]+)/i', $whois, $matches)) { //Nic.br
        $abuseEmail = $matches[1];
    } else {
        exit(2);
    }
}

if(!filter_var($matches[1], FILTER_VALIDATE_EMAIL)) {
    echo 'Unable to validate the abuse mail';
    exit(3);
}

$abuseEmail = $matches[1];

//Send the abuse email
$user = "";
$password = "";
$port = 465;

$nocEmail = '';
$serverIp = '';

$server = "";

$transport = Transport::fromDsn("smtp://" . urlencode($user) . ':' . urlencode($password) . '@' . $server . ':' . $port);
$mailer = new Mailer($transport);

$msg = 'Hello, you are receiving this message because you are responsable for the following ip [' . $ip . '] which was used in a attack against ours services. Please do all the necessary things in order to no repeat the attack, or to reduce it. For records, our current ip is ' . $serverIp;

$attach = [
    'Version' => '1',
    'ReporterInfo' => [
        'ReporterOrg' => '',
        'ReporterOrgDomain' => '',
        'ReporterOrgEmail' => $nocEmail,
        'ReporterContactEmail' => $nocEmail,
        'ReporterContactName' => 'Network Operations Control',
        'ReporterContactPhone' => 'null'
    ],
    'Disclosure' => true,
    'Report' => [
        'ReportClass' => 'Activity',
        'ReportType' => 'LoginAttack',
        'Date' => (new \DateTime())->format(DATE_ATOM),
        'SourceIp' => $ip,
        'DestinationIp' => $serverIp
    ]
];

$message = (new Email())
    ->subject('Abuse contact for ip')
    ->from('')
    ->replyTo('')
    ->to($abuseEmail)
    ->cc($nocEmail)
    ->text($msg)
    ->attach(json_encode($attach), 'xarf.json', 'application/json');

try {
    $mailer->send($message);
    echo "Mails successfully send.";
} catch (\Symfony\Component\Mailer\Exception\TransportExceptionInterface $e) {
    echo "Some error happend : " . $e->getMessage();
}

//echo 'End of the script';
