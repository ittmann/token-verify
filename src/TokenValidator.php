<?php

namespace Ittmann\TokenVerify;

use Exception;
use PDO;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

class TokenValidator
{
    private bool $debug = false;
    private string $smtp_server;
    private bool $smtp_auth;
    private string $smtp_username;
    private string $smtp_password;
    private string $mail_from_address;
    private string $mail_from_name;
    private string $mail_subject;
    private string $mail_body; // HTML body
    private string $mail_alt_body; // Plain text body
    private string $token_expires_minutes;
    private string $token_cleanup_hours;
    private string $backoff_time_minutes;
    private string $backoff_amount;
    private string $db_file;

    private PDO $pdo;

    public function __construct() {
        $this->setEnvValues();
        $this->pdo = $this->initDb();
    }

    private function setEnvValues(): void
    {
        $this->debug = ($_ENV['APP_DEBUG'] ?? 'false') === 'true';
        $this->smtp_server = $_ENV['SMTP_SERVER'] ?? 'smtp.example.com';
        $this->smtp_auth = ($_ENV['SMTP_AUTH'] ?? 'true') === 'true';
        $this->smtp_username = $_ENV['SMTP_USERNAME'] ?? 'user@example.com';
        $this->smtp_password = $_ENV['SMTP_PASSWORD'] ?? 'secret';
        $this->mail_from_address = $_ENV['MAIL_FROM_ADDRESS'] ?? 'from@example.com';
        $this->mail_from_name = $_ENV['MAIL_FROM_NAME'] ?? 'Mailer';
        $this->mail_subject = $_ENV['MAIL_SUBJECT'] ?? 'Reset token';
        $this->mail_body = $_ENV['MAIL_BODY'] ?? 'Use this token to reset your password: <b>%s</b>'; // HTML body
        $this->mail_alt_body = $_ENV['MAIL_ALT_BODY'] ?? 'Use this token to reset your password: %s'; // Plain text body
        $this->token_expires_minutes = $_ENV['TOKEN_EXPIRES_MINUTES'] ?? 5;
        $this->token_cleanup_hours = $_ENV['TOKEN_CLEANUP_HOURS'] ?? 1;
        $this->backoff_time_minutes = $_ENV['BACKOFF_TIME_MINUTES'] ?? 60;
        $this->backoff_amount = $_ENV['BACKOFF_AMOUNT'] ?? 3;
        $this->db_file = $_ENV['DB_FILE'] ?? 'db/db.sqlite3';
    }
    public function processRequest(): void
    {
        $action = $_POST['action'] ?? null;
        $email  = $_POST['email'] ?? null;
        $code  = $_POST['code'] ?? null;

        $email = is_string($email) ? trim($email) : null;

        if ($email !== null && filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $this->errorResponse(400, 'Invalid email');
        }

        switch ($action) {
            case 'resetpassword':
                if (!$email) {
                    $this->errorResponse(400, 'Missing email parameter');
                } else {
                    if (!$this->backOff($email)) {
                        $this->insertRequest($email);
                        $found = $this->dbGetToken($email);
                        if ($found) {
                            $sql = "DELETE FROM tokens WHERE email = ?";
                            $this->pdo->prepare($sql)->execute([$email]);
                        }
                        $code = random_int(10000, 99999);
                        $sql = "INSERT INTO tokens (email, code, time) VALUES (?,?,?)";
                        $this->pdo->prepare($sql)->execute([$email, $code, time()]);

                        $this->sendTokenMail($email, $code);
                        $this->jsonResponse(['backoff' => false]);
                    }
                }
                break;
            case 'verifypasscode':
                if (!$email || !$code) {
                    $this->errorResponse(400, 'Missing parameters');
                } else {
                    if (!$this->backOff($email)) {
                        $this->insertRequest($email);
                        $email = htmlspecialchars($email);
                        $code = htmlspecialchars($code);
                        $this->dbCleanupTokens();
                        $token = $this->dbGetToken($email, $code);
                        if (!$token) {
                            $result = ['result' => false, 'error' => 'No token found'];
                        } elseif (time() - $token->time > $this->token_expires_minutes * 60) {
                            $result = ['result' => false, 'error' => 'Token expired'];
                        } else {
                            $result = ['result' => true];
                        }
                        $this->jsonResponse($result);
                    }
                }
                break;
            default:
                $this->errorResponse(400, 'Invalid action');
        }
    }

    private function initDb(): PDO {
        $dbPath = realpath(dirname(__DIR__)) . '/' . $this->db_file;
        $pdo = new PDO('sqlite:' . $dbPath);

        $query = "CREATE TABLE IF NOT EXISTS tokens (
            email VARCHAR(255) PRIMARY KEY,
            code VARCHAR(255),
            time INTEGER)";
        $pdo->exec($query);

        $query = "CREATE TABLE IF NOT EXISTS requests (
            email VARCHAR(255),
            time INTEGER)
        ";
        $pdo->exec($query);

        return $pdo;
    }

    private function dbCleanupTokens():void
    {
        $sql = "DELETE FROM requests WHERE time < ?";
        $this->pdo->prepare($sql)->execute([time() - $this->token_cleanup_hours * 60 * 60]);
    }

    private function dbGetToken(string $email, ?string $code = null): Token|false
    {
        $query = "SELECT * FROM tokens WHERE email = :email";
        if ($code) {
            $query .= " AND code = :code";
        }
        $stmt = $this->pdo->prepare($query);
        $stmt->bindParam(':email', $email);
        if ($code) {
            $stmt->bindParam(':code', $code);
        }
        $stmt->execute();
        return $stmt->fetchObject(Token::class);
    }

    private function sendTokenMail(string $email, string $code): void {
        $mail = new PHPMailer(true);
        try {
//            $mail->SMTPDebug = SMTP::DEBUG_SERVER;                    //Enable verbose debug output
            $mail->isSMTP();                                            //Send using SMTP
            $mail->Host       = $this->smtp_server;                     //Set the SMTP server to send through
            $mail->SMTPAuth   = $this->smtp_auth;                       //Enable SMTP authentication
            $mail->Username   = $this->smtp_username;                   //SMTP username
            $mail->Password   = $this->smtp_password;                   //SMTP password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;            //Enable implicit TLS encryption
            $mail->Port       = 465;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

            //Recipients
            $mail->setFrom($this->mail_from_address, $this->mail_from_name);
            $mail->addAddress($email);               //Name is optional

            //Content
            $mail->isHTML(true);                                  //Set email format to HTML
            $mail->Subject = $this->mail_subject;
            $mail->Body    = sprintf($this->mail_body, $code);
            $mail->AltBody = sprintf($this->mail_alt_body, $code);

            $mail->send();
        } catch (Exception $e) {
            $this->errorResponse(500, 'Message could not be sent. Mailer Error: ' . $mail->ErrorInfo);
        }
    }

    private function backOff(string $email): false {
        $sql = "DELETE FROM requests WHERE email = ? AND time < ?";
        $this->pdo->prepare($sql)->execute([$email, (time() - $this->backoff_time_minutes * 60)]);

        $sql = "SELECT COUNT(*) cnt FROM requests WHERE email = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$email]);

        $backoff = $stmt->fetch(PDO::FETCH_ASSOC)['cnt'] >= $this->backoff_amount;
        if ($backoff) {
            $this->jsonResponse(['backoff' => true]);
        }
        return $backoff;
    }

    private function insertRequest(string $email): void {
        $sql = "INSERT INTO requests (email, time) VALUES (?, ?)";
        $this->pdo->prepare($sql)->execute([$email, time()]);
    }

    private function jsonResponse(array $data): void {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
        die();
    }

    private function errorResponse(int $errorCode, string $errorText): void
    {
        $httpCodes = [
            '400' => 'Bad Request',
        ];
        $protocol = (isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0');
        header("$protocol $errorCode $httpCodes[$errorCode]");
        $this->jsonResponse($errorText);
    }
}
