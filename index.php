<?php
require_once 'WikiAphpi/main.php';

/**
 * Telegram Verification Class.
 *
 * This class extends the WikiAphpiOAuth class and is specialized for handling Telegram verification. It provides methods
 * to check Telegram authorization data, ensuring that it is valid and not outdated. The class utilizes OAuth for token
 * management, interacting with the MediaWiki API. It also includes functionality to handle the insertion of verification
 * entries into the 'verifications' table, storing information related to Telegram and corresponding Wiki user details.
 *
 */
class TelegramVerify extends WikiAphpiOAuth
{
    private $mysqli;

    /**
     * Constructs a new instance of the class.
     *
     * @param mixed $endpoint The initial endpoint for the object.
     * @throws mysqli_sql_exception if there is an error establishing the database connection.
     */
    public function __construct($endpoint, $consumerKey, $consumerSecret)
    {
        parent::__construct($endpoint, $consumerKey, $consumerSecret);
        $ts_pw = posix_getpwuid(posix_getuid());
        $ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");
        $this->mysqli = new mysqli(
            'tools.db.svc.eqiad.wmflabs',
            $ts_mycnf['user'],
            $ts_mycnf['password'],
            $ts_mycnf['user']."__telegram"
        );
    }

    /**
     * Checks the authorization data received from Telegram.
     *
     * This method verifies the authenticity of the data received from Telegram during user
     * authorization. It checks the integrity of the data using a hash and ensures that the
     * data is recent. If the data is valid, it is returned; otherwise, a
     * ContentRetrievalException is thrown with a corresponding error message.
     *
     * @param array  $auth_data           The authorization data received from Telegram.
     * @param string $telegramVerifyToken The verification token provided by Telegram.
     *
     * @throws ContentRetrievalException When the data is not from Telegram or is outdated.
     *
     * @return array The valid authorization data from Telegram.
     */
    public function checkTelegramAuthorization($auth_data, $telegramVerifyToken) {
        if (
            !isset($auth_data['hash'], $auth_data['auth_date']) ||
            !is_string($auth_data['hash']) ||
            !is_numeric($auth_data['auth_date'])
        ) {
            throw new ContentRetrievalException('Telegram authentication data is incomplete.');
        }

        $check_hash = $auth_data['hash'];
        unset($auth_data['hash']);
        unset($auth_data['channel']);
        ksort($auth_data);
        $data_check_string = urldecode(http_build_query($auth_data, "", "\n"));
        $secret_key = hash('sha256', $telegramVerifyToken, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);
        if (!hash_equals($hash, $check_hash)) {
            throw new ContentRetrievalException('Data is NOT from Telegram');
        }
        if ((time() - (int) $auth_data['auth_date']) > 86400 || (int) $auth_data['auth_date'] > time() + 60) {
            throw new ContentRetrievalException('Data from Telegram is outdated');
        }
        return $auth_data;
    }

    /**
     * Retrieves results from the 'verifications' table.
     *
     * This method performs a SQL SELECT query on the 'verifications' table to retrieve information
     * such as 't_id', 't_date', 't_username', 'w_username', and 'w_id'. The results are fetched
     * and returned as an array of rows. If there's an error in preparing or executing the SQL
     * query, a ContentRetrievalException is thrown.
     *
     * @throws ContentRetrievalException When there's an error executing the SQL query.
     *
     * @return array An array of rows containing the retrieved results from the table.
     */
    public function results()
    {
        $query = "SELECT t_id, t_date, t_username, w_username, w_id FROM verifications WHERE w_id IS NOT NULL ORDER BY n DESC";
        $stmt = $this->mysqli->prepare($query);

        if (!$stmt) {
            throw new ContentRetrievalException("Erro na consulta SQL");
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $list = [];

        while ($row = $result->fetch_assoc()) {
            $list[] = $row;
        }

        $stmt->close();
        return $list;
    }

    /**
     * Retrieves the list of administrators from the Telegram group.
     *
     * This method sends a request to the Telegram API to get the list of administrators in a
     * specific chat. It takes the Telegram verification token and the list of users as parameters.
     * The method returns an array of usernames of the administrators.
     *
     * @param string $telegramVerifyToken The verification token provided by Telegram.
     * @param array  $verifiedUsers       The list of users from the 'verifications' table.
     * @param string $channelId           The ID of the Telegram channel.
     *
     * @return array|null An array of usernames, or null if the Telegram API request failed.
     */
    public function getAdmins($telegramVerifyToken, $verifiedUsers, $channelId, &$error = null)
    {
        $admins = [];
        $data = $this->telegramApiRequest(
            $telegramVerifyToken,
            'getChatAdministrators',
            ['chat_id' => $channelId],
            $error
        );
        if ($data === null || !isset($data['result']) || !is_array($data['result'])) {
            return null;
        }

        foreach ($data['result'] as $admin) {
            // Ignore when admin is not a real admin, due to lack of admin rights in the group
            if ($admin['can_restrict_members'] === false) {
                continue;
            }

            foreach ($verifiedUsers as $verifiedUser) {
                if (isset($admin['user']['id'], $verifiedUser['t_id']) && $admin['user']['id'] == $verifiedUser['t_id']) {
                    $admins[] = $verifiedUser['w_username'];
                }
            }
        }
        return $admins;
    }

    /**
     * Makes a Telegram Bot API request without allowing warnings to expose the bot token.
     *
     * @param string      $telegramVerifyToken The Telegram bot token.
     * @param string      $method              The Bot API method.
     * @param array       $params              Request parameters.
     * @param string|null $error               Receives a safe error description on failure.
     *
     * @return array|null The successful API response, or null on failure.
     */
    private function telegramApiRequest($telegramVerifyToken, $method, array $params, &$error = null)
    {
        $error = null;
        $url = "https://api.telegram.org/bot{$telegramVerifyToken}/{$method}?" . http_build_query($params);
        $context = stream_context_create([
            'http' => [
                'ignore_errors' => true,
                'timeout' => 10
            ]
        ]);
        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            $error = 'Could not connect to the Telegram API.';
            return null;
        }

        $data = json_decode($response, true);
        if (!is_array($data)) {
            $error = 'The Telegram API returned an invalid response.';
            return null;
        }
        if (empty($data['ok'])) {
            $error = $data['description'] ?? 'The Telegram API rejected the request.';
            if ($telegramVerifyToken !== '') {
                $error = str_replace($telegramVerifyToken, '[redacted]', $error);
            }
            return null;
        }

        return $data;
    }

    /**
     * Creates a new verification entry in the 'verifications' table.
     *
     * This method prepares and executes a SQL REPLACE statement to insert or update a verification
     * entry in the 'verifications' table. It takes authentication data ($authData) and a Wiki
     * username ($wikiuser) as parameters. The 't_id', 't_date', 't_username', 'w_username', and
     * 'w_id' columns are updated with the corresponding values. If the operation is successful,
     * the method returns true. If there's an error in preparing the SQL statement, executing it,
     * or if the row is not inserted, a relevant exception is thrown.
     *
     * @param array  $authData  Authentication data containing 'id', 'auth_date', and 'username' (optional).
     * @param string $wikiuser  Wiki username for which the verification is being created.
     *
     * @throws UnexpectedValueException   When there's an error in preparing the SQL statement.
     * @throws ContentRetrievalException  When there's an error in executing the SQL statement or the row is not inserted.
     *
     * @return bool True if the verification entry is successfully created or updated.
     */
    public function newVerification($authData, $wikiuser)
    {
        $t_id = $authData['id'];
        $t_date = $authData['auth_date'];
        $t_username = $authData['username'] ?? null;

        $api_params = [
            "action"    => "query",
            "format"    => "json",
            "list"      => "users",
            "ususers"   => $wikiuser
        ];
        $api = "https://meta.wikimedia.org/w/api.php?" . http_build_query($api_params);
        $response = @file_get_contents($api);
        if ($response === false) {
            throw new ContentRetrievalException("Não foi possível consultar a API da Wikimedia.");
        }

        $api = json_decode($response, true);
        if (!is_array($api)) {
            throw new ContentRetrievalException("Resposta JSON inválida da API da Wikimedia: " . json_last_error_msg());
        }
        if (isset($api['error'])) {
            throw new ContentRetrievalException("Erro na API da Wikimedia: " . ($api['error']['info'] ?? 'erro desconhecido'));
        }

        $wikiUserData = $api['query']['users'][0] ?? null;
        if (
            !is_array($wikiUserData) ||
            !isset($wikiUserData['name'], $wikiUserData['userid']) ||
            !is_numeric($wikiUserData['userid'])
        ) {
            throw new ContentRetrievalException("A API da Wikimedia não retornou um usuário válido para {$wikiuser}.");
        }

        $w_username = $wikiUserData['name'];
        $w_id = (int) $wikiUserData['userid'];

        $stmt = $this->mysqli->prepare(
            "REPLACE INTO verifications (t_id, t_date, t_username, w_username, w_id) VALUES (?, ?, ?, ?, ?)"
        );
        if (!$stmt) {
            throw new UnexpectedValueException("Error in prepare statement:".$this->mysqli->error);
        }

        $stmt->bind_param('iissi', $t_id, $t_date, $t_username, $w_username, $w_id);
        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            $stmt->close();
            return true;
        } else {
            throw new ContentRetrievalException("Row not inserted!");
        }
    }

    /**
     * Unmutes a Telegram user in a chat.
     *
     * This method sends a request to the Telegram API to unmute a user in a chat. It takes the
     * authentication data ($authData) and the Telegram verification token ($telegramVerifyToken)
     * as parameters. The user is unmuted in the chat with the ID "-1001169425230". The user is
     * unmuted for 100 seconds and, then, it reverts to the default group permissions.
     *
     * @param array  $authData            Authentication data containing 'id', 'auth_date', and 'username' (optional).
     * @param string $telegramVerifyToken The verification token provided by Telegram.
     * @param string $channelId           The ID of the Telegram channel.
     *
     * @return array The response from the Telegram API as an associative array.
     */
    public function unmuteTelegramUser($authData, $telegramVerifyToken, $channelId) {
        $user_id = $authData['id'];

        $params = [
            "chat_id" => $channelId,
            "user_id" => $user_id,
            "until_date" => time() + 100,
            "permissions" => [
                "can_send_messages" => true,
                "can_send_audios" => true,
                "can_send_documents" => true,
                "can_send_photos" => true,
                "can_send_videos" => true,
                "can_send_video_notes" => true,
                "can_send_voice_notes" => true,
                "can_send_polls" => true,
                "can_send_other_messages" => true,
                "can_add_web_page_previews" => true,
                "can_change_info" => false,
                "can_invite_users" => true,
                "can_pin_messages" => false,
                "can_manage_topics" => false,
            ]
        ];

        $api = "https://api.telegram.org/bot" . $telegramVerifyToken . "/restrictChatMember";

        #Make a Curl POST request to the Telegram API
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $api);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($params));
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        $response = curl_exec($curl);
        $curlError = curl_error($curl);
        curl_close($curl);

        if ($response === false) {
            return ['ok' => false, 'description' => 'Telegram API request failed: ' . $curlError];
        }

        $result = json_decode($response, true);
        return is_array($result) ? $result : ['ok' => false, 'description' => 'Invalid response from Telegram API.'];
    }

    /**
     * Handles the verification of a Telegram user.
     *
     * This method processes the verification of a Telegram user by checking their username or ID
     * against the database and the Telegram group. It returns the corresponding wiki user details
     * if the verification is successful.
     *
     * @param string $telegramUser The Telegram username or ID to verify.
     * @param string $telegramVerifyToken The Telegram bot token for API requests.
     * @param string $channelId The Telegram channel ID.
     *
     * @return array An associative array containing the verification result and user data.
     */
    public function verifyTelegramUser($telegramUser, $telegramVerifyToken, $channelId) {
        $telegramUser = trim($telegramUser); // Trim whitespace
        $result = ['success' => false, 'message' => ''];

        if (!is_numeric($telegramUser)) {
            // Check the database for the username and retrieve the Telegram ID
            $stmt = $this->mysqli->prepare("SELECT t_id FROM verifications WHERE t_username = ?");
            $stmt->bind_param('s', $telegramUser);
            $stmt->execute();
            $dbResult = $stmt->get_result();
            $row = $dbResult->fetch_assoc();
            $stmt->close();

            if ($row) {
                $telegramUser = $row['t_id']; // Use the Telegram ID from the database
            } else {
                $result['message'] = 'Username not found in the database.';
                return $result;
            }
        }

        // The step is important to avoid admins to verify users from other groups
        $response = $this->telegramApiRequest(
            $telegramVerifyToken,
            'getChatMember',
            ['chat_id' => $channelId, 'user_id' => $telegramUser],
            $apiError
        );

        if (isset($response['result']['user'])) {
            $stmt = $this->mysqli->prepare("SELECT w_username, w_id FROM verifications WHERE t_id = ? OR t_username = ?");
            $stmt->bind_param('is', $response['result']['user']['id'], $telegramUser);
            $stmt->execute();
            $dbResult = $stmt->get_result();
            $userData = $dbResult->fetch_assoc();
            $stmt->close();

            if ($userData) {
                $result['success'] = true;
                $result['data'] = ['wikiUsername' => $userData['w_username'], 'wikiUserId' => $userData['w_id']];
            } else {
                $result['message'] = 'User not found in the database.';
            }
        } else {
            $result['message'] = $apiError ?? 'User not found in the Telegram group.';
        }

        return $result;
    }

    /**
     * Retrieves channel information for the given group list.
     *
     * @param array $groups_list List of group IDs to fetch information for.
     * @param string $telegramVerifyToken Telegram bot token for API requests.
     * @param array  $errors              Receives errors for groups that could not be loaded.
     *
     * @return array An array of channels with their ID, name, and photo URL.
     */
    public function getChannels(array $groups_list, string $telegramVerifyToken, &$errors = []): array
    {
        $channels = [];
        $errors = [];
        $context = stream_context_create([
            'http' => [
                'ignore_errors' => true,
                'timeout' => 10
            ]
        ]);
        $photoCacheDirectory = __DIR__ . '/channel_photos';
        if (!is_dir($photoCacheDirectory) && !@mkdir($photoCacheDirectory, 0755, true) && !is_dir($photoCacheDirectory)) {
            error_log("Could not create channel photo cache directory: {$photoCacheDirectory}");
            $photoCacheDirectory = null;
        }

        foreach ($groups_list as $groupId) {
            $data = $this->telegramApiRequest(
                $telegramVerifyToken,
                'getChat',
                ['chat_id' => $groupId],
                $error
            );
            if ($data === null || !isset($data['result']) || !is_array($data['result'])) {
                $errors[] = "Group {$groupId}: {$error}";
                continue;
            }

            $photoBase64 = null;
            $photoUrl = null;
            if (isset($data['result']['photo']['small_file_id'])) {
                $photo = $data['result']['photo'];
                $photoVersion = $photo['small_file_unique_id'] ?? $photo['small_file_id'];
                $cacheFileName = hash('sha256', (string)$groupId) . '-' . hash('sha256', (string)$photoVersion) . '.jpg';
                $cacheFilePath = $photoCacheDirectory === null
                    ? null
                    : $photoCacheDirectory . '/' . $cacheFileName;

                if ($cacheFilePath !== null && is_file($cacheFilePath)) {
                    $photoUrl = 'channel_photos/' . $cacheFileName;
                } else {
                    $fileData = $this->telegramApiRequest(
                        $telegramVerifyToken,
                        'getFile',
                        ['file_id' => $photo['small_file_id']],
                        $photoError
                    );
                    if (isset($fileData['result']['file_path'])) {
                        $filePath = $fileData['result']['file_path'];
                        $fileUrl = "https://api.telegram.org/file/bot" . $telegramVerifyToken . "/" . $filePath;
                        $photoContent = @file_get_contents($fileUrl, false, $context);
                        if ($photoContent !== false) {
                            if ($cacheFilePath !== null) {
                                $temporaryFile = @tempnam($photoCacheDirectory, '.channel-photo-');
                                if ($temporaryFile !== false) {
                                    $written = file_put_contents($temporaryFile, $photoContent, LOCK_EX);
                                    if ($written === strlen($photoContent) && @rename($temporaryFile, $cacheFilePath)) {
                                        $photoUrl = 'channel_photos/' . $cacheFileName;
                                    } else {
                                        @unlink($temporaryFile);
                                        if (is_file($cacheFilePath)) {
                                            $photoUrl = 'channel_photos/' . $cacheFileName;
                                        } else {
                                            error_log("Could not write channel photo cache file: {$cacheFilePath}");
                                        }
                                    }
                                } else {
                                    error_log("Could not create temporary channel photo cache file in: {$photoCacheDirectory}");
                                }
                            }
                            if ($photoUrl === null) {
                                $photoBase64 = base64_encode($photoContent);
                            }
                        }
                    }
                }
            }

            $channels[] = [
                'id' => $groupId,
                'name' => $data['result']['title'] ?? 'Unknown',
                'photo' => $photoUrl ?? ($photoBase64 === null ? null : 'data:image/jpeg;base64,' . $photoBase64)
            ];
        }
        return $channels;
    }

}

$ts_pw = posix_getpwuid(posix_getuid());
$ts_tokens = parse_ini_file($ts_pw['dir'] . "/tokens.inc");
$verify_consumer_token = $ts_tokens['verify_consumer_token'];
$verify_secret_token = $ts_tokens['verify_secret_token'];
$telegramVerifyToken = $ts_tokens['TelegramVerifyToken'];

// Instantiate a new TelegramVerify object for handling Telegram verification.
$verify = new TelegramVerify(
    'https://meta.wikimedia.org/w/api.php',
    $verify_consumer_token,
    $verify_secret_token
);

// Retrieve verification results from the 'verifications' table.
$verifiedUsers = $verify->results();

// Check if the user is logged in through OAuth.
$user = false;
$loginError = null;
try {
    $user = $verify->checkLogin();
} catch (ContentRetrievalException $e) {
    http_response_code(200);
    $loginError = 'Wikimedia could not confirm your login right now. Please retry the login.';
}

// Get the list of groups from the 'groups_list.inc' file.
// This file should contain a list of group IDs, one per line.
$groups_file = __DIR__ . '/groups_list.inc';
$groups_list = [];
$group_settings = [];
if (file_exists($groups_file)) {
    foreach (file($groups_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $group_line) {
        if (strpos($group_line, ':') !== false) {
            list($group_id, $delete_enabled) = explode(':', $group_line, 2);
            $groups_list[] = $group_id;
            $group_settings[$group_id] = filter_var($delete_enabled, FILTER_VALIDATE_BOOLEAN);
        } else {
            $groups_list[] = $group_line;
            $group_settings[$group_line] = false; // Default to false if not specified
        }
    }
}

// Check if a channel is selected in the GET request.
if (isset($_GET['channel']) && in_array($_GET['channel'], $groups_list)) {

    // If a channel is selected, retrieve its ID from the GET request.
    $channelId = $_GET['channel'];

    // Get administrators of the chat
    $admins = $verify->getAdmins($telegramVerifyToken, $verifiedUsers, $channelId, $adminError);
    $telegramActionError = $admins === null
        ? 'Telegram could not provide the administrator list (' . $adminError . '). Verification can continue, but Telegram permissions will not be changed.'
        : null;

    // Check if the "auth_date" parameter from Telegram is present in the GET request.
    // In this case, the user is at the last step of the verification process, after Telegram authentication.
    if (isset($_GET["auth_date"])) {
        if (!is_array($user) || empty($user['username'])) {
            $verificationError = $loginError ?? 'Please sign in to Wikimedia again before verifying with Telegram.';
        } else {
            try {
                $validatedAuthData = $verify->checkTelegramAuthorization($_GET, $telegramVerifyToken);
            } catch (ContentRetrievalException $e) {
                http_response_code(200);
                $verificationError = 'Telegram authentication could not be verified or has expired. Please restart the Telegram login.';
            }

            if (isset($validatedAuthData)) {
                try {
                    $verify->newVerification($validatedAuthData, $user['username']);
                    $authData = $validatedAuthData;
                } catch (ContentRetrievalException $e) {
                    http_response_code(200);
                    $verificationError = 'The verification could not be saved right now. Please try again later.';
                }

                if (isset($authData) && is_array($admins) && !in_array($user['username'], $admins, true)) {
                    $unmuteResult = $verify->unmuteTelegramUser($authData, $telegramVerifyToken, $channelId);
                    if (empty($unmuteResult['ok'])) {
                        $telegramActionError = 'Verification was saved, but Telegram could not update your group permissions. Please contact a group administrator.';
                    }
                }
            }
        }
    }

    // Handle admin panel POST for message deletion setting
    if (
        $_SERVER['REQUEST_METHOD'] === 'POST' &&
        isset($_POST['delete_enabled']) &&
        isset($channelId) &&
        isset($user['username']) &&
        isset($admins) &&
        in_array($user['username'], $admins)
    ) {
        $delete_enabled = $_POST['delete_enabled'] === '1' ? 'true' : 'false';
        $new_lines = [];
        foreach ($group_settings as $gid => $enabled) {
            if ($gid == $channelId) {
                $new_lines[] = $gid . ':' . $delete_enabled;
            } else {
                $new_lines[] = $gid . ':' . ($enabled ? 'true' : 'false');
            }
        }
        file_put_contents($groups_file, implode(PHP_EOL, $new_lines) . PHP_EOL);
        $group_settings[$channelId] = $delete_enabled === 'true';
        // Optional: reload page to reflect changes
        header('Location: ' . $_SERVER['REQUEST_URI']);
        exit;
    }

} else {

    // If no channel is selected, retrieve the list of channels from the Telegram API.
    $channelErrors = [];
    $channels = $verify->getChannels($groups_list, $telegramVerifyToken, $channelErrors);
}

// Small API to check an user in the group with a wiki username
if (
    $_SERVER['REQUEST_METHOD'] === 'POST' &&
    isset($_POST['action'], $user['username'], $admins) &&
    $_POST['action'] === 'checkUser' &&
    is_array($admins) &&
    in_array($user['username'], $admins, true)
) {
    $telegramUser = trim($_POST['telegramUser']); // Trim whitespace
    $verificationResult = $verify->verifyTelegramUser($telegramUser, $telegramVerifyToken, $channelId);
    if ($verificationResult['success']) {
        echo json_encode(['success' => true, 'data' => $verificationResult['data']]);
    } else {
        echo json_encode(['success' => false, 'message' => $verificationResult['message']]);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
    <head>
        <title>WikiVerifyBot</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="./w3.css">
        <link rel="stylesheet" href="https://tools-static.wmflabs.org/cdnjs/ajax/libs/font-awesome/6.2.0/css/all.css">
        <script src="https://tools-static.wmflabs.org/cdnjs/ajax/libs/jquery/3.7.0/jquery.min.js"></script>
        <style>
            .stepper-wrapper {
                font-family: Arial;
                margin-top: 50px;
                display: flex;
                justify-content: space-between;
                margin-bottom: 20px;
            }
            .stepper-item {
                position: relative;
                display: flex;
                flex-direction: column;
                align-items: center;
                flex: 1;

                @media (max-width: 768px) {
                    font-size: 12px;
                }
            }

            .stepper-item::before {
                position: absolute;
                content: "";
                border-bottom: 2px solid #ccc;
                width: 100%;
                top: 20px;
                left: -50%;
                z-index: 2;
            }

            .stepper-item::after {
                position: absolute;
                content: "";
                border-bottom: 2px solid #ccc;
                width: 100%;
                top: 20px;
                left: 50%;
                z-index: 2;
            }

            .stepper-item .step-counter {
                position: relative;
                z-index: 5;
                display: flex;
                justify-content: center;
                align-items: center;
                width: 40px;
                height: 40px;
                border-radius: 50%;
                background: #ccc;
                margin-bottom: 6px;
            }

            .stepper-item.active {
                font-weight: bold;
            }

            .stepper-item.completed .step-counter {
                background-color: #4bb543;
            }

            .stepper-item.completed::after {
                position: absolute;
                content: "";
                border-bottom: 2px solid #4bb543;
                width: 100%;
                top: 20px;
                left: 50%;
                z-index: 3;
            }

            .stepper-item:first-child::before {
                content: none;
            }
            .stepper-item:last-child::after {
                content: none;
            }

            .loader {
                border: 16px solid #f3f3f3;
                border-radius: 50%;
                border-top: 16px solid #000000;
                width: 120px;
                height: 120px;
                margin: auto;
                animation: spin 2s linear infinite;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            #menu {
                display: none;
            }

            .custom-dropdown {
                position: relative;
                display: inline-block;
                width: 300px;
            }

            .dropdown-container {
                position: relative;
                cursor: pointer;
            }

            .dropdown-selected {
                padding: 10px;
                border: 1px solid #ccc;
                background-color: #fff;
                border-radius: 4px;
            }

            .dropdown-options {
                display: none;
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                border: 1px solid #ccc;
                background-color: #fff;
                z-index: 1000;
                max-height: 200px;
                overflow-y: auto;
            }

            .dropdown-option {
                padding: 2px;
                display: flex;
                align-items: center;
                cursor: pointer;
            }

            .dropdown-option:hover {
                background-color: #f0f0f0;
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function () {
                const dropdown = document.querySelector('.dropdown-container');
                const selected = document.querySelector('.dropdown-selected');
                const options = document.querySelector('.dropdown-options');
                const hiddenInput = document.querySelector('#channel');

                dropdown.addEventListener('click', function () {
                    options.style.display = options.style.display === 'block' ? 'none' : 'block';
                });

                options.addEventListener('click', function (e) {
                    if (e.target.classList.contains('dropdown-option')) {
                        const value = e.target.getAttribute('data-value');
                        const text = e.target.textContent.trim();
                        hiddenInput.value = value;
                        selected.textContent = text;
                        options.style.display = 'none';
                    }
                });

                document.addEventListener('click', function (e) {
                    if (!dropdown.contains(e.target)) {
                        options.style.display = 'none';
                    }
                });
            });

            // Save channelId to localStorage when the button is clicked
            function saveChannelIdAndRedirect(channelId) {
                localStorage.setItem('channelId', channelId);
                location.href = `<?=$_SERVER['SCRIPT_NAME']?>?oauth=seek`;
            }
        </script>
    </head>
    <body>
        <div class="w3-container">
            <div class="w3-content" style="max-width:800px">
                <h5 class="w3-center w3-padding-48"><span class="w3-tag w3-wide">WikiVerifyBot</span></h5>
                <div class="w3-row-padding w3-center w3-padding-8 w3-margin-top">
                    <div class="w3-container w3-margin w3-padding-12 w3-card w3-center">
                        <?php if ($loginError !== null): ?>
                            <div class="w3-panel w3-pale-yellow w3-left-align" role="alert">
                                <?php echo htmlspecialchars($loginError, ENT_QUOTES, 'UTF-8'); ?>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($verificationError)): ?>
                            <div class="w3-panel w3-pale-yellow w3-left-align" role="alert">
                                <?php echo htmlspecialchars($verificationError, ENT_QUOTES, 'UTF-8'); ?>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($telegramActionError)): ?>
                            <div class="w3-panel w3-pale-yellow w3-left-align" role="alert">
                                <?php echo htmlspecialchars($telegramActionError, ENT_QUOTES, 'UTF-8'); ?>
                            </div>
                        <?php endif; ?>
                        <?php if (!empty($channelErrors)): ?>
                            <div class="w3-panel w3-pale-yellow w3-left-align" role="alert">
                                <p>Some configured groups could not be loaded from Telegram. Check the group IDs and the bot's access to those groups.</p>
                                <ul>
                                    <?php foreach ($channelErrors as $channelError): ?>
                                        <li><?php echo htmlspecialchars($channelError, ENT_QUOTES, 'UTF-8'); ?></li>
                                    <?php endforeach; ?>
                                </ul>
                            </div>
                        <?php endif; ?>
                        <?php if(isset($channels) && !empty($channels)): ?>
                            <!-- Step 0: Channel Selection -->
                            <div class='loader' id='loader'></div>
                            <div id='menu' class="w3-section">
                                <form method='GET'>
                                    <label for='channel'>Please select a channel:</label>
                                    <div class='custom-dropdown'>
                                        <div class='dropdown-container'>
                                            <input type='hidden' id='channel' name='channel' required>
                                            <div class='dropdown-selected'>Select a channel</div>
                                            <div class='dropdown-options'>
                                                <?php foreach ($channels as $channel): ?>
                                                    <div class='dropdown-option' data-value='<?php echo htmlspecialchars($channel['id']); ?>'>
                                                        <?php if ($channel['photo']): ?>
                                                            <img src='<?php echo htmlspecialchars($channel['photo'], ENT_QUOTES, 'UTF-8'); ?>' alt='Channel' style='width: 20px; height: 20px; vertical-align: middle; margin-right: 5px;'>
                                                        <?php endif; ?>
                                                        <?php echo htmlspecialchars($channel['name']); ?>
                                                    </div>
                                                <?php endforeach; ?>
                                            </div>
                                        </div>
                                    </div>
                                    <button type='submit'>Submit</button>
                                </form>
                            </div>
                            <script>
                                // Check for channel ID and update the URL if necessary
                                const urlParams = new URLSearchParams(window.location.search);
                                if (!urlParams.has('channel') && localStorage.getItem('channelId')) {
                                    const channelId = localStorage.getItem('channelId');
                                    urlParams.set('channel', channelId);
                                    localStorage.removeItem('channelId');
                                    window.location.search = urlParams.toString();
                                } else {
                                    document.getElementById('loader').style.display = 'none';
                                    document.getElementById('menu').style.display = 'block';
                                }
                            </script>
                        <?php elseif(isset($channels)): ?>
                            <p><?php echo empty($groups_list) ? 'No groups are configured.' : 'No configured groups are currently available from Telegram.'; ?></p>
                        <?php elseif(isset($authData)): ?>
                            <!-- Step 3: Verification Success -->
                            <div class="stepper-wrapper">
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w" style="color: white;"></i></div>
                                    <div class="step-name">Authentication<br>Wikimedia</div>
                                </div>
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane" style="color: white;"></i></div>
                                    <div class="step-name">Authentication<br>Telegram</div>
                                </div>
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-solid fa-check" style="color: white;"></i></div>
                                    <div class="step-name">Completed</div>
                                </div>
                            </div>
                            <hr>
                            <svg xmlns="http://www.w3.org/2000/svg" width="150"
                            viewBox="0 0 20 20" height="150" style="margin: auto; width: auto;">
                                <path fill="green" d="m7,14.17-4.17-4.17-1.41,1.41 5.58,5.58 12-12-1.41-1.41"></path>
                            </svg>
                            <p>Hello <?=$user['username']?>! Your verification was successful and your name
                            has been added to the verified users table. Thank you!
                        <?php elseif($user): ?>
                            <!-- Step 2: Telegram Authentication -->
                            <div class="stepper-wrapper">
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w" style="color: white;"></i></div>
                                    <div class="step-name">Authentication<br>Wikimedia</div>
                                </div>
                                <div class="stepper-item active">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane"></i></div>
                                    <div class="step-name">Authentication<br>Telegram</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-solid fa-check"></i></div>
                                    <div class="step-name">Completed</div>
                                </div>
                            </div>
                            <hr>
                            <p>Hello <?=$user['username']?>! Next, authenticate with your
                            Telegram account using the button below.</p>
                            <script
                            async src="https://telegram.org/js/telegram-widget.js?22"
                            data-auth-url="<?=$_SERVER['SCRIPT_NAME']?>?channel=<?=$channelId?>"
                            data-telegram-login="WikiVerifyBot" data-size="large"></script>
                            <p>A new screen will open where you will log in via Telegram.
                            Some data may be requested by Telegram itself, such
                            as a phone number, but we will not have access to any
                            information about you except for your name and user number on the
                            platform.
                            </p>
                            <p>If the blue button is not displayed above, try opening
                            this page in a different browser or in an incognito tab.
                            </p>
                        <?php else: ?>
                            <!-- Step 1: Wikimedia Authentication -->
                            <div class="stepper-wrapper">
                                <div class="stepper-item active">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w"></i></div>
                                    <div class="step-name">Authentication<br>Wikimedia</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane"></i></div>
                                    <div class="step-name">Authentication<br>Telegram</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-solid fa-check"></i></div>
                                    <div class="step-name">Completed</div>
                                </div>
                            </div>
                            <hr>
                            <p>Hello! As the first step, you need to authenticate your wiki account using the button below.</p>
                            <button
                            class="w3-button w3-white w3-border"
                            onclick="saveChannelIdAndRedirect('<?=$channelId?>');"
                            >
                                <img src="./wikimedia.svg" alt="Wikimedia Logo" style="width: 30px; height: 30px;">
                            <br>Login</button>
                            <p>After authenticating on the Wiki, some scripts will be loaded directly
                                from Telegram servers. Be aware that by using this tool, your browsing
                                data may be stored on third-party servers not affiliated with WMF.
                            </p>
                        <?php endif; ?>
                    </div>
                    <?php if(isset($user['username']) && isset($admins) && in_array($user['username'], $admins)): ?>
                        <!-- Admin Panel -->
                        <div class="w3-container w3-margin w3-padding-48 w3-card w3-small" id="main">
                            <p style="color:red;">Administrative panel. If you are reading this message,
                            you are an administrator of the Telegram group</p>
                            <form id="userCheckForm" method="POST" action="<?=$_SERVER['SCRIPT_NAME']?>?channel=<?=$channelId?>">
                                <label for="telegramUser">Enter the Telegram ID or username:</label>
                                <input type="text" id="telegramUser" name="telegramUser" required>
                                <button type="submit">Verify</button>
                            </form>
                            <div id="userInfo" style="margin-top: 20px; display: none;">
                                <h4>User Information:</h4>
                                <p><strong>Wiki Account:</strong> <span id="wikiUsername"></span></p>
                                <p><strong>Wiki ID:</strong> <span id="wikiUserId"></span></p>
                            </div>
                            <hr>
                            <form id="deleteSettingForm" method="POST" action="<?=$_SERVER['SCRIPT_NAME']?>?channel=<?=$channelId?>">
                                <label for="delete_enabled">Delete join notifications and messages from restricted users in this group?</label>
                                <select name="delete_enabled" id="delete_enabled">
                                    <option value="1" <?=($group_settings[$channelId]??true)?'selected':''?>>Yes</option>
                                    <option value="0" <?=!($group_settings[$channelId]??true)?'selected':''?>>No</option>
                                </select>
                                <button type="submit">Save</button>
                            </form>
                            <script type="text/javascript">
                                $(document).ready(function () {
                                    $('#userCheckForm').on('submit', function (e) {
                                        e.preventDefault();
                                        const telegramUser = $('#telegramUser').val();
                                        $.post('', { action: 'checkUser', telegramUser: telegramUser }, function (response) {
                                            if (response.success) {
                                                $('#wikiUsername').text(response.data.wikiUsername);
                                                $('#wikiUserId').text(response.data.wikiUserId);
                                                $('#userInfo').show();
                                            } else {
                                                alert(response.message);
                                            }
                                        }, 'json');
                                    });
                                });
                            </script>
                        </div>
                    <?php endif; ?>
                    <!-- Footer -->
                    <div class="w3-container w3-margin w3-padding-12 w3-card w3-center">
                        <p>WikiVerifyBot is a tool designed to verify users from Wikimedia projects in Telegram groups, keeping spammers and impersonators out.</p>
                        <p>Hosted on <a href="https://wikitech.wikimedia.org/wiki/Toolforge">Toolforge</a> and sourced on <a href="https://github.com/albertoleoncio/wikitelegram">GitHub</a>.</p>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>
