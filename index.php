<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
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
        $check_hash = $auth_data['hash'];
        unset($auth_data['hash']);
        unset($auth_data['channel']);
        ksort($auth_data);
        $data_check_string = urldecode(http_build_query($auth_data, "", "\n"));
        $secret_key = hash('sha256', $telegramVerifyToken, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key);
        if (strcmp($hash, $check_hash) !== 0) {
            throw new ContentRetrievalException('Data is NOT from Telegram');
        }
        if ((time() - $auth_data['auth_date']) > 86400) {
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
     * @param array  $lines               The list of users from the 'verifications' table.
     * @param string $channelId           The ID of the Telegram channel.
     *
     * @return array An array of usernames of the administrators.
     */
    public function getAdmins($telegramVerifyToken, $lines, $channelId)
    {
        $admins = [];
        $api = "https://api.telegram.org/bot" . $telegramVerifyToken . "/getChatAdministrators?chat_id=" . $channelId;
        $response = file_get_contents($api);
        $data = json_decode($response, true);
        foreach ($data['result'] as $admin) {
            foreach ($lines as $line) {
                if ($admin['user']['id'] == $line['t_id']) {
                    $admins[] = $line['w_username'];
                }
            }
        }
        return $admins;
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
        $stmt = $this->mysqli->prepare(
            "REPLACE INTO verifications (t_id, t_date, t_username, w_username, w_id) VALUES (?, ?, ?, ?, ?)"
        );

        if (!$stmt) {
            throw new UnexpectedValueException("Error in prepare statement:".$this->mysqli->error);
        }

        $t_id = $authData['id'];
        $t_date = $authData['auth_date'];
        $t_username = $authData['username'] ?? null;

        $api_params = [
            "action"    => "query",
            "format"    => "php",
            "list"      => "users",
            "ususers"   => $wikiuser
        ];
        $api = "https://meta.wikimedia.org/w/api.php?" . http_build_query($api_params);
        $api = unserialize(file_get_contents($api));
        $w_username = $api["query"]["users"]["0"]["name"];
        $w_id = $api["query"]["users"]["0"]["userid"];

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
        $response = curl_exec($curl);
        curl_close($curl);

        return json_decode($response, true);
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
        $api = "https://api.telegram.org/bot${telegramVerifyToken}/getChatMember?chat_id=${channelId}&user_id=${telegramUser}";
        $response = json_decode(file_get_contents($api), true);

        if (isset($response['ok']) && $response['ok'] && isset($response['result']['user'])) {
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
            $result['message'] = 'User not found in the Telegram group.';
        }

        return $result;
    }

    /**
     * Retrieves channel information for the given group list.
     *
     * @param array $groups_list List of group IDs to fetch information for.
     * @param string $telegramVerifyToken Telegram bot token for API requests.
     *
     * @return array An array of channels with their ID, name, and photo (base64 encoded).
     */
    public function getChannels(array $groups_list, string $telegramVerifyToken): array
    {
        $channels = [];
        foreach ($groups_list as $groupId) {
            $api = "https://api.telegram.org/bot" . $telegramVerifyToken . "/getChat?chat_id=" . $groupId;
            $response = file_get_contents($api);
            $data = json_decode($response, true);
            if (isset($data['ok']) && $data['ok']) {
                $photoBase64 = null;
                if (isset($data['result']['photo']['small_file_id'])) {
                    $fileApi = "https://api.telegram.org/bot" . $telegramVerifyToken . "/getFile?file_id=" . $data['result']['photo']['small_file_id'];
                    $fileResponse = file_get_contents($fileApi);
                    $fileData = json_decode($fileResponse, true);
                    if (isset($fileData['ok']) && $fileData['ok']) {
                        $filePath = $fileData['result']['file_path'];
                        $fileUrl = "https://api.telegram.org/file/bot" . $telegramVerifyToken . "/" . $filePath;
                        $photoContent = file_get_contents($fileUrl);
                        $photoBase64 = base64_encode($photoContent);
                    }
                }
                $channels[] = [
                    'id' => $groupId,
                    'name' => $data['result']['title'] ?? 'Unknown',
                    'photo' => $photoBase64
                ];
            }
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
$lines = $verify->results();

// Check if the user is logged in through OAuth.
$user = $verify->checkLogin();

// Get the list of groups from the 'groups_list.inc' file.
// This file should contain a list of group IDs, one per line.
$groups_file = __DIR__ . '/groups_list.inc';
$groups_list = file_exists($groups_file) ? file($groups_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
if (empty($groups_list)) {
    die("Error: groups_list.inc file is empty or not found.");
}

// Check if a channel is selected in the GET request.
if (isset($_GET['channel']) && in_array($_GET['channel'], $groups_list)) {

    // If a channel is selected, retrieve its ID from the GET request.
    $channelId = $_GET['channel'];

    // Get administrators of the chat
    $admins = $verify->getAdmins($telegramVerifyToken, $lines, $channelId);

    // Check if the "auth_date" parameter from Telegram is present in the GET request.
    // In this case, the user is at the last step of the verification process, after Telegram authentication.
    if (isset($_GET["auth_date"])) {

        // Retrieve and verify Telegram authorization data from the GET parameters.
        $authData = $verify->checkTelegramAuthorization($_GET, $telegramVerifyToken);

        // Add a new verification entry for the authenticated user.
        $verify->newVerification($authData, $user['username']);

        // Unmute the Telegram user in the group chat, if they are not an admin.
        if (!in_array($user['username'], $admins)) {
            $verify->unmuteTelegramUser($authData, $telegramVerifyToken, $channelId);
        }
    }
} else {

    // If no channel is selected, retrieve the list of channels from the Telegram API.
    $channels = $verify->getChannels($groups_list, $telegramVerifyToken);

    // Check if the channels array is empty.
    // If it is empty, display an error message and exit.
    if (empty($channels)) {
        die("Error: Unable to retrieve channel information.");
    }
}

// Small API to check an user in the group with a wiki username
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'checkUser' && in_array($user['username'], $admins)) {
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
                padding: 10px;
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
        <div class="w3-container" id="menu">
            <div class="w3-content" style="max-width:800px">
                <h5 class="w3-center w3-padding-48"><span class="w3-tag w3-wide">WikiVerifyBot</span></h5>
                <div class="w3-row-padding w3-center w3-padding-8 w3-margin-top">
                    <div class="w3-container w3-margin w3-padding-12 w3-card w3-center">
                        <?php if(isset($channels) && !empty($channels)): ?>
                            <!-- Step 0: Channel Selection -->
                            <div class='loader' id='loader'></div>
                            <div id='menu'>
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
                                                            <img src='data:image/jpeg;base64,<?php echo $channel['photo']; ?>' alt='Channel' style='width: 20px; height: 20px; vertical-align: middle; margin-right: 5px;'>
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
                    <?php if(isset($user['username']) && in_array($user['username'], $admins)): ?>
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
                </div>
            </div>
        </div>
    </body>
</html>
