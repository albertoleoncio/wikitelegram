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
     * @param string $TelegramVerifyToken The verification token provided by Telegram.
     *
     * @throws ContentRetrievalException When the data is not from Telegram or is outdated.
     *
     * @return array The valid authorization data from Telegram.
     */
    public function checkTelegramAuthorization($auth_data, $TelegramVerifyToken) {
        $check_hash = $auth_data['hash'];
        unset($auth_data['hash']);
        unset($auth_data['channel']);
        ksort($auth_data);
        $data_check_string = urldecode(http_build_query($auth_data, "", "\n"));
        $secret_key = hash('sha256', $TelegramVerifyToken, true);
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
     * @param string $TelegramVerifyToken The verification token provided by Telegram.
     * @param array  $lines               The list of users from the 'verifications' table.
     * @param string $channelId           The ID of the Telegram channel.
     *
     * @return array An array of usernames of the administrators.
     */
    public function getAdmins($TelegramVerifyToken, $lines, $channelId)
    {
        $admins = [];
        $api = "https://api.telegram.org/bot" . $TelegramVerifyToken . "/getChatAdministrators?chat_id=" . $channelId;
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
     * authentication data ($authData) and the Telegram verification token ($TelegramVerifyToken)
     * as parameters. The user is unmuted in the chat with the ID "-1001169425230". The user is
     * unmuted for 100 seconds and, then, it reverts to the default group permissions.
     *
     * @param array  $authData            Authentication data containing 'id', 'auth_date', and 'username' (optional).
     * @param string $TelegramVerifyToken The verification token provided by Telegram.
     * @param string $channelId           The ID of the Telegram channel.
     *
     * @return array The response from the Telegram API as an associative array.
     */
    public function unmuteTelegramUser($authData, $TelegramVerifyToken, $channelId) {
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

        $api = "https://api.telegram.org/bot" . $TelegramVerifyToken . "/restrictChatMember";

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

}

$ts_pw = posix_getpwuid(posix_getuid());
$ts_tokens = parse_ini_file($ts_pw['dir'] . "/tokens.inc");
$verify_consumer_token = $ts_tokens['verify_consumer_token'];
$verify_secret_token = $ts_tokens['verify_secret_token'];
$TelegramVerifyToken = $ts_tokens['TelegramVerifyToken'];

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

$groups_file = __DIR__ . '/groups_list.inc';
$groups_list = file_exists($groups_file) ? file($groups_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
if (empty($groups_list)) {
    die("Error: groups_list.inc file is empty or not found.");
}
if (isset($_GET['channel']) && in_array($_GET['channel'], $groups_list)) {
    $channelId = $_GET['channel'];
} else {
    echo "<html lang='pt-BR'>
    <head>
        <title>WikiVerifyBot - Error</title>
        <meta charset='UTF-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <link rel='stylesheet' href='./w3.css'>
        <script>
            // Check if channelId exists in localStorage and append it to the URL if not present
            document.addEventListener('DOMContentLoaded', function () {
                const urlParams = new URLSearchParams(window.location.search);
                if (!urlParams.has('channel') && localStorage.getItem('channelId')) {
                    const channelId = localStorage.getItem('channelId');
                    urlParams.set('channel', channelId);
                    localStorage.removeItem('channelId');
                    window.location.search = urlParams.toString();
                }
            });
        </script>
    </head>
    <body>
        <div class='w3-container' id='menu'>
            <div class='w3-content' style='max-width:800px'>
                <h5 class='w3-center w3-padding-48'><span class='w3-tag w3-wide'>WikiVerifyBot</span></h5>
                <div class='w3-container w3-margin w3-padding-12 w3-card w3-center'>
                    <p style='color:red;'>Error: Invalid or missing channel ID.</p>
                    <form method='GET'>
                        <label for='channel'>Please provide a valid channel ID:</label>
                        <input type='text' id='channel' name='channel' required>
                        <button type='submit'>Submit</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>";
    exit;
}

// Get administrators of the chat
$admins = $verify->getAdmins($TelegramVerifyToken, $lines, $channelId);

// Check if the "auth_date" parameter from Telegram is present in the GET request.
// In this case, the user is at the second step of the verification process.
if (isset($_GET["auth_date"])) {

    // Retrieve and verify Telegram authorization data from the GET parameters.
    $authData = $verify->checkTelegramAuthorization($_GET, $TelegramVerifyToken);

    // Add a new verification entry for the authenticated user.
    $verify->newVerification($authData, $user['username']);

    // Unmute the Telegram user in the group chat, if they are not an admin.
    if (!in_array($user['username'], $admins)) {
        $verify->unmuteTelegramUser($authData, $TelegramVerifyToken, $channelId);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'checkUser' && in_array($user['username'], $admins)) {
    $telegramUser = trim($_POST['telegramUser']); // Trim whitespace

    if (!is_numeric($telegramUser)) {
        // Check the database for the username and retrieve the Telegram ID
        $stmt = $verify->mysqli->prepare("SELECT t_id FROM verifications WHERE t_username = ?");
        $stmt->bind_param('s', $telegramUser);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if ($row) {
            $telegramUser = $row['t_id']; // Use the Telegram ID from the database
        } else {
            // Handle the case where the username is not found in the database
            echo json_encode(['success' => false, 'message' => 'Username not found in the database.']);
            exit;
        }
    }

    $api = "https://api.telegram.org/bot${TelegramVerifyToken}/getChatMember?chat_id=${channelId}&user_id=${telegramUser}";
    $response = json_decode(file_get_contents($api), true);

    if (isset($response['ok']) && $response['ok'] && isset($response['result']['user'])) {
        $stmt = $verify->mysqli->prepare("SELECT w_username, w_id FROM verifications WHERE t_id = ? OR t_username = ?");
        $stmt->bind_param('is', $response['result']['user']['id'], $telegramUser);
        $stmt->execute();
        $result = $stmt->get_result();
        $userData = $result->fetch_assoc();
        $stmt->close();

        if ($userData) {
            echo json_encode(['success' => true, 'data' => ['wikiUsername' => $userData['w_username'], 'wikiUserId' => $userData['w_id']]]);
        } else {
            echo json_encode(['success' => false, 'message' => 'User not found in the database.']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'User not found in the Telegram group.']);
    }
    exit;
}

?><!DOCTYPE html>
<html lang="pt-BR">
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
        </style>
        <script>
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
                        <?php if(isset($authData)): ?>
                            <div class="stepper-wrapper">
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w" style="color: white;"></i></div>
                                    <div class="step-name">Autenticação<br>Wikipédia</div>
                                </div>
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane" style="color: white;"></i></div>
                                    <div class="step-name">Autenticação<br>Telegram</div>
                                </div>
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-solid fa-check" style="color: white;"></i></div>
                                    <div class="step-name">Concluído</div>
                                </div>
                            </div>
                            <hr>
                            <svg xmlns="http://www.w3.org/2000/svg" width="150"
                            viewBox="0 0 20 20" height="150" style="margin: auto; width: auto;">
                                <path fill="green" d="m7,14.17-4.17-4.17-1.41,1.41 5.58,5.58 12-12-1.41-1.41"></path>
                            </svg>
                            <p>Olá <?=$user['username']?>! Sua verificação deu certo e seu nome
                            foi inserido na tabela de usuários verificados. Obrigado!
                        <?php elseif($user): ?>
                            <div class="stepper-wrapper">
                                <div class="stepper-item completed">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w" style="color: white;"></i></div>
                                    <div class="step-name">Autenticação<br>Wikipédia</div>
                                </div>
                                <div class="stepper-item active">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane"></i></div>
                                    <div class="step-name">Autenticação<br>Telegram</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-solid fa-check"></i></div>
                                    <div class="step-name">Concluído</div>
                                </div>
                            </div>
                            <hr>
                            <p>Olá <?=$user['username']?>! Em seguida, autentique-se com sua
                            conta do Telegram usando o botão abaixo.</p>
                            <script
                            async src="https://telegram.org/js/telegram-widget.js?22"
                            data-auth-url="<?=$_SERVER['SCRIPT_NAME']?>?channel=<?=$channelId?>"
                            data-telegram-login="WikiVerifyBot" data-size="large"></script>
                            <p>Uma nova tela será aberta, onde você fará login via Telegram.
                            Alguns dados poderão ser solicitados pelo próprio Telegram, tal
                            como um número de telefone, mas não teremos acesso a nenhuma
                            informação sua exceto pelo seu nome e número de usuário na
                            plataforma.
                            </p>
                            <p>Caso o botão azul não esteja sendo exibido acima, tente abrir
                            essa página em um navegador diferente ou em uma aba anônima.
                            </p>
                        <?php else: ?>
                            <div class="stepper-wrapper">
                                <div class="stepper-item active">
                                    <div class="step-counter"><i class="fa-brands fa-wikipedia-w"></i></div>
                                    <div class="step-name">Autenticação<br>Wikipédia</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-regular fa-paper-plane"></i></div>
                                    <div class="step-name">Autenticação<br>Telegram</div>
                                </div>
                                <div class="stepper-item">
                                    <div class="step-counter"><i class="fa-solid fa-check"></i></div>
                                    <div class="step-name">Concluído</div>
                                </div>
                            </div>
                            <hr>
                            <p>Olá! Como primeiro passo, você precisa autenticar sua conta
                            wiki usando o botão abaixo.</p>
                            <button
                            class="w3-button w3-white w3-border"
                            onclick="saveChannelIdAndRedirect('<?=$channelId?>');"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" aria-label="Wikipedia"
                                role="img" style="width: 30px;" viewBox="0 0 512 512">
                                    <rect width="512" height="512" rx="15%" fill="#fff"/>
                                    <path d="m65 152v8c0 2 1 3 4 3 20 1 20 5 28 23l90 196c7 
                                    14 16 16 25-1l45-88 42 88c8 15 16 16 24 0l86-194c8-17 
                                    19-24 36-24 2 0 2-1 2-3v-8h-80l-1 1v7c0 2 2 3 4 3 10 0 
                                    29 2 21 19l-70 166-3-1-43-88 37-72c8-15 10-24 25-24 2 
                                    0 4-1 4-3v-7l-1-1h-64l-1 1v7c0 3 4 3 7 3 18 1 16 8 10 
                                    19l-27 56-25-52c-9-16-11-21 2-22 3-1 8-1 8-4v-7l-1-1h-69l-1 
                                    1v8c0 2 2 2 5 2 12 2 12 3 23 26l40 84-37 
                                    75-3-1-76-167c-8-17 2-16 18-17 3 0 3-1 3-3v-7l-1-1z"/>
                                </svg> 
                            <br>Login</button>
                            <p>Após se autenticar na Wiki, alguns scripts serão carregador
                            diretamente dos servidores do Telegram. Esteja ciente que, ao usar essa
                            ferramenta, seus dados de navegação podem ser armazenados em servidores
                            de terceiros sem vínculo com a WMF.
                            </p>
                        <?php endif; ?>
                    </div>
                    <?php if(isset($user['username']) && in_array($user['username'], $admins)): ?>
                        <div class="w3-container w3-margin w3-padding-48 w3-card w3-small" id="main">
                            <p style="color:red;">Painel administrativo. Se você está lendo essa mensagem,
                            você é um administrador do grupo do Telegram</p>
                            <form id="userCheckForm" method="POST" action="<?=$_SERVER['SCRIPT_NAME']?>?channel=<?=$channelId?>">
                                <label for="telegramUser">Informe o ID ou username do Telegram:</label>
                                <input type="text" id="telegramUser" name="telegramUser" required>
                                <button type="submit">Verificar</button>
                            </form>
                            <div id="userInfo" style="margin-top: 20px; display: none;">
                                <h4>Informações do Usuário:</h4>
                                <p><strong>Conta Wiki:</strong> <span id="wikiUsername"></span></p>
                                <p><strong>ID Wiki:</strong> <span id="wikiUserId"></span></p>
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