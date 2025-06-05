<?php
// This script is designed to run as a daemon on Toolforge.
if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.");
}

require_once __DIR__ . '/WikiAphpi/main.php';

class TelegramDaemon {
    /**
     * @var string $telegramVerifyToken The token used to authenticate with the Telegram Bot API.
     */
    private $telegramVerifyToken;

    /**
     * @var string $groupsFile The path to the file containing group settings.
     * @var string $fileOffset The path to the file storing the last offset of Telegram API updates.
     */
    private $groupsFile;
    private $fileOffset;

    /**
     * This file is used to keep track of users who just got restricted in a group, but their
     * messages are still present in the group if they were fast enough to send a message
     * before being restricted. This file is used to find those users and delete their messages.
     * Their IDs are removed from the file as soon as the API confirms that the user is restricted.
     * 
     * @var string $restrictedUsersFile The path to the file containing restricted user IDs.
     */
    private $restrictedUsersFile;

    /**
     * @var bool $verbose Whether to enable verbose logging for detailed debugging.
     */
    private $verbose;

    /**
     * Load configuration from an INI file. This method reads the specified INI file
     * and returns the configuration settings as an associative array.
     *
     * @param string $file_path The path to the INI file.
     * @return array The configuration settings.
     */
    private function loadConfig($file_path) {
        $full_path = posix_getpwuid(posix_getuid())['dir'] . "/${file_path}";
        if (!file_exists($full_path)) {
            $this->logMessage("ERROR", "Configuration file ${file_path} not found.");
            exit(1);
        }
        return parse_ini_file($full_path);
    }

    /**
     * Constructor for the TelegramDaemon class. This method initializes the daemon by
     * loading configuration settings, group settings, and other necessary files.
     *
     * @param bool $verbose Whether to enable verbose logging.
     */
    public function __construct($verbose = false) {
        $this->verbose = $verbose;

        $ts_tokens = $this->loadConfig("tokens.inc");
        $this->telegramVerifyToken = $ts_tokens['TelegramVerifyToken'];

        $this->groupsFile = __DIR__ . '/groups_list.inc';
        $this->fileOffset = __DIR__ . '/telegram_offset.inc';
        $this->restrictedUsersFile = __DIR__ . '/restricted_users.inc';
        $this->logMessage("DEBUG", "Verbose mode enabled.");
    }

    /**
     * Log messages to the console with a timestamp. This method formats the log message
     * with the current timestamp and the type of message (INFO, ERROR, DEBUG, etc.).
     *
     * @param string $type The type of log message (e.g., INFO, ERROR, DEBUG).
     * @param string $message The message to log.
     */
    private function logMessage($type, $message) {
        if (!$this->verbose && $type === "DEBUG") {
            return; // Skip debug messages if verbose mode is disabled
        }
        $timestamp = date("Y-m-d H:i:s");
        echo "[$timestamp] [$type] $message\n";
    }

    /**
     * Load group settings from the groups file. This method reads the file containing
     * group IDs and their delete message settings, returning an associative array.
     *
     * @return array An associative array where keys are group IDs and values are boolean indicating if delete is enabled.
     */
    private function loadGroupSettings() {
        $this->logMessage("DEBUG", "Loading group settings from {$this->groupsFile}.");
        $groups_list = file_exists($this->groupsFile) ? file($this->groupsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
        $group_settings = [];
        foreach ($groups_list as $group_line) {
            if (strpos($group_line, ':') !== false) {
                list($group_id, $delete_enabled) = explode(':', $group_line, 2);
                $group_settings[$group_id] = filter_var($delete_enabled, FILTER_VALIDATE_BOOLEAN);
            } else {
                $group_settings[$group_line] = false; // default to false for legacy lines
            }
        }
        $this->logMessage("DEBUG", "Loaded group settings: " . json_encode($group_settings));
        return $group_settings;
    }

    /**
     * Load the last offset of the Telegram API from a file. This method reads the offset
     * from a file and returns it as an integer. If the file does not exist or contains
     * invalid data, it returns 0.
     *
     * @return int The last offset read from the file, or 0 if the file does not exist or contains invalid data.
     */
    private function loadOffset() {
        $this->logMessage("DEBUG", "Loading offset from {$this->fileOffset}.");
        $offset = file_exists($this->fileOffset) ? file($this->fileOffset) : 0;
        if (is_array($offset)) $offset = trim($offset[0]);
        $this->logMessage("DEBUG", "Loaded offset: {$offset}");
        return is_numeric($offset) ? $offset : 0;
    }

    /**
     * Load the list of restricted users from the file. This method reads the file containing
     * user IDs of restricted users and returns them as an array.
     *
     * @return array The list of restricted user IDs.
     */
    private function loadRestrictedUsers() {
        $this->logMessage("DEBUG", "Loading restricted users from {$this->restrictedUsersFile}.");
        return file_exists($this->restrictedUsersFile) ? file($this->restrictedUsersFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    }

    /**
     * Handle my_chat_member updates. This method checks the status of the bot in the chat
     * and updates the groups list accordingly.
     *
     * @param array $event The update event from Telegram.
     */
    private function handleMyChatMember($event) {
        $chat_id = $event["my_chat_member"]["chat"]["id"];
        $chat_type = $event["my_chat_member"]["chat"]["type"];
        $new_status = $event["my_chat_member"]["new_chat_member"]["status"];

        // Ignore private chats
        if ($chat_type === "private") {
            return;
        }

        $groups_list = file_exists($this->groups_file) ? file($this->groups_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

        if ($new_status === "member" || $new_status === "administrator") {
            // Add the group to the list if not already present
            if (!in_array($chat_id, $groups_list)) {
                $groups_list[] = $chat_id;
                file_put_contents($this->groups_file, implode(PHP_EOL, $groups_list) . PHP_EOL);
                $this->logMessage("INFO", "Added group ${chat_id} to groups list.");
            }
        } elseif ($new_status === "kicked" || $new_status === "left") {
            // Remove the group from the list if present
            if (in_array($chat_id, $groups_list)) {
                $groups_list = array_diff($groups_list, [$chat_id]);
                file_put_contents($this->groups_file, implode(PHP_EOL, $groups_list) . PHP_EOL);
                $this->logMessage("INFO", "Removed group ${chat_id} from groups list.");
            }
        }
    }

    /**
     * Handle messages from restricted users. This method checks if the message is from a user
     * that has been restricted in the group, and deletes the message if necessary.
     *
     * @param array $event The update event from Telegram.
     * @param array $group_settings The settings for groups.
     * @param array $restricted_users The list of restricted users.
     */
    private function handleMessage($event, $group_settings, $restricted_users) {
        $this->logMessage("DEBUG", "Handling message event: " . json_encode($event));

        $message_user_id = $event["message"]["from"]["id"];
        $message_id = $event["message"]["message_id"];
        $chat_id = $event["message"]["chat"]["id"];

        if (!isset($group_settings[$chat_id])) {
            $this->logMessage("DEBUG", "Condition failed: Group ID {$chat_id} is not in group settings.");
            return;
        }

        if ($group_settings[$chat_id] !== true) {
            $this->logMessage("DEBUG", "Condition failed: Delete messages is not enabled for group ID {$chat_id}.");
            return;
        }

        if (!in_array($message_user_id, $restricted_users)) {
            $this->logMessage("DEBUG", "Condition failed: User ID {$message_user_id} is not in the restricted users list.");
            return;
        }

        // Delete the message
        $delete_params = [
            'chat_id' => $chat_id,
            'message_id' => $message_id
        ];
        $delete_content = file_get_contents("https://api.telegram.org/bot{$this->telegramVerifyToken}/deleteMessage?" . http_build_query($delete_params));
        $delete_result = json_decode($delete_content, true);

        if (isset($delete_result["ok"])) {
            $this->logMessage("INFO", "Deleted message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
        } else {
            $this->logMessage("ERROR", "Failed to delete message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
        }
    }

    /**
     * Handle chat member updates. This method checks if a user was restricted in a chat,
     * and if so, removes them from the temporary restricted users list.
     *
     * @param array $event The update event from Telegram.
     * @param array &$restricted_users The list of restricted users.
     */
    private function handleChatMember($event, &$restricted_users) {
        $this->logMessage("DEBUG", "Handling chat member update: " . json_encode($event));

        if (!isset($event["chat_member"]["new_chat_member"])) {
            $this->logMessage("DEBUG", "Condition failed: was not a 'new_chat_member' update.");
            return;
        }

        $new_chat_member_status = $event["chat_member"]["new_chat_member"]["status"];
        if ($new_chat_member_status !== "restricted") {
            $this->logMessage("DEBUG", "Condition failed: 'new_chat_member' status is not 'restricted' (status: {$new_chat_member_status}).");
            return;
        }

        $restricted_user_id = $event["chat_member"]["new_chat_member"]["user"]["id"];
        if (!in_array($restricted_user_id, $restricted_users)) {
            $this->logMessage("DEBUG", "Condition failed: User ID {$restricted_user_id} is not in the restricted users list.");
            return;
        }

        // Remove the user from the restricted users file
        $restricted_users = array_diff($restricted_users, [$restricted_user_id]);
        file_put_contents($this->restrictedUsersFile, implode(PHP_EOL, $restricted_users) . PHP_EOL);
        $this->logMessage("INFO", "Removed user ${restricted_user_id} from restricted users list.");
    }

    /**
     * Fetch updates from the Telegram API. This method retrieves updates such as new messages,
     * chat member updates, and other events.
     *
     * @param int $offset The offset to start fetching updates from.
     * @return array|null The updates fetched from the Telegram API, or null on failure.
     */
    private function fetchUpdates($offset) {
        $this->logMessage("DEBUG", "Fetching updates with offset: {$offset} + 1.");
        $params = [
            'timeout' => 20,
            'allowed_updates' => '["chat_member","message","my_chat_member"]',
            'offset' => $offset + 1 // Increment offset to avoid fetching the same update again
        ];

        $result = null;

        try {
            $content = @file_get_contents("https://api.telegram.org/bot{$this->telegramVerifyToken}/getUpdates?" . http_build_query($params));
            
            if ($content === false) {
                $this->logMessage("ERROR", "Failed to fetch updates from Telegram API.");
                sleep(5); // Wait for 5 seconds before retrying
            } else {
                $response = json_decode($content, true);

                if (!isset($response["ok"]) || !$response["ok"]) {
                    $this->logMessage("ERROR", "Telegram API returned an error: " . json_encode($response));
                    sleep(5); // Wait for 5 seconds before retrying
                } else {
                    $result = $response["result"];
                }
            }
        } catch (Exception $e) {
            $this->logMessage("ERROR", "Exception occurred while fetching updates: " . $e->getMessage());
        }

        $this->logMessage("DEBUG", "Fetched updates: " . json_encode($result));
        return $result;
    }

    /**
     * Restrict a user in a chat. This method uses the Telegram API to restrict a user
     * from sending messages and other interactions in the specified chat.
     *
     * @param int $chat_id The ID of the chat where the user will be restricted.
     * @param int $user_id The ID of the user to restrict.
     * @param string $username The username of the user to restrict.
     */
    private function restrictUser($chat_id, $user_id, $username) {
        $params = [
            'chat_id' => $chat_id,
            'user_id' => $user_id,
            "permissions" => [
                "can_send_messages" => false,
                "can_send_audios" => false,
                "can_send_documents" => false,
                "can_send_photos" => false,
                "can_send_videos" => false,
                "can_send_video_notes" => false,
                "can_send_voice_notes" => false,
                "can_send_polls" => false,
                "can_send_other_messages" => false,
                "can_add_web_page_previews" => false,
                "can_change_info" => false,
                "can_invite_users" => false,
                "can_pin_messages" => false,
                "can_manage_topics" => false,
            ]
        ];

        $content = file_get_contents("https://api.telegram.org/bot{$this->telegramVerifyToken}/restrictChatMember?" . http_build_query($params));
        $response = json_decode($content, true);

        if (isset($response["ok"]) && $response["ok"]) {
            $this->logMessage("INFO", "Restricted ${username} (${user_id}) in chat ${chat_id}.");
            file_put_contents($this->restrictedUsersFile, $user_id . PHP_EOL, FILE_APPEND);
        } else {
            $this->logMessage("ERROR", "Failed to restrict ${username} (${user_id}) in chat ${chat_id}.");
        }
    }

    /**
     * Handle new chat members. This method checks if the new member is a bot or already verified,
     * and restricts them if they are not verified.
     *
     * @param array $event The update event from Telegram.
     */
    private function handleNewChatMember($event) {
        $this->logMessage("DEBUG", "Handling new chat member event: " . json_encode($event));
        if ($event["chat_member"]["chat"]["type"] == "private") {
            return; // Ignore unrelated chats
        }

        if ($event["chat_member"]["new_chat_member"]["user"]["is_bot"]) {
            return; // Ignore bots
        }

        if ($event["chat_member"]["new_chat_member"]["status"] != "member") {
            return; // Ignore non-members
        }

        $new_user_id = $event["chat_member"]["new_chat_member"]["user"]["id"];
        $new_user = $event["chat_member"]["new_chat_member"]["user"]["username"] ?? '';

        if ($this->queryUserDatabase($new_user_id)) {
            $this->logMessage("INFO", "User ${new_user_id} is already verified.");
            return; // User is already verified, no need to restrict
        }

        // Get user status on Telegram
        $params = [
            'chat_id' => $event["chat_member"]["chat"]["id"],
            'user_id' => $new_user_id
        ];
        $content = file_get_contents("https://api.telegram.org/bot{$this->telegramVerifyToken}/getChatMember?" . http_build_query($params));
        $status = json_decode($content, true)["result"]["status"];

        if ($status == "member") {
            $this->restrictUser($event["chat_member"]["chat"]["id"], $new_user_id, $new_user);
        }
    }

    /**
     * Query the user database to check if the user is already verified.
     *
     * @param int $user_id The Telegram user ID to check.
     * @return bool True if the user is verified, false otherwise.
     */
    private function queryUserDatabase($user_id) {
        try {
            $ts_mycnf = $this->loadConfig("replica.my.cnf");
            $con = mysqli_connect(
                'tools.db.svc.eqiad.wmflabs',
                $ts_mycnf['user'],
                $ts_mycnf['password'],
                $ts_mycnf['user'] . "__telegram"
            );
            if (!$con) {
                throw new Exception("Failed to connect to the database: " . mysqli_connect_error());
            }

            $sql_user_id = mysqli_real_escape_string($con, $user_id);
            $result = mysqli_query($con, "SELECT * FROM `verifications` WHERE `t_id` = '$sql_user_id' LIMIT 1");
            if (!$result) {
                throw new Exception("Database query failed: " . mysqli_error($con));
            }

            if (mysqli_num_rows($result) > 0) {
                $row = mysqli_fetch_assoc($result);
                $w_id = $row['w_id'];
                if ($w_id != null) {
                    $this->logMessage("INFO", "User ${user_id} already verified on wiki as ${w_id}.");
                    return true; // User is already verified
                }
            }

            $this->logMessage("INFO", "User ${user_id} is not verified.");
            return false; // User is not verified

        } catch (Exception $e) {
            $this->logMessage("ERROR", "Database error: " . $e->getMessage());
            $this->logMessage("INFO", "Retrying to connect in 15 seconds.");
            sleep(15);
            exit;
        }
    }

    /**
     * Update the offset file with the latest update ID.
     *
     * @param int $offset The latest update ID to store.
     */
    private function updateOffset($offset) {
        file_put_contents($this->fileOffset, $offset);
        $this->logMessage("DEBUG", "Updated offset to ${offset}.");
    }

    /**
     * Process updates from Telegram API. This method handles different types of updates
     * including messages, chat member updates, and new chat members.
     *
     * @param array $event The update event from Telegram.
     * @param array $group_settings The settings for groups.
     * @param array &$restricted_users The list of restricted users.
     */
    private function processUpdates($event, $group_settings, &$restricted_users) {
        $this->logMessage("DEBUG", "Processing update event: " . json_encode($event));
        // Handle my_chat_member updates
        if (isset($event["my_chat_member"])) {
            $this->handleMyChatMember($event);
        }
        
        // Check for messages from restricted users
        if (isset($event["message"])) {
            $this->handleMessage($event, $group_settings, $restricted_users);
        }

        // Handle restriction updates
        if (isset($event["chat_member"])) {
            $this->handleChatMember($event, $restricted_users);
        }

        // Handle new chat members
        if (isset($event["chat_member"]["new_chat_member"])) {
            $this->handleNewChatMember($event);
        }
    }

    public function run() {
        $this->logMessage("DEBUG", "Starting TelegramDaemon in verbose mode.");
        while (true) {
            // Reload group settings on every loop to reflect changes
            $group_settings = $this->loadGroupSettings();

            // Load last offset of the Telegram API from file
            $offset = $this->loadOffset();

            // Load the list of users that are recently restricted in order to delete their messages
            $restricted_users = $this->loadRestrictedUsers();

            // Fetch updates from Telegram API
            $updates = $this->fetchUpdates($offset);
            if ($updates === null || empty($updates)) {
                $this->logMessage("DEBUG", "No updates found or failed to fetch updates. Retrying in 1 second.");
                sleep(1); // Delay for 1 second
                continue;
            }

            // Process each update
            foreach ($updates as $event) {
                $offset = $event["update_id"];
                $this->processUpdates($event, $group_settings, $restricted_users);
            }

            // Update the offset after processing all updates
            $this->updateOffset($offset);
        }
    }
}

$verbose = in_array('--verbose', $argv);
$daemon = new TelegramDaemon($verbose);
$daemon->run();