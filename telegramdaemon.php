<?php
// This script is designed to run as a daemon on Toolforge.
if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.");
}

require_once __DIR__ . '/WikiAphpi/main.php';

class TelegramDaemon {
    private $TelegramVerifyToken;
    private $groups_file;
    private $file_offset;
    private $restricted_users_file;

    public function __construct() {
        $ts_pw = posix_getpwuid(posix_getuid());
        $ts_tokens = parse_ini_file($ts_pw['dir'] . "/tokens.inc");
        $this->TelegramVerifyToken = $ts_tokens['TelegramVerifyToken'];

        $this->groups_file = __DIR__ . '/groups_list.inc';
        $this->file_offset = __DIR__ . '/telegram_offset.inc';
        $this->restricted_users_file = __DIR__ . '/restricted_users.inc';
    }

    private function logMessage($type, $message) {
        $timestamp = date("Y-m-d H:i:s");
        echo "[$timestamp] [$type] $message\n";
    }

    private function loadGroupSettings() {
        $groups_list = file_exists($this->groups_file) ? file($this->groups_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
        $group_settings = [];
        foreach ($groups_list as $group_line) {
            if (strpos($group_line, ':') !== false) {
                list($group_id, $delete_enabled) = explode(':', $group_line, 2);
                $group_settings[$group_id] = filter_var($delete_enabled, FILTER_VALIDATE_BOOLEAN);
            } else {
                $group_settings[$group_line] = false; // default to false for legacy lines
            }
        }
        return $group_settings;
    }

    private function loadOffset() {
        $offset = file_exists($this->file_offset) ? file($this->file_offset) : 0;
        return is_numeric($offset) ? $offset : 0;
    }

    private function loadRestrictedUsers() {
        return file_exists($this->restricted_users_file) ? file($this->restricted_users_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
    }

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

    private function handleMessage($event, $group_settings, $restricted_users) {
        $message_user_id = $event["message"]["from"]["id"];
        $message_id = $event["message"]["message_id"];
        $chat_id = $event["message"]["chat"]["id"];

        // Only delete if enabled for this group
        if (isset($group_settings[$chat_id]) && $group_settings[$chat_id] === true && in_array($message_user_id, $restricted_users)) {
            // Delete the message
            $delete_params = [
                'chat_id' => $chat_id,
                'message_id' => $message_id
            ];
            $delete_content = file_get_contents("https://api.telegram.org/bot{$this->TelegramVerifyToken}/deleteMessage?" . http_build_query($delete_params));
            $delete_result = json_decode($delete_content, true);
            if (isset($delete_result["ok"])) {
                $this->logMessage("INFO", "Deleted message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
            } else {
                $this->logMessage("ERROR", "Failed to delete message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
            }
        }
    }

    private function handleChatMember($event, &$restricted_users) {
        if (isset($event["chat_member"]["new_chat_member"]) && $event["chat_member"]["new_chat_member"]["status"] == "restricted") {
            $restricted_user_id = $event["chat_member"]["new_chat_member"]["user"]["id"];
            if (in_array($restricted_user_id, $restricted_users)) {
                // Remove the user from the restricted users file
                $restricted_users = array_diff($restricted_users, [$restricted_user_id]);
                file_put_contents($this->restricted_users_file, implode(PHP_EOL, $restricted_users) . PHP_EOL);
                $this->logMessage("INFO", "Removed user ${restricted_user_id} from restricted users list.");
            }
        }
    }
    private function processUpdates($params, &$offset, $group_settings, $restricted_users) {
        try {
            $content = @file_get_contents("https://api.telegram.org/bot{$this->TelegramVerifyToken}/getUpdates?" . http_build_query($params));
            
            if ($content === false) {
                $this->logMessage("ERROR", "Failed to fetch updates from Telegram API.");
                sleep(5); // Wait for 5 seconds before retrying
                return;
            }

            $response = json_decode($content, true);

            if (!isset($response["ok"]) || !$response["ok"]) {
                $this->logMessage("ERROR", "Telegram API returned an error: " . json_encode($response));
                sleep(5); // Wait for 5 seconds before retrying
                return;
            }

            $updates = $response["result"];

            if (empty($updates)) {
                // No updates, skip output
                usleep(200000); // Delay for 0.2 seconds
                return;
            }

            foreach ($updates as $event) {
                $offset = $event["update_id"];

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
                    if ($event["chat_member"]["chat"]["type"] == "private") {
                        continue; // Ignore unrelated chats
                    }

                    if ($event["chat_member"]["new_chat_member"]["user"]["is_bot"]) {
                        continue; // Ignore bots
                    }

                    if ($event["chat_member"]["new_chat_member"]["status"] != "member") {
                        continue; // Ignore non-members
                    }

                    $new_user = $event["chat_member"]["new_chat_member"]["user"]["username"] ?? '';
                    $new_user_id = $event["chat_member"]["new_chat_member"]["user"]["id"];

                    try {

                        $ts_pw = posix_getpwuid(posix_getuid());
                        $ts_mycnf = parse_ini_file($ts_pw['dir'] . "/replica.my.cnf");
                        $con = mysqli_connect(
                            'tools.db.svc.eqiad.wmflabs',
                            $ts_mycnf['user'],
                            $ts_mycnf['password'],
                            $ts_mycnf['user']."__telegram"
                        );

                        $query = "SELECT * FROM `verifications` WHERE `t_id` = '$new_user_id'";
                        $result = mysqli_query($con, $query);
                        if (mysqli_num_rows($result) > 0) {
                            $row = mysqli_fetch_assoc($result);
                            $w_id = $row['w_id'];
                            if ($w_id != null) {
                                $this->logMessage("INFO", "User ${new_user} (${new_user_id}) already verified as ${w_id}.");
                                continue;
                            }
                        }

                    } catch (Exception $e) {
                        $this->logMessage("ERROR", "Database connection error: " . $e->getMessage());
                        $this->logMessage("INFO", "Retrying to connect in 15 seconds.");
                        sleep(15);
                        exit;
                    }

                    # Get user status on Telegram
                    $params = [
                        'chat_id' => $event["chat_member"]["chat"]["id"],
                        'user_id' => $new_user_id
                    ];
                    $content = file_get_contents("https://api.telegram.org/bot{$this->TelegramVerifyToken}/getChatMember?" . http_build_query($params));
                    $status = json_decode($content, true)["result"]["status"];

                    if ($status == "member") {
                        $params = [
                            'chat_id' => $event["chat_member"]["chat"]["id"],
                            'user_id' => $new_user_id,
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
                        $content = file_get_contents("https://api.telegram.org/bot{$this->TelegramVerifyToken}/restrictChatMember?" . http_build_query($params));
                        $content = json_decode($content, true);
                        if (isset($content["ok"])) {
                            $id = $event["chat_member"]["chat"]["id"];
                            $this->logMessage("INFO", "Restricted ${new_user} (${new_user_id}) in chat ${id}.");

                            // Add the restricted user to the file
                            file_put_contents($this->restricted_users_file, $new_user_id . PHP_EOL, FILE_APPEND);
                        } else {
                            $this->logMessage("ERROR", "Failed to restrict ${new_user} (${new_user_id}).");
                        }
                    }
                }
            }

            // Update the offset after processing all updates
            file_put_contents($this->file_offset, $offset);

        } catch (Exception $e) {
            $this->logMessage("ERROR", "Exception occurred while fetching updates: " . $e->getMessage());
            sleep(5); // Wait for 5 seconds before retrying
        }
    }

    public function run() {
        while (true) {
            // Reload group settings on every loop to reflect changes
            $group_settings = $this->loadGroupSettings();

            // Load last offset of the Telegram API from file
            $offset = $this->loadOffset();

            // Load the list of users that are recently restricted in order to delete their messages
            $restricted_users = $this->loadRestrictedUsers();

            $params = [
                'timeout' => 10,
                'allowed_updates' => '["chat_member","message","my_chat_member"]', // Include "message" and "my_chat_member" updates
                'offset' => $offset
            ];

            // Encapsulated update processing logic
            $this->processUpdates($params, $offset, $group_settings, $restricted_users);
        }
    }
}

$daemon = new TelegramDaemon();
$daemon->run();