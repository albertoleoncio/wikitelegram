<?php
require_once __DIR__ . '/bin/globals.php';
require_once __DIR__ . '/WikiAphpi/main.php';

function logMessage($type, $message) {
    $timestamp = date("Y-m-d H:i:s");
    echo "[$timestamp] [$type] $message\n";
}

while (true) {
    $offset = file_get_contents(__DIR__ . '/telegram_offset.inc');
    if (!is_numeric($offset)) {
        $offset = 0;
    }

    // Load restricted users from the file
    $restricted_users_file = __DIR__ . '/restricted_users.inc';
    $restricted_users = file_exists($restricted_users_file) ? file($restricted_users_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

    $params = [
        'timeout' => 10,
        'allowed_updates' => '["chat_member","message"]', // Include "message" updates
        'offset' => $offset
    ];

    try {
        $content = file_get_contents("https://api.telegram.org/bot${TelegramVerifyToken}/getUpdates?" . http_build_query($params));
        
        if ($content === false) {
            logMessage("ERROR", "Failed to fetch updates from Telegram API.");
            sleep(5); // Wait for 5 seconds before retrying
            continue;
        }

        $response = json_decode($content, true);

        if (!isset($response["ok"]) || !$response["ok"]) {
            logMessage("ERROR", "Telegram API returned an error: " . $response);
            sleep(5); // Wait for 5 seconds before retrying
            continue;
        }

        $update = $response["result"];

    } catch (Exception $e) {
        logMessage("ERROR", "Exception occurred while fetching updates: " . $e->getMessage());
        sleep(5); // Wait for 5 seconds before retrying
        continue;
    }

    if (empty($update)) {
        // No updates, skip output
        usleep(200000); // Delay for 0.2 seconds
        continue;
    }

    foreach ($update as $event) {
        $offset = $event["update_id"];
        
        // Check for messages from restricted users
        if (isset($event["message"])) {
            $message_user_id = $event["message"]["from"]["id"];
            $message_id = $event["message"]["message_id"];
            $chat_id = $event["message"]["chat"]["id"];

            if (in_array($message_user_id, $restricted_users)) {
                // Delete the message
                $delete_params = [
                    'chat_id' => $chat_id,
                    'message_id' => $message_id
                ];
                $delete_content = file_get_contents("https://api.telegram.org/bot${TelegramVerifyToken}/deleteMessage?" . http_build_query($delete_params));
                $delete_result = json_decode($delete_content, true);
                if (isset($delete_result["ok"])) {
                    logMessage("INFO", "Deleted message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
                } else {
                    logMessage("ERROR", "Failed to delete message ${message_id} from restricted user ${message_user_id} in chat ${chat_id}.");
                }
            }
        }

        // Handle restriction updates
        if (isset($event["chat_member"]["new_chat_member"])) {
            if ($event["chat_member"]["new_chat_member"]["status"] == "restricted") {
                $restricted_user_id = $event["chat_member"]["new_chat_member"]["user"]["id"];
                if (in_array($restricted_user_id, $restricted_users)) {
                    // Remove the user from the restricted users file
                    $restricted_users = array_diff($restricted_users, [$restricted_user_id]);
                    file_put_contents($restricted_users_file, implode(PHP_EOL, $restricted_users) . PHP_EOL);
                    logMessage("INFO", "Removed user ${restricted_user_id} from restricted users list.");
                }
            }
        }

        // Handle new chat members
        if (isset($event["chat_member"]["new_chat_member"])) {
            if ($event["chat_member"]["chat"]["id"] != "-1001169425230") {
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
                        logMessage("INFO", "User ${new_user} (${new_user_id}) already verified as ${w_id}.");
                        continue;
                    }
                } else {
                    $query = "INSERT IGNORE INTO `verifications` (`t_id`, `t_username`) VALUES ('$new_user_id', '$new_user')";
                    mysqli_query($con, $query);
                    mysqli_close($con);
                    logMessage("INFO", "User ${new_user} (${new_user_id}) added to database.");
                }

            } catch (Exception $e) {
                logMessage("ERROR", "Database connection error: " . $e->getMessage());
                logMessage("INFO", "Retrying to connect in 15 seconds.");
                sleep(15);
                exit;
            }

            # Get user status on Telegram
            $params = [
                'chat_id' => $event["chat_member"]["chat"]["id"],
                'user_id' => $new_user_id
            ];
            $content = file_get_contents("https://api.telegram.org/bot${TelegramVerifyToken}/getChatMember?" . http_build_query($params));
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
                $content = file_get_contents("https://api.telegram.org/bot${TelegramVerifyToken}/restrictChatMember?" . http_build_query($params));
                $content = json_decode($content, true);
                if (isset($content["ok"])) {
                    $id = $content["result"]["user"]["id"];
                    logMessage("INFO", "Restricted ${new_user} (${new_user_id}) in chat ${id}.");

                    // Add the restricted user to the file
                    file_put_contents($restricted_users_file, $new_user_id . PHP_EOL, FILE_APPEND);
                } else {
                    logMessage("ERROR", "Failed to restrict ${new_user} (${new_user_id}).");
                }
            }
        }

        // Update the offset after processing all updates
        file_put_contents(__DIR__ . "/telegram_offset.inc", $offset);
    }

    // Delay for a fifth of a second
    usleep(200000); // 200,000 microseconds = 0.2 seconds
}

// toolforge jobs run telegramdaemon --command "php public_html/telegramdaemon.php" --image php8.2 --continuous