# Telegram Verification Bot

This repository contains a Telegram bot designed to handle user verification and group management. The bot integrates with the MediaWiki API and uses OAuth for authentication. It is built to run on Toolforge and provides various functionalities, including user verification, group management, and restricted user handling.

## Features

- **Telegram User Verification**: Verifies Telegram users against a MediaWiki database.
- **Group Management**: Automatically adds or removes groups based on user activity.
- **Restricted User Handling**: Restricts or unrestricts users in Telegram groups based on verification status.
- **Admin Tools**: Provides tools for administrators to manage users and groups.

## File Structure

- `index.php`: Main entry point for the bot's web interface.
- `telegramdaemon.php`: Daemon script to handle Telegram updates and manage group activities.
- `w3.css`: CSS file for styling the web interface.
- `WikiAphpi/`: Contains helper classes and functions for interacting with the MediaWiki API.
- `tokens.inc`: Configuration file containing API tokens and credentials.
- `groups_list.inc`: Stores the list of Telegram group IDs managed by the bot.
- `restricted_users.inc`: Stores the list of restricted Telegram user IDs.
- `telegram_offset.inc`: Stores the last update from Telegram stream.

## Requirements

- PHP 8.2 or higher
- Toolforge environment
- MediaWiki API credentials
- Telegram Bot API token

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/albertoleoncio/wikitelegram.git
   ```
2. Navigate to the project directory:
   ```bash
   cd wikitelegram
   ```
3. Set up the `tokens.inc` file with your API credentials:
   ```ini
   [tokens]
   verify_consumer_token = "your_consumer_token"
   verify_secret_token = "your_secret_token"
   TelegramVerifyToken = "your_telegram_bot_token"
   ```
4. Create the `groups_list.inc` with at least one group ID:
   ```ini
   -10000987654321
   ```
5. Create the `restricted_users.inc` and `telegram_offset.inc` files to store restricted users and the last update offset:
   ```bash
   touch restricted_users.inc
   touch telegram_offset.inc
   ```
6. Deploy the bot to Toolforge. The bot was not tested on other environments, but it should work with some adjustments.

## Usage

### Web Interface
- Access the web interface through the `index.php` file to manage verifications and view group information.

### Daemon Script
- Run the `telegramdaemon.php` script to handle Telegram updates and manage group activities:
  ```bash
  toolforge jobs run telegramdaemon --command "php public_html/telegramdaemon.php" --image php8.2 --continuous
  ```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- Inspired by all the spammers and bots that plague Telegram groups.
- Thanks to the MediaWiki for their API and documentation. About the Telegram API... yeah.
