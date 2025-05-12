# Bot usage

## What is @WikiVerifyBot?
@WikiVerifyBot is a Telegram bot designed to help manage group membership and verification for Wikimedia-related communities. It automatically restricts new members until they verify themselves, helping to prevent spam, impersonation and other issues.

## How Does It Work?
- **Restricts new members:** Every new member who joins the group will be automatically set as silent/restricted (cannot send messages or media).
- **Deletes join notifications:** The bot will delete the system message that announces a new user has joined. Some spammers use this notification to spam the group, since it links to their profile, where the spam can be found. This feature can now be enabled or disabled per group by the group admin in the web interface.
- **Unmutes on verification:** When a user completes verification, the bot will automatically unmute them, allowing them to participate in the chat.

## How to Use

### 1. Add the Bot to Your Group
- Search for `@WikiVerifyBot` on Telegram.
- Add it to your group.
- **Important:** Set the bot as an **administrator**. It needs admin rights to restrict/unrestrict users and delete join notifications.

### 2. How Users Can Verify Themselves
- Users should follow the instructions provided in the group to verify their identity.
- Verification is done via the website: [https://wikitelegram.toolforge.org/](https://wikitelegram.toolforge.org/)

### 3. Recommended: Pin a Verification Message
To help new users, pin a message in your group chat with instructions and the verification link. Example:

> **Welcome!**
> To participate in this group, you must verify your Wikimedia account.
> Please visit: https://wikitelegram.toolforge.org/
> After verification, you will be able to chat normally.

---

For questions or support, open an issue or contact the bot maintainer at https://t.me/albertoleoncio.
