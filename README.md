# Zombot - A Project Zomboid Discord Bot

Zombot is a Python-based Discord bot for managing a Project Zomboid dedicated server. It provides a set of slash commands to monitor and administer your server directly from Discord.

## Features

- **Detailed Server Info:** A `/serverinfo` command that shows live server status, map, player count, a detailed player list with session times, and system resource usage (CPU/RAM).
- **RCON Commands:** Full administrative control via slash commands:
    - `/rcon <command>`: Execute any raw RCON command.
    - `/broadcast <message>`: Send a server-wide message.
    - `/kick <user>`: Kick a player from the server.
    - `/ban <user>`: Ban a player from the server.
    - `/adduser <user> <pwd>`: Add a user to the server's whitelist.
    - `/removeuser <user>`: Remove a user from the whitelist.
- **Automated Restarts:**
    - **Scheduled:** Restart the server at configured times (e.g., daily).
    - **Mod Updates:** Automatically checks for Steam Workshop mod updates and restarts the server to apply them.
- **Log Management:**
    - **Log Dumping:** Automatically uploads a compressed archive of the console log to a specified channel upon every restart.
    - **Log Purging:** Cleans up old `.log` and `.txt` files from log directories during the restart process.
- **Self-Contained:** The bot uses a built-in RCON and A2S client, removing dependencies on external libraries that may have installation issues.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd zombot_py_public
    ```

2.  **Create a Python virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the bot:**
    -   Make a copy of `config.template.json` and name it `config.json`.
    -   Open `config.json` and fill in all the required values, especially:
        -   `token`: Your Discord bot token.
        -   `rcon_password`: Your server's RCON password.
        -   `owner_id`: Your Discord user ID to get access to owner-only commands.
        -   `steam_web_api_key`: Your Steam Web API key (for the mod update checker).
        -   All `channel_id` fields.

5.  **Run the bot:**
    ```bash
    python bot.py
    ```
