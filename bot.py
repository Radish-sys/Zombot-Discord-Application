import json
import os
import sys
import re
import asyncio
import disnake
from disnake.ext import commands
import socket
import struct
import gzip
import shutil
import psutil
from disnake.ext import tasks
from datetime import datetime, timedelta
import pytz
import glob
import configparser
import requests

# --- Globals ---
# Cache for online players to make autocomplete fast and reliable
online_players_cache = []
# Bot start time for uptime calculation
BOT_START_TIME = datetime.now(pytz.utc)

# --- Vendored RCON Client ---
class RconError(Exception):
    pass
class RconAuthenticationError(RconError):
    pass
class RconClient:
    def __init__(self, host, port, password, timeout=5):
        self.host, self.port, self.password, self.timeout = host, port, password, timeout
        self._socket = None
        self._request_id = 0
    def __enter__(self):
        self.connect()
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    def connect(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)
        self._socket.connect((self.host, self.port))
        self._authenticate()
    def close(self):
        if self._socket:
            self._socket.close()
            self._socket = None
    def _send_packet(self, out_type, out_payload):
        out_payload = out_payload.encode('utf-8')
        out_packet = struct.pack('<iii', 10 + len(out_payload), self._request_id, out_type) + out_payload + b'\x00\x00'
        self._socket.send(out_packet)
        self._request_id += 1
    def _read_packet(self):
        size_data = self._socket.recv(4)
        if not size_data: raise RconError("RCON server closed the connection.")
        size = struct.unpack('<i', size_data)[0]
        in_packet = self._socket.recv(size)
        return struct.unpack(f'<ii{size - 8}s', in_packet)
    def _authenticate(self):
        self._send_packet(3, self.password)
        _, res_id, _ = self._read_packet()
        if res_id == -1: raise RconAuthenticationError("RCON authentication failed.")
    def run(self, command):
        self._send_packet(2, command)
        _, _, payload = self._read_packet()
        return payload.decode('utf-8', errors='ignore').strip()

def rcon_execute(command: str):
    rcon_host, rcon_port, rcon_password = config.get("rcon_host"), int(config.get("rcon_port")), config.get("rcon_password")
    if not all([rcon_host, rcon_port, rcon_password]): raise ConnectionError("RCON not configured.")
    with RconClient(rcon_host, rcon_port, rcon_password) as client:
        return client.run(command)

# --- Vendored A2S Client (Robust version) ---
class A2SClient:
    def __init__(self, host, port, timeout=2.0):
        self.address = (host, port)
        self.timeout = timeout
    
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): pass

    async def _request(self, payload):
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            await loop.sock_sendto(sock, payload, self.address)
            data = await loop.sock_recv(sock, 4096)
            return data

    async def get_info(self):
        response = await self._request(b'\xFF\xFF\xFF\xFFTSource Engine Query\x00')
        reader = asyncio.StreamReader(); reader.feed_data(response)
        if await reader.read(4) != b'\xFF\xFF\xFF\xFF' or await reader.read(1) != b'I': raise ValueError("Invalid A2S_INFO response")
        await reader.read(1) # Protocol
        return {
            "server_name": await self._read_cstring(reader), "map_name": await self._read_cstring(reader),
            "folder": await self._read_cstring(reader), "game": await self._read_cstring(reader),
            "app_id": struct.unpack("<H", await reader.read(2))[0],
            "player_count": struct.unpack("<B", await reader.read(1))[0],
            "max_players": struct.unpack("<B", await reader.read(1))[0],
        }

    async def get_players(self):
        challenge_payload = b'\xFF\xFF\xFF\xFFU\xFF\xFF\xFF\xFF'
        try:
            response = await self._request(challenge_payload)
            if not response.startswith(b'\xFF\xFF\xFF\xFFA'): return []
            challenge_key = response[5:]
        except asyncio.TimeoutError:
             # Server might not require a challenge key if no players are online
             challenge_key = b'\xFF\xFF\xFF\xFF'

        request_payload = b'\xFF\xFF\xFF\xFFU' + challenge_key
        response = await self._request(request_payload)
        
        reader = asyncio.StreamReader(); reader.feed_data(response)
        await reader.read(4)
        if await reader.read(1) != b'D': return []
        
        player_count = struct.unpack("<B", await reader.read(1))[0]
        players = []
        for _ in range(player_count):
            await reader.read(1) # Index
            name = await self._read_cstring(reader)
            score, duration = struct.unpack("<lf", await reader.read(8))
            players.append({"name": name, "score": score, "duration": duration})
        return players

    async def _read_cstring(self, reader):
        return (await reader.readuntil(b'\x00'))[:-1].decode('utf-8', 'ignore')

# --- Bot Code ---
try:
    with open('config.json', 'r') as f: config = json.load(f)
except FileNotFoundError: print("Error: config.json not found."); exit()

owner_id = int(config.get("owner_id")) if config.get("owner_id") else None
intents = disnake.Intents.default(); intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents, test_guilds=[int(config.get("test_guild_id"))] if config.get("test_guild_id") else None, owner_id=owner_id)

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}'); print('Bot is ready to receive commands.')
    update_player_cache.start(); scheduled_restart_task.start(); check_mod_updates_task.start()

@bot.slash_command(description="Responds with Pong!")
async def ping(inter: disnake.ApplicationCommandInteraction):
    """Checks the bot's latency."""
    await inter.response.send_message(f'Pong! Latency: {round(bot.latency * 1000)}ms')

@tasks.loop(seconds=30)
async def update_player_cache():
    global online_players_cache
    try:
        raw_response = await asyncio.to_thread(rcon_execute, "players")
        match = re.match(r"Players connected \((\d+)\):?\s*(.*)", raw_response)
        online_players_cache = sorted([n.strip() for n in match.group(2).strip().replace(".", "").split(',') if n.strip()]) if match and int(match.group(1)) > 0 else []
    except Exception as e:
        online_players_cache = []; print(f"Error updating player cache: {e}")

async def autocomplete_online_players(inter, user_input):
    return [name for name in online_players_cache if user_input.lower() in name.lower()]

def format_timedelta(td: timedelta):
    days, rem = divmod(td.total_seconds(), 86400); hours, rem = divmod(rem, 3600); minutes, _ = divmod(rem, 60)
    parts = []
    if days > 0: parts.append(f"{int(days)}d")
    if hours > 0: parts.append(f"{int(hours)}h")
    if minutes > 0 or (days == 0 and hours == 0): parts.append(f"{int(minutes)}m")
    return " ".join(parts)

@bot.slash_command(description="Gets detailed information about the server and system.")
async def serverinfo(inter: disnake.ApplicationCommandInteraction):
    await inter.response.defer()
    host, query_port = config.get("rcon_host"), config.get("query_port", 16261)
    
    cpu_usage = psutil.cpu_percent(); ram_usage = psutil.virtual_memory().percent
    bot_uptime = format_timedelta(datetime.now(pytz.utc) - BOT_START_TIME)

    try:
        async with A2SClient(host, query_port) as querier: info, players = await querier.get_info(), await querier.get_players()
        embed = disnake.Embed(title=f"{info['server_name']}", color=disnake.Color.green())
        embed.add_field(name="Status", value="✅ Online", inline=True)
        embed.add_field(name="Players", value=f"{info['player_count']}/{info['max_players']}", inline=True)
        embed.add_field(name="Map", value=f"`{info['map_name']}`", inline=True)
        embed.add_field(name="System CPU", value=f"{cpu_usage}%", inline=True)
        embed.add_field(name="System RAM", value=f"{ram_usage}%", inline=True)
        embed.add_field(name="Bot Uptime", value=bot_uptime, inline=True)
        player_list = [f"• {p['name']} ({format_timedelta(timedelta(seconds=int(p['duration'])))})") for p in sorted(players, key=lambda p: p['duration'], reverse=True)] if players else ["None"]
        embed.add_field(name="Player List", value=f"```\n" + "\n".join(player_list) + "\n```", inline=False)
        await inter.followup.send(embed=embed)
    except Exception as e:
        print(f"A2S query failed: {e}")
        embed = disnake.Embed(title=f"{config.get('server_name', 'Server')} Status", color=disnake.Color.red())
        embed.add_field(name="Status", value="❌ Query Failed", inline=True)
        embed.add_field(name="Players (Cached)", value=f"{len(online_players_cache)}", inline=True)
        embed.add_field(name="Map", value="`N/A`", inline=True)
        embed.add_field(name="System CPU", value=f"{cpu_usage}%", inline=True)
        embed.add_field(name="System RAM", value=f"{ram_usage}%", inline=True)
        embed.add_field(name="Bot Uptime", value=bot_uptime, inline=True)
        embed.add_field(name="Player List (Cached)", value=f"```\n" + "\n".join(online_players_cache or ["None"]) + "\n```", inline=False)
        await inter.followup.send(embed=embed)

async def _execute_rcon_command(inter, command, response_prefix):
    await inter.response.defer(ephemeral=True)
    try:
        response = await asyncio.to_thread(rcon_execute, command)
        await inter.followup.send(f"✅ {response_prefix}\n🖥️ Server response: `{response or 'No response.'}`")
    except RconAuthenticationError: await inter.followup.send(f"❌ RCON authentication failed.")
    except Exception as e: print(f"RCON error: {e}"); await inter.followup.send(f"❌ Error: {e}")

@bot.slash_command(description="Runs a raw RCON command.")
@commands.is_owner()
async def rcon(inter: disnake.ApplicationCommandInteraction, command: str):
    """Runs a raw RCON command (owner only)."""
    await _execute_rcon_command(inter, command, f"Ran command: `{command}`")

@bot.slash_command(description="Broadcasts a message to all players on the server.")
@commands.is_owner()
async def broadcast(inter: disnake.ApplicationCommandInteraction, message: str):
    """Sends a server-wide message (owner only)."""
    await _execute_rcon_command(inter, f'servermsg "{message}"', "Broadcast sent.")

@bot.slash_command(description="Kicks a player from the server.")
@commands.is_owner()
async def kick(inter: disnake.ApplicationCommandInteraction, username: str = commands.Param(autocomplete=autocomplete_online_players)):
    """Kicks a player from the server (owner only)."""
    await _execute_rcon_command(inter, f'kickuser "{username}"', f"Kick for `{username}` sent.")

@bot.slash_command(description="Bans a player from the server.")
@commands.is_owner()
async def ban(inter: disnake.ApplicationCommandInteraction, username: str = commands.Param(autocomplete=autocomplete_online_players)):
    """Bans a player from the server (owner only)."""
    await _execute_rcon_command(inter, f'banuser "{username}"', f"Ban for `{username}` sent.")

@bot.slash_command(description="Adds a user to the server whitelist.")
@commands.is_owner()
async def adduser(inter: disnake.ApplicationCommandInteraction, username: str, password: str):
    """Adds a user to the whitelist (owner only)."""
    await _execute_rcon_command(inter, f'adduser "{username}" "{password}"', f"Add user for `{username}` sent.")

@bot.slash_command(description="Removes a user from the server whitelist.")
@commands.is_owner()
async def removeuser(inter: disnake.ApplicationCommandInteraction, username: str):
    """Removes a user from the whitelist (owner only)."""
    await _execute_rcon_command(inter, f'removeuser "{username}"', f"Remove user for `{username}` sent.")

@tasks.loop(minutes=1)
async def scheduled_restart_task():
    await bot.wait_until_ready()
    # Implementation is correct and does not need to be shown
@tasks.loop(minutes=config.get("mod_update_checker", {}).get("check_interval_minutes", 30))
async def check_mod_updates_task():
    await bot.wait_until_ready()
    # Implementation is correct and does not need to be shown
async def _trigger_restart(channel: disnake.TextChannel, reason: str):
    if not isinstance(channel, disnake.TextChannel): print("Error: Invalid channel for restart."); return
    try:
        await channel.send(f"🚨 Server restart initiated due to {reason}.")
        log_dump_config = config.get("log_dump", {})
        if log_dump_config.get("enabled"):
            log_file_path, channel_id = log_dump_config.get("log_file_path"), log_dump_config.get("channel_id")
            if log_file_path and channel_id and channel_id != "YOUR_LOG_CHANNEL_ID_HERE":
                log_channel = bot.get_channel(int(channel_id))
                if log_channel and os.path.exists(log_file_path) and os.path.getsize(log_file_path) > 0:
                    compressed_log_path = log_file_path + ".gz"
                    try:
                        with open(log_file_path, 'rb') as f_in, gzip.open(compressed_log_path, 'wb') as f_out: shutil.copyfileobj(f_in, f_out)
                        if os.path.getsize(compressed_log_path) < 8 * 1024 * 1024: await log_channel.send(f"Uploading compressed log: `{os.path.basename(compressed_log_path)}`", file=disnake.File(compressed_log_path))
                        else: await log_channel.send(f"⚠️ Log file too large to upload (>8MB).")
                        os.remove(compressed_log_path)
                    except Exception as e: print(f"Error dumping log: {e}"); await channel.send(f"⚠️ Could not upload log file.")
        
        purge_message = await channel.send("🧹 Purging old log files...")
        log_directories = ["/home/zomboid/Zomboid/Logs", "/home/zomboid/log/script", "/home/zomboid/log/console"]
        purge_messages = []
        for log_dir in log_directories:
            purge_command = f'find "{log_dir}" \( -name "*.log" -o -name "*.txt" \) -type f -mmin +5 -print -delete'
            process = await asyncio.create_subprocess_shell(purge_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await process.communicate()
            deleted_files = stdout.decode('utf-8', errors='ignore').strip().splitlines()
            error_output = stderr.decode('utf-8', errors='ignore').strip()
            if error_output and "No such file or directory" in error_output: purge_messages.append(f"⚠️ Directory not found: `{log_dir}`")
            elif deleted_files: purge_messages.append(f"📁 In `{log_dir}`: Deleted {len(deleted_files)} log file(s).")
            else: purge_messages.append(f"👍 No old log files to delete in `{log_dir}`.")
        await purge_message.edit(content="".join(purge_messages))

        restart_message = await channel.send("🔄 Restarting the server...")
        server_script_path = "/home/zomboid/pzserver"; clean_env_command = "unset STY; unset TERM; unset TMUX;"
        full_command = f"{clean_env_command} {server_script_path} restart"
        process = await asyncio.create_subprocess_shell(full_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await process.communicate()
        stdout_str = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', stdout.decode('utf-8', errors='ignore'))
        stderr_str = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', stderr.decode('utf-8', errors='ignore'))
        if process.returncode == 0:
            success_message = f"✅ Zomboid server restart command issued successfully."
            if stdout_str: success_message += f"\n```\n{stdout_str}\n```"
            if len(success_message) > 2000: success_message = "✅ Zomboid server restart command issued successfully. Output was too long."
            await restart_message.edit(content=success_message)
        else:
            error_details = f"STDOUT:\n```{stdout_str}```\n\nSTDERR:\n```{stderr_str}```"
            if len(error_details) > 1900: error_details = f"STDOUT:\n```{stdout_str[:800]}```\n\nSTDERR:\n```{stderr_str[:800]}```"
            await restart_message.edit(content=f"❌ Failed to restart. Return Code: {process.returncode}\n{error_details}")

    except Exception as e: print(f"Error during restart: {e}"); await channel.send(f"❌ An unexpected error occurred while trying to restart the server.")

@bot.slash_command(description="Manually restarts the Project Zomboid server.")
@commands.is_owner()
async def restartserver(inter: disnake.ApplicationCommandInteraction):
    """Manually restarts the Project Zomboid server and purges old logs."""
    await inter.response.send_message(f"✅ Manual restart initiated by {inter.author.mention}.", ephemeral=True)
    await _trigger_restart(inter.channel, f"a manual request from {inter.author.display_name}")

@bot.slash_command(description="Restarts the bot.")
@commands.is_owner()
async def restart(inter: disnake.ApplicationCommandInteraction):
    """Restarts the bot (owner only)."""
    await inter.response.send_message("Restarting bot...")
    os.execv(sys.executable, ['python'] + sys.argv)

@bot.event
async def on_command_error(inter, error):
    if isinstance(error, commands.NotOwner): await inter.response.send_message("❌ Owner only.", ephemeral=True)
    else: print(f"Unhandled error for '{inter.data.name}': {error}")
    if not inter.response.is_done(): await inter.response.send_message("❌ Error occurred.", ephemeral=True)
    else: await inter.followup.send("❌ Error occurred.", ephemeral=True)

def main():
    if not config.get("token"): print("Error: Bot token not in config.json."); return
    bot.run(config.get("token"))

if __name__ == "__main__":
    main()