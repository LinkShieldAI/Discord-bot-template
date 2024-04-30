from urllib.parse import urlparse

import discord
from discord.ext import commands

from utils import *

bot = commands.AutoShardedBot(intents=discord.Intents.all())

API_key = ''

TOKEN = ''

owner_id = int()


@bot.event
async def on_ready():
    print("=================================")
    print(f"{bot.user.name} is online!")
    print("=================================")


@bot.slash_command(name="results_guide")
@commands.guild_only()
async def results_guide(self, ctx):
    embed = discord.Embed(
        title="Understanding Scan Results",
        description="This command helps you interpret the results of URL scans.",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="🔍 Tag Found + Result = Might be Malicious",
        value="The URL is likely malicious.",
        inline=False
    )
    embed.add_field(
        name="🔍 Tag Found + Result = Phishing Attempt",
        value="The URL wasn't found in our database, but it might be malicious if a tag was detected.",
        inline=False
    )
    embed.add_field(
        name="❌ No Tags Found + Result = Might be Malicious",
        value="The URL is in the database, but it couldn't detect the brand.",
        inline=False
    )
    embed.add_field(
        name="✅ No Tags Found + Result = Likely Safe",
        value="The URL is in the database and is likely safe.",
        inline=False
    )
    embed.set_thumbnail(url=self.bot.user.avatar)
    await ctx.respond(embed=embed, ephemeral=True)


@bot.slash_command(name='scan')
@commands.guild_only()
async def scan(ctx, url):
    await ctx.defer()

    parsed_url = urlparse(url)

    if not parsed_url.netloc or not parsed_url.scheme:
        embed = discord.Embed(
            title="Invalid URL",
            description="Please provide a valid URL",
            color=discord.Color.red(),
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed)
    else:
        link = url
        API_ENDPOINT = f'https://api.linkshieldai.com/classify_link?key={API_key}&url={link}'

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(API_ENDPOINT, timeout=35) as response:
                    if response.status == 200:
                        data = await response.json()

                        # Extract information from the JSON response
                        screenshot_url = data.get('screenshot url',
                                                  'https://api.linkshieldai.com/screenshot/placeholder.png')
                        tag = data.get('tag', "No tags found")
                        result = data.get('result', "Failed to connect to the site.")
                        error = data.get("Error", None)

                        if error:
                            embed = discord.Embed(
                                title="Error",
                                description=f"Error: {error}, don't try again",
                                color=discord.Color.red()
                            )
                            await ctx.respond(embed=embed, ephemeral=True)
                            return

                        if result != "Might be malicious" and tag != "No tags found":
                            embed_color = discord.Color.red()
                        elif result == "Might be malicious":
                            embed_color = discord.Color.red()
                        elif result == "Likely safe":
                            embed_color = discord.Color.green()
                        else:
                            embed_color = discord.Color.darker_grey()

                        truncated_url = await truncate_url(url)
                        # Create Discord embed
                        embed = discord.Embed(
                            title="URL check!",
                            description=f"```{truncated_url}```",
                            color=embed_color
                        )

                        # Add the information to the embed
                        embed.set_image(url=screenshot_url)
                        embed.add_field(name="Tag", value=f"```{tag}```", inline=True)
                        embed.add_field(name="Result", value=f"```{result}```", inline=False)

                        # Print data for debugging
                        print(data)

                        await ctx.respond(embed=embed)  # Sending the embed here

                    else:
                        print(f"Error: {response.status}")
                        embed = discord.Embed(
                            title="Error",
                            description=f"Error code: {response.status}, don't try again",
                            color=discord.Color.red()
                        )
                        await ctx.respond(embed=embed, ephemeral=True)
                        return
            except asyncio.TimeoutError:
                embed = discord.Embed(
                    title="Error",
                    description="Timeout occurred while trying to fetch URL do NOT try again.",
                    color=discord.Color.red()
                )
                await ctx.respond(embed=embed, ephemeral=True)


@bot.slash_command(name="set_logs")
@commands.has_guild_permissions(manage_channels=True, manage_guild=True)
@commands.guild_only()
async def set_logs(ctx, channel: discord.TextChannel):
    # Retrieve server ID
    server_id = ctx.guild.id

    # Update configuration
    config = await read_config(server_id)
    config["logging_channel_id"] = channel.id
    await write_config(server_id, config)

    # Send an ephemeral response
    await ctx.respond(f"Logging channel set to {channel.mention}", ephemeral=True)


@bot.event
async def on_message_edit(before, message):
    if before.author.bot:
        return

    links = await extract_links(message.content)
    if links:
        for link in links:
            resolved_link, duration = await get_final_url(link)
            if await check_mal(resolved_link, API_key):
                try:
                    embed = discord.Embed(
                        title='Malicious Link Detected!',
                        description='A malicious link was detected and removed from the chat.',
                        color=discord.Color.red()
                    )
                    embed.set_author(name=bot.user.name, icon_url=bot.user.avatar)
                    embed.add_field(name="Author", value=f"{message.author.mention} (ID: {message.author.id})",
                                    inline=False)
                    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
                    embed.add_field(name="Time:",
                                    value=f"<t:{int(message.created_at.timestamp())}:R> | <t:{int(message.created_at.timestamp())}:d>")

                    await message.channel.send(embed=embed)
                    await message.delete()
                    server_id = message.guild.id
                    config = await read_config(server_id)
                    logging_channel_id = config.get("logging_channel_id")
                    if logging_channel_id:
                        logging_channel = bot.get_channel(logging_channel_id)
                        if logging_channel:
                            await logging_channel.send(embed=embed)
                except Exception as e:
                    print(f"Error deleting message: {e}")


@bot.event
async def on_message(message):
    if message.author.bot:
        return

    links = await extract_links(message.content)
    if links:
        for link in links:
            resolved_link, duration = await get_final_url(link)
            if await check_mal(resolved_link, API_key):
                try:
                    embed = discord.Embed(
                        title='Malicious Link Detected!',
                        description='A malicious link was detected and removed from the chat.',
                        color=discord.Color.red()
                    )
                    embed.set_author(name=bot.user.name, icon_url=bot.user.avatar)
                    embed.add_field(name="Author", value=f"{message.author.mention} (ID: {message.author.id})",
                                    inline=False)
                    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
                    embed.add_field(name="Time:",
                                    value=f"<t:{int(message.created_at.timestamp())}:R> | <t:{int(message.created_at.timestamp())}:d>")

                    await message.channel.send(embed=embed)
                    await message.delete()

                    server_id = message.guild.id
                    config = await read_config(server_id)
                    logging_channel_id = config.get("logging_channel_id")
                    if logging_channel_id:
                        logging_channel = bot.get_channel(logging_channel_id)
                        if logging_channel:
                            await logging_channel.send(embed=embed)
                except Exception as e:
                    print(f"Error deleting message: {e}")


@bot.event
async def on_guild_join(guild):
    try:
        owner = await bot.fetch_user(owner_id)
        message = f"I just joined the server {guild.name} ({guild.id})"
        await owner.send(message)
    except Exception as e:
        print(f"Unable to send DM to the bot owner. {e}")


@bot.event
async def on_application_command_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        embed = discord.Embed(
            title="Command on Cooldown",
            description=f"You are on cooldown. Try again in {error.retry_after:.2f}s.",
            color=discord.Color.red()
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed, ephemeral=True)
    elif isinstance(error, commands.NoPrivateMessage):
        embed = discord.Embed(
            title="Error",
            description="This command can only be used in a server.",
            color=discord.Color.red()
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed, ephemeral=True)
    elif isinstance(error, commands.MissingPermissions):
        embed = discord.Embed(
            title="Error",
            description="You don't have permission to use this command.",
            color=discord.Color.red()
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed, ephemeral=True)
    elif isinstance(error, commands.NotOwner):
        embed = discord.Embed(
            title="Error",
            description="This command can only be used by the bot owner.",
            color=discord.Color.red()
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed, ephemeral=True)
    elif isinstance(error, commands.CheckFailure):
        pass
    else:
        embed = discord.Embed(
            title="Error",
            description="An error occurred while running the command. Please try again later.",
            color=discord.Color.red()
        )
        embed.set_thumbnail(url=bot.user.avatar)
        await ctx.respond(embed=embed, ephemeral=True)
        raise error


bot.run(TOKEN)
