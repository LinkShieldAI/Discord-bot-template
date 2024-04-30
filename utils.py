import asyncio
import json
import os
import re
import time

import aiohttp

url_pattern = re.compile(r'(?P<url>https?://[^\s]+[-a-zA-Z0-9@:%_+~#?&/=]+)')


# TODO add headers for requests from your bot


async def get_final_url(shortened_url):
    start_time = time.time()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.head(shortened_url, allow_redirects=True) as response:
                final_url = str(response.url)
                end_time = time.time()
                duration = end_time - start_time
                return final_url, duration
    except aiohttp.ClientError as e:
        print("Error occurred:", e)
        end_time = time.time()
        duration = end_time - start_time
        return shortened_url, duration


async def extract_links(text):
    links = url_pattern.findall(text)
    return links


async def truncate_url(url, max_length=30):
    if len(url) > max_length:
        return url[:max_length - 3] + "..."
    else:
        return url


async def read_config(server_id):
    config_file = f"server_configs/{server_id}.json"
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            return json.load(f)
    else:
        return {}


async def write_config(server_id, config):
    config_file = f"server_configs/{server_id}.json"
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
    except FileNotFoundError:
        print(f"Error: File '{config_file}' not found.")
    except PermissionError:
        print(f"Error: Permission denied to write to '{config_file}'.")
    except Exception as e:
        print(f"Error: An unexpected error occurred: {e}")


async def check_mal(url, API_key):
    API_ENDPOINT = f'https://api.linkshieldai.com/?key={API_key}&url={url}'

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(API_ENDPOINT, timeout=35) as response:
                if response.status == 200:
                    data = await response.json()

                    result = data.get('result', "Failed to connect to the site.")

                    if result == "Might be malicious":
                        return True
                    else:
                        return False
        except asyncio.TimeoutError:
            print("Couldn't connect to the API.")
