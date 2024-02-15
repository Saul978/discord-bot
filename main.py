import discord, os, re, requests
import vt, asyncio

from discord.message import Message

intents = discord.Intents.default()
client = discord.Client(intents=intents)
intents.members = True
intents.message_content = True
intents.messages = True



@client.event
async def on_ready():
  print('We have logged in as {0.user}'.format(client))


@client.event
async def on_message(message):
  if message.author == client.user:
    return

  regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

  url = re.findall(regex, message.content.lower())

  headers = {
      "accept": "application/json",
      "content-type": "application/x-www-form-urlencoded",
      "x-apikey": os.environ['apivt']
  }

  if url:
    responses = []
    for i in url:
      response = requests.post('https://www.virustotal.com/api/v3/urls',
                               headers=headers,
                               data={'url': i[0]})
      if response.status_code == 200:
        responses.append(response.json())

    if len(responses) > 0:
      for i in responses:
        response = requests.get('https://www.virustotal.com/api/v3/analyses/' +
                                i.get('data').get('id'),
                                headers=headers)
        stats = response.json().get('data').get('attributes').get('stats')
        if stats.get('malicious') > 0 or stats.get('suspicious') > 2:

          await message.reply(
              'Surmano este link ' +
              str(response.json().get('meta').get('url_info').get('url')) +
              ' esta malito\n' + ' malicioso: ' + str(stats.get('malicious')) +
              '\n' + ' sospechoso: ' + str(stats.get('suspicious')))


try:
  client.run(os.environ['TOKEN'])
except Exception as e:
  raise e
