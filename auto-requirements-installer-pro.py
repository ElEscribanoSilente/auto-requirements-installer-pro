#!/usr/bin/env python3
"""
Auto Requirements Installer Pro v2.0
=====================================
Herramienta avanzada para gestión automática de dependencias Python.

Características:
- Escaneo profundo de imports con AST
- Detección completa de stdlib (3.8-3.12+)
- Mapeo extensivo import→PyPI (~250+ paquetes)
- Gestión de entornos virtuales
- Múltiples formatos de exportación
- Verificación de seguridad (vulnerabilidades)
- Tema oscuro/claro
- Caché de paquetes
- Historial de operaciones
- Análisis de dependencias transitivas

Autor: Esraderey
Versión: 2.0.0
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os
import ast
import subprocess
import sys
import threading
import json
from pathlib import Path
import re
from typing import Set, List, Dict, Optional, Tuple, Any
import importlib.util
import venv
import platform
import configparser
import hashlib
import sqlite3
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error
from collections import defaultdict
import traceback


# ==============================================================================
# CONSTANTES Y CONFIGURACIÓN
# ==============================================================================

APP_NAME = "Auto Requirements Installer Pro"
APP_VERSION = "2.0.0"
CONFIG_DIR = Path.home() / ".requirements_installer_pro"
CACHE_FILE = CONFIG_DIR / "package_cache.json"
HISTORY_FILE = CONFIG_DIR / "history.db"
SETTINGS_FILE = CONFIG_DIR / "settings.json"

# Tiempo de expiración del caché en segundos (24 horas)
CACHE_EXPIRY = 86400


class PackageStatus(Enum):
    """Estado de un paquete"""
    STDLIB = auto()
    INSTALLED = auto()
    MISSING = auto()
    UNKNOWN = auto()
    ERROR = auto()


@dataclass
class PackageInfo:
    """Información de un paquete"""
    import_name: str
    pypi_name: str
    status: PackageStatus
    version: Optional[str] = None
    latest_version: Optional[str] = None
    description: Optional[str] = None
    is_vulnerable: bool = False
    vulnerabilities: List[str] = field(default_factory=list)


# ==============================================================================
# STDLIB MODULES - Lista completa para Python 3.8-3.12+
# ==============================================================================

def get_stdlib_modules() -> Set[str]:
    """Obtiene la lista completa de módulos de la biblioteca estándar"""
    # Para Python 3.10+, usar sys.stdlib_module_names
    if hasattr(sys, 'stdlib_module_names'):
        return set(sys.stdlib_module_names)
    
    # Para versiones anteriores, lista manual completa
    return {
        # Servicios del sistema
        'sys', 'os', 'io', 'time', 'argparse', 'getopt', 'logging',
        'getpass', 'curses', 'platform', 'errno', 'ctypes', 'msvcrt',
        'winreg', 'winsound', 'posix', 'pwd', 'grp', 'termios', 'tty',
        'pty', 'fcntl', 'resource', 'syslog', 'select', 'selectors',
        'signal', 'mmap', 'readline', 'rlcompleter',
        
        # Tipos de datos
        'datetime', 'zoneinfo', 'calendar', 'collections', 'heapq',
        'bisect', 'array', 'weakref', 'types', 'copy', 'pprint',
        'reprlib', 'enum', 'graphlib',
        
        # Numéricos y matemáticos
        'numbers', 'math', 'cmath', 'decimal', 'fractions', 'random',
        'statistics',
        
        # Programación funcional
        'itertools', 'functools', 'operator',
        
        # Acceso a archivos y directorios
        'pathlib', 'fileinput', 'stat', 'filecmp', 'tempfile', 'glob',
        'fnmatch', 'linecache', 'shutil',
        
        # Persistencia de datos
        'pickle', 'copyreg', 'shelve', 'marshal', 'dbm', 'sqlite3',
        
        # Compresión y archivado
        'zlib', 'gzip', 'bz2', 'lzma', 'zipfile', 'tarfile',
        
        # Formatos de archivo
        'csv', 'configparser', 'tomllib', 'netrc', 'plistlib',
        
        # Criptografía
        'hashlib', 'hmac', 'secrets',
        
        # Servicios genéricos del SO
        'subprocess', 'sched', 'queue', 'contextvars',
        
        # Concurrencia
        'threading', 'multiprocessing', 'concurrent', 'asyncio',
        '_thread',
        
        # Redes
        'socket', 'ssl', 'asyncore', 'asynchat',
        
        # Internet
        'email', 'json', 'mailbox', 'mimetypes', 'base64', 'binascii',
        'quopri', 'uu',
        
        # Protocolos de Internet
        'webbrowser', 'wsgiref', 'urllib', 'http', 'ftplib', 'poplib',
        'imaplib', 'smtplib', 'uuid', 'socketserver', 'xmlrpc', 'ipaddress',
        
        # Multimedia
        'wave', 'colorsys', 'chunk', 'sndhdr', 'ossaudiodev', 'aifc',
        'sunau',
        
        # Internacionalización
        'gettext', 'locale',
        
        # Frameworks de programación
        'turtle', 'cmd', 'shlex',
        
        # GUI
        'tkinter', 'tkinter.ttk', 'tkinter.scrolledtext',
        
        # Herramientas de desarrollo
        'typing', 'pydoc', 'doctest', 'unittest', 'test', '2to3', 'lib2to3',
        'venv',
        
        # Depuración y perfilado
        'bdb', 'faulthandler', 'pdb', 'profile', 'pstats', 'timeit',
        'trace', 'tracemalloc', 'cProfile',
        
        # Empaquetado y distribución
        'ensurepip', 'zipapp', 'pkgutil', 'modulefinder', 'runpy',
        'importlib', 'zipimport',
        
        # Runtime de Python
        'builtins', 'warnings', 'dataclasses', 'contextlib', 'abc',
        'atexit', 'traceback', 'gc', '__future__', 'inspect', 'site',
        'sysconfig',
        
        # Parsers
        'html', 'xml', 'ast', 'symtable', 'token', 'keyword', 'tokenize',
        'tabnanny', 'pyclbr', 'py_compile', 'compileall', 'dis', 'pickletools',
        
        # Cosas varias
        're', 'difflib', 'textwrap', 'unicodedata', 'stringprep', 'codecs',
        'struct', 'string', 'code', 'codeop',
        
        # Módulos obsoletos pero aún presentes
        'optparse', 'imp', 'formatter', 'parser', 'symbol', 'distutils',
        'cgi', 'cgitb', 'imghdr', 'mailcap', 'nntplib', 'pipes', 'spwd',
        'telnetlib', 'xdrlib',
        
        # Módulos internos comunes
        '_collections_abc', '_io', '_warnings', '_weakref', '_thread',
        '_locale', '_operator', '_sre', '_codecs', '_functools',
        '_abc', '_bisect', '_blake2', '_bz2', '_codecs_cn', '_codecs_hk',
        '_codecs_iso2022', '_codecs_jp', '_codecs_kr', '_codecs_tw',
        '_collections', '_contextvars', '_csv', '_ctypes', '_datetime',
        '_decimal', '_elementtree', '_hashlib', '_heapq', '_json', '_lsprof',
        '_lzma', '_md5', '_multibytecodec', '_multiprocessing', '_opcode',
        '_operator', '_osx_support', '_pickle', '_posixshmem', '_posixsubprocess',
        '_queue', '_random', '_sha1', '_sha256', '_sha3', '_sha512', '_signal',
        '_socket', '_sqlite3', '_ssl', '_stat', '_statistics', '_string',
        '_strptime', '_struct', '_symtable', '_thread', '_tracemalloc',
        '_uuid', '_warnings', '_weakref', '_winapi', '_xxsubinterpreters',
        '_zoneinfo',
    }


# ==============================================================================
# MAPEO IMPORT → PYPI (Extensivo)
# ==============================================================================

def get_import_to_pypi_mapping() -> Dict[str, str]:
    """Retorna un mapeo extensivo de nombres de import a paquetes PyPI"""
    return {
        # Computer Vision
        'cv2': 'opencv-python',
        'cv': 'opencv-python',
        'skimage': 'scikit-image',
        'imageio': 'imageio',
        'imutils': 'imutils',
        
        # Machine Learning / AI
        'sklearn': 'scikit-learn',
        'tensorflow': 'tensorflow',
        'tf': 'tensorflow',
        'keras': 'keras',
        'torch': 'torch',
        'torchvision': 'torchvision',
        'torchaudio': 'torchaudio',
        'transformers': 'transformers',
        'xgboost': 'xgboost',
        'lightgbm': 'lightgbm',
        'catboost': 'catboost',
        'onnx': 'onnx',
        'onnxruntime': 'onnxruntime',
        'paddlepaddle': 'paddlepaddle',
        'mxnet': 'mxnet',
        'jax': 'jax',
        'flax': 'flax',
        'optuna': 'optuna',
        'ray': 'ray',
        'mlflow': 'mlflow',
        'wandb': 'wandb',
        'tensorboard': 'tensorboard',
        'huggingface_hub': 'huggingface-hub',
        
        # Data Science
        'numpy': 'numpy',
        'np': 'numpy',
        'pandas': 'pandas',
        'pd': 'pandas',
        'scipy': 'scipy',
        'statsmodels': 'statsmodels',
        'sympy': 'sympy',
        
        # Visualización
        'matplotlib': 'matplotlib',
        'plt': 'matplotlib',
        'seaborn': 'seaborn',
        'sns': 'seaborn',
        'plotly': 'plotly',
        'bokeh': 'bokeh',
        'altair': 'altair',
        'pygal': 'pygal',
        'holoviews': 'holoviews',
        'dash': 'dash',
        'streamlit': 'streamlit',
        'gradio': 'gradio',
        'panel': 'panel',
        
        # Imagen
        'PIL': 'Pillow',
        'pillow': 'Pillow',
        'wand': 'Wand',
        'cairo': 'pycairo',
        
        # Web Scraping
        'bs4': 'beautifulsoup4',
        'BeautifulSoup': 'beautifulsoup4',
        'scrapy': 'scrapy',
        'selenium': 'selenium',
        'playwright': 'playwright',
        'pyppeteer': 'pyppeteer',
        'requests_html': 'requests-html',
        'mechanize': 'mechanize',
        'lxml': 'lxml',
        'html5lib': 'html5lib',
        'parsel': 'parsel',
        'httpx': 'httpx',
        
        # HTTP / API
        'requests': 'requests',
        'aiohttp': 'aiohttp',
        'urllib3': 'urllib3',
        'httplib2': 'httplib2',
        'treq': 'treq',
        'grequests': 'grequests',
        
        # Web Frameworks
        'flask': 'Flask',
        'django': 'Django',
        'fastapi': 'fastapi',
        'starlette': 'starlette',
        'tornado': 'tornado',
        'bottle': 'bottle',
        'cherrypy': 'CherryPy',
        'falcon': 'falcon',
        'hug': 'hug',
        'pyramid': 'pyramid',
        'sanic': 'sanic',
        'aiofiles': 'aiofiles',
        'uvicorn': 'uvicorn',
        'gunicorn': 'gunicorn',
        'hypercorn': 'hypercorn',
        'daphne': 'daphne',
        'werkzeug': 'Werkzeug',
        'jinja2': 'Jinja2',
        'wtforms': 'WTForms',
        'flask_sqlalchemy': 'Flask-SQLAlchemy',
        'flask_login': 'Flask-Login',
        'flask_cors': 'Flask-CORS',
        'flask_restful': 'Flask-RESTful',
        'django_rest_framework': 'djangorestframework',
        'rest_framework': 'djangorestframework',
        'graphene': 'graphene',
        'ariadne': 'ariadne',
        'strawberry': 'strawberry-graphql',
        
        # Bases de datos
        'sqlalchemy': 'SQLAlchemy',
        'alembic': 'alembic',
        'psycopg2': 'psycopg2-binary',
        'psycopg': 'psycopg',
        'pymysql': 'PyMySQL',
        'MySQLdb': 'mysqlclient',
        'mysql': 'mysql-connector-python',
        'pymongo': 'pymongo',
        'mongoengine': 'mongoengine',
        'motor': 'motor',
        'redis': 'redis',
        'aioredis': 'aioredis',
        'elasticsearch': 'elasticsearch',
        'cassandra': 'cassandra-driver',
        'influxdb': 'influxdb',
        'neo4j': 'neo4j',
        'sqlite_utils': 'sqlite-utils',
        'databases': 'databases',
        'peewee': 'peewee',
        'tortoise': 'tortoise-orm',
        'pony': 'pony',
        'prisma': 'prisma',
        'sqlmodel': 'sqlmodel',
        'cx_Oracle': 'cx-Oracle',
        'oracledb': 'oracledb',
        'pyodbc': 'pyodbc',
        'aiomysql': 'aiomysql',
        'aiopg': 'aiopg',
        'asyncpg': 'asyncpg',
        
        # Testing
        'pytest': 'pytest',
        'nose': 'nose',
        'nose2': 'nose2',
        'mock': 'mock',
        'faker': 'Faker',
        'hypothesis': 'hypothesis',
        'coverage': 'coverage',
        'tox': 'tox',
        'nox': 'nox',
        'locust': 'locust',
        'behave': 'behave',
        'lettuce': 'lettuce',
        'robot': 'robotframework',
        'responses': 'responses',
        'httpretty': 'httpretty',
        'vcrpy': 'vcrpy',
        'factory_boy': 'factory-boy',
        'freezegun': 'freezegun',
        'time_machine': 'time-machine',
        'pytest_asyncio': 'pytest-asyncio',
        'pytest_cov': 'pytest-cov',
        'pytest_mock': 'pytest-mock',
        
        # CLI
        'click': 'click',
        'typer': 'typer',
        'fire': 'fire',
        'docopt': 'docopt',
        'clint': 'clint',
        'cliff': 'cliff',
        'plumbum': 'plumbum',
        'prompt_toolkit': 'prompt-toolkit',
        'questionary': 'questionary',
        'inquirer': 'inquirer',
        'rich': 'rich',
        'colorama': 'colorama',
        'termcolor': 'termcolor',
        'blessed': 'blessed',
        'tqdm': 'tqdm',
        'alive_progress': 'alive-progress',
        'progressbar': 'progressbar2',
        'tabulate': 'tabulate',
        'prettytable': 'prettytable',
        
        # Configuración
        'yaml': 'PyYAML',
        'toml': 'toml',
        'tomli': 'tomli',
        'tomlkit': 'tomlkit',
        'dotenv': 'python-dotenv',
        'decouple': 'python-decouple',
        'environ': 'environ-config',
        'hydra': 'hydra-core',
        'omegaconf': 'omegaconf',
        'pydantic': 'pydantic',
        'pydantic_settings': 'pydantic-settings',
        'attrs': 'attrs',
        'cattrs': 'cattrs',
        'marshmallow': 'marshmallow',
        'dynaconf': 'dynaconf',
        
        # Documentos
        'docx': 'python-docx',
        'pptx': 'python-pptx',
        'openpyxl': 'openpyxl',
        'xlrd': 'xlrd',
        'xlwt': 'xlwt',
        'xlsxwriter': 'XlsxWriter',
        'PyPDF2': 'PyPDF2',
        'pypdf': 'pypdf',
        'pdfplumber': 'pdfplumber',
        'reportlab': 'reportlab',
        'fpdf': 'fpdf2',
        'weasyprint': 'weasyprint',
        'pdfrw': 'pdfrw',
        'pikepdf': 'pikepdf',
        'tabula': 'tabula-py',
        'camelot': 'camelot-py',
        'mammoth': 'mammoth',
        'docx2txt': 'docx2txt',
        'epub': 'EbookLib',
        'ebooklib': 'EbookLib',
        
        # Fechas
        'dateutil': 'python-dateutil',
        'arrow': 'arrow',
        'pendulum': 'pendulum',
        'pytz': 'pytz',
        'babel': 'Babel',
        'humanize': 'humanize',
        'timeago': 'timeago',
        'croniter': 'croniter',
        
        # Seguridad / Criptografía
        'jwt': 'PyJWT',
        'jose': 'python-jose',
        'OpenSSL': 'pyOpenSSL',
        'Crypto': 'pycryptodome',
        'Cryptodome': 'pycryptodome',
        'cryptography': 'cryptography',
        'nacl': 'PyNaCl',
        'bcrypt': 'bcrypt',
        'passlib': 'passlib',
        'fernet': 'cryptography',
        'itsdangerous': 'itsdangerous',
        'argon2': 'argon2-cffi',
        'oauthlib': 'oauthlib',
        'authlib': 'authlib',
        'msal': 'msal',
        
        # Hardware / IoT
        'serial': 'pyserial',
        'usb': 'pyusb',
        'gpio': 'RPi.GPIO',
        'RPi': 'RPi.GPIO',
        'smbus': 'smbus2',
        'spidev': 'spidev',
        'pynput': 'pynput',
        'keyboard': 'keyboard',
        'mouse': 'mouse',
        'pyautogui': 'PyAutoGUI',
        'evdev': 'evdev',
        
        # GUI
        'PyQt5': 'PyQt5',
        'PyQt6': 'PyQt6',
        'PySide2': 'PySide2',
        'PySide6': 'PySide6',
        'wx': 'wxPython',
        'kivy': 'kivy',
        'pygame': 'pygame',
        'arcade': 'arcade',
        'pyglet': 'pyglet',
        'pyqtgraph': 'pyqtgraph',
        'dearpygui': 'dearpygui',
        'customtkinter': 'customtkinter',
        'ttkbootstrap': 'ttkbootstrap',
        'flet': 'flet',
        'toga': 'toga',
        'eel': 'Eel',
        
        # Audio / Video
        'pydub': 'pydub',
        'soundfile': 'soundfile',
        'librosa': 'librosa',
        'pyaudio': 'PyAudio',
        'sounddevice': 'sounddevice',
        'simpleaudio': 'simpleaudio',
        'playsound': 'playsound',
        'moviepy': 'moviepy',
        'ffmpeg': 'ffmpeg-python',
        'av': 'av',
        'speech_recognition': 'SpeechRecognition',
        'gtts': 'gTTS',
        'pyttsx3': 'pyttsx3',
        'whisper': 'openai-whisper',
        
        # Cloud / DevOps
        'boto3': 'boto3',
        'botocore': 'botocore',
        'google': 'google-cloud-core',
        'googleapiclient': 'google-api-python-client',
        'azure': 'azure-core',
        'digitalocean': 'python-digitalocean',
        'linode': 'linode-api',
        'vultr': 'vultr',
        'hcloud': 'hcloud',
        'docker': 'docker',
        'kubernetes': 'kubernetes',
        'k8s': 'kubernetes',
        'ansible': 'ansible',
        'fabric': 'fabric',
        'paramiko': 'paramiko',
        'invoke': 'invoke',
        'troposphere': 'troposphere',
        'pulumi': 'pulumi',
        'terraform': 'python-terraform',
        
        # Logging / Monitoring
        'loguru': 'loguru',
        'structlog': 'structlog',
        'sentry_sdk': 'sentry-sdk',
        'newrelic': 'newrelic',
        'datadog': 'datadog',
        'prometheus_client': 'prometheus-client',
        'opentelemetry': 'opentelemetry-api',
        'jaeger_client': 'jaeger-client',
        
        # Mensajería / Cola
        'celery': 'celery',
        'rq': 'rq',
        'dramatiq': 'dramatiq',
        'huey': 'huey',
        'arq': 'arq',
        'pika': 'pika',
        'kombu': 'kombu',
        'kafka': 'kafka-python',
        'confluent_kafka': 'confluent-kafka',
        'stomp': 'stomp.py',
        'nats': 'nats-py',
        'zmq': 'pyzmq',
        
        # NLP
        'nltk': 'nltk',
        'spacy': 'spacy',
        'gensim': 'gensim',
        'textblob': 'textblob',
        'flair': 'flair',
        'stanza': 'stanza',
        'polyglot': 'polyglot',
        'pattern': 'pattern',
        'sumy': 'sumy',
        'newspaper': 'newspaper3k',
        'langdetect': 'langdetect',
        'ftfy': 'ftfy',
        'unidecode': 'Unidecode',
        'emoji': 'emoji',
        'flashtext': 'flashtext',
        'rake_nltk': 'rake-nltk',
        'keybert': 'keybert',
        'sentence_transformers': 'sentence-transformers',
        
        # Geolocalización
        'geopy': 'geopy',
        'folium': 'folium',
        'geopandas': 'geopandas',
        'shapely': 'shapely',
        'fiona': 'fiona',
        'pyproj': 'pyproj',
        'rasterio': 'rasterio',
        'cartopy': 'cartopy',
        'osmnx': 'osmnx',
        'h3': 'h3',
        
        # Finanzas
        'yfinance': 'yfinance',
        'pandas_datareader': 'pandas-datareader',
        'ta': 'ta',
        'talib': 'TA-Lib',
        'pyfolio': 'pyfolio',
        'zipline': 'zipline-reloaded',
        'backtrader': 'backtrader',
        'ccxt': 'ccxt',
        'robin_stocks': 'robin_stocks',
        'alpaca_trade_api': 'alpaca-trade-api',
        'fredapi': 'fredapi',
        'quandl': 'Quandl',
        
        # Blockchain
        'web3': 'web3',
        'eth_account': 'eth-account',
        'brownie': 'eth-brownie',
        'vyper': 'vyper',
        'py_solc_x': 'py-solc-x',
        
        # Validación
        'cerberus': 'Cerberus',
        'voluptuous': 'voluptuous',
        'jsonschema': 'jsonschema',
        'schema': 'schema',
        'validators': 'validators',
        'email_validator': 'email-validator',
        'phonenumbers': 'phonenumbers',
        
        # Otros
        'tldextract': 'tldextract',
        'shortuuid': 'shortuuid',
        'nanoid': 'nanoid',
        'slugify': 'python-slugify',
        'qrcode': 'qrcode',
        'barcode': 'python-barcode',
        'pdf417': 'pdf417gen',
        'cairosvg': 'CairoSVG',
        'svgwrite': 'svgwrite',
        'pygraphviz': 'pygraphviz',
        'networkx': 'networkx',
        'igraph': 'python-igraph',
        'schedule': 'schedule',
        'apscheduler': 'APScheduler',
        'joblib': 'joblib',
        'dask': 'dask',
        'vaex': 'vaex',
        'polars': 'polars',
        'modin': 'modin',
        'pyarrow': 'pyarrow',
        'fastparquet': 'fastparquet',
        'orjson': 'orjson',
        'ujson': 'ujson',
        'rapidjson': 'python-rapidjson',
        'msgpack': 'msgpack',
        'protobuf': 'protobuf',
        'thrift': 'thrift',
        'avro': 'avro-python3',
        'capnp': 'pycapnp',
        'flatbuffers': 'flatbuffers',
        'cachetools': 'cachetools',
        'diskcache': 'diskcache',
        'dogpile': 'dogpile.cache',
        'aiocache': 'aiocache',
        'tenacity': 'tenacity',
        'retry': 'retry',
        'backoff': 'backoff',
        'ratelimit': 'ratelimit',
        'limits': 'limits',
        'returns': 'returns',
        'result': 'result',
        'toolz': 'toolz',
        'cytoolz': 'cytoolz',
        'more_itertools': 'more-itertools',
        'boltons': 'boltons',
        'wrapt': 'wrapt',
        'decorator': 'decorator',
        'multipledispatch': 'multipledispatch',
        'plum': 'plum-dispatch',
        'typing_extensions': 'typing-extensions',
        'mypy': 'mypy',
        'pylint': 'pylint',
        'flake8': 'flake8',
        'black': 'black',
        'isort': 'isort',
        'autopep8': 'autopep8',
        'yapf': 'yapf',
        'ruff': 'ruff',
        'bandit': 'bandit',
        'safety': 'safety',
        'pip_audit': 'pip-audit',
        'pyupgrade': 'pyupgrade',
        'pre_commit': 'pre-commit',
        'commitizen': 'commitizen',
        'semantic_release': 'python-semantic-release',
        'bumpversion': 'bumpversion',
        'nuitka': 'Nuitka',
        'pyinstaller': 'pyinstaller',
        'cx_Freeze': 'cx-Freeze',
        'briefcase': 'briefcase',
        'poetry': 'poetry',
        'pipenv': 'pipenv',
        'pdm': 'pdm',
        'hatch': 'hatch',
        'flit': 'flit',
        'build': 'build',
        'twine': 'twine',
        'setuptools': 'setuptools',
        'wheel': 'wheel',
        'cython': 'Cython',
        'numba': 'numba',
        'cffi': 'cffi',
        'pybind11': 'pybind11',
        'swig': 'swig',
        'mako': 'Mako',
        'chameleon': 'Chameleon',
        'genshi': 'Genshi',
        'lark': 'lark',
        'pyparsing': 'pyparsing',
        'ply': 'ply',
        'antlr4': 'antlr4-python3-runtime',
        'parsimonious': 'parsimonious',
        'regex': 'regex',
        'parse': 'parse',
        'dateparser': 'dateparser',
        'parsedatetime': 'parsedatetime',
        'chardet': 'chardet',
        'charset_normalizer': 'charset-normalizer',
        'magic': 'python-magic',
        'filetype': 'filetype',
        'mimesis': 'mimesis',
        'faker': 'Faker',
        'names': 'names',
        'essential_generators': 'essential-generators',
        'lorem': 'lorem',
        'synth': 'synth',
        'factory': 'factory_boy',
        'model_bakery': 'model-bakery',
        'mixer': 'mixer',
    }


# ==============================================================================
# CACHE MANAGER
# ==============================================================================

class CacheManager:
    """Gestiona el caché de información de paquetes"""
    
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self.cache: Dict[str, Any] = {}
        self._load_cache()
    
    def _load_cache(self):
        """Carga el caché desde disco"""
        try:
            if CACHE_FILE.exists():
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Verificar expiración
                    if data.get('timestamp', 0) + CACHE_EXPIRY > datetime.now().timestamp():
                        self.cache = data.get('packages', {})
        except Exception:
            self.cache = {}
    
    def _save_cache(self):
        """Guarda el caché a disco"""
        try:
            data = {
                'timestamp': datetime.now().timestamp(),
                'packages': self.cache
            }
            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def get(self, package: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de un paquete del caché"""
        return self.cache.get(package.lower())
    
    def set(self, package: str, info: Dict[str, Any]):
        """Guarda información de un paquete en el caché"""
        self.cache[package.lower()] = info
        self._save_cache()
    
    def clear(self):
        """Limpia el caché"""
        self.cache = {}
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()


# ==============================================================================
# HISTORY MANAGER
# ==============================================================================

class HistoryManager:
    """Gestiona el historial de operaciones"""
    
    def __init__(self):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Inicializa la base de datos de historial"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    package TEXT,
                    status TEXT NOT NULL,
                    details TEXT,
                    venv_path TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    total_files INTEGER,
                    total_imports INTEGER,
                    missing_packages INTEGER
                )
            ''')
            conn.commit()
    
    def log_operation(self, operation: str, package: Optional[str], 
                      status: str, details: str = "", venv_path: str = ""):
        """Registra una operación en el historial"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            conn.execute('''
                INSERT INTO operations (timestamp, operation, package, status, details, venv_path)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), operation, package, status, details, venv_path))
            conn.commit()
    
    def log_scan(self, project_path: str, total_files: int, 
                 total_imports: int, missing_packages: int):
        """Registra un escaneo en el historial"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            conn.execute('''
                INSERT INTO scans (timestamp, project_path, total_files, total_imports, missing_packages)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), project_path, total_files, total_imports, missing_packages))
            conn.commit()
    
    def get_recent_operations(self, limit: int = 100) -> List[Tuple]:
        """Obtiene las operaciones recientes"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            cursor = conn.execute('''
                SELECT timestamp, operation, package, status, details
                FROM operations
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
    
    def get_recent_scans(self, limit: int = 20) -> List[Tuple]:
        """Obtiene los escaneos recientes"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            cursor = conn.execute('''
                SELECT timestamp, project_path, total_files, total_imports, missing_packages
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
    
    def clear_history(self):
        """Limpia todo el historial"""
        with sqlite3.connect(HISTORY_FILE) as conn:
            conn.execute('DELETE FROM operations')
            conn.execute('DELETE FROM scans')
            conn.commit()


# ==============================================================================
# PYPI CLIENT
# ==============================================================================

class PyPIClient:
    """Cliente para consultar información de PyPI"""
    
    PYPI_API_URL = "https://pypi.org/pypi/{package}/json"
    
    def __init__(self, cache: CacheManager):
        self.cache = cache
    
    def get_package_info(self, package: str) -> Optional[Dict[str, Any]]:
        """Obtiene información de un paquete desde PyPI"""
        # Verificar caché primero
        cached = self.cache.get(package)
        if cached:
            return cached
        
        try:
            url = self.PYPI_API_URL.format(package=package)
            req = urllib.request.Request(url, headers={'User-Agent': 'RequirementsInstaller/2.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                info = {
                    'name': data['info']['name'],
                    'version': data['info']['version'],
                    'summary': data['info']['summary'],
                    'author': data['info']['author'],
                    'license': data['info']['license'],
                    'requires_python': data['info']['requires_python'],
                    'home_page': data['info']['home_page'],
                    'exists': True
                }
                self.cache.set(package, info)
                return info
        except urllib.error.HTTPError as e:
            if e.code == 404:
                info = {'exists': False, 'name': package}
                self.cache.set(package, info)
                return info
        except Exception:
            pass
        return None
    
    def package_exists(self, package: str) -> bool:
        """Verifica si un paquete existe en PyPI"""
        info = self.get_package_info(package)
        return info is not None and info.get('exists', False)


# ==============================================================================
# VULNERABILITY CHECKER
# ==============================================================================

class VulnerabilityChecker:
    """Verifica vulnerabilidades de seguridad en paquetes"""
    
    # URL de la base de datos de seguridad de PyPI
    SAFETY_DB_URL = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
    
    def __init__(self):
        self.db: Dict[str, List[Dict]] = {}
        self._loaded = False
    
    def load_database(self) -> bool:
        """Carga la base de datos de vulnerabilidades"""
        if self._loaded:
            return True
        
        try:
            req = urllib.request.Request(
                self.SAFETY_DB_URL, 
                headers={'User-Agent': 'RequirementsInstaller/2.0'}
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                self.db = json.loads(response.read().decode('utf-8'))
                self._loaded = True
                return True
        except Exception:
            return False
    
    def check_package(self, package: str, version: Optional[str] = None) -> List[Dict]:
        """Verifica si un paquete tiene vulnerabilidades conocidas"""
        if not self._loaded:
            if not self.load_database():
                return []
        
        vulnerabilities = []
        package_lower = package.lower()
        
        if package_lower in self.db:
            for vuln in self.db[package_lower]:
                if version:
                    # Verificar si la versión está afectada
                    specs = vuln.get('specs', [])
                    if self._version_matches(version, specs):
                        vulnerabilities.append({
                            'id': vuln.get('id', 'Unknown'),
                            'advisory': vuln.get('advisory', 'No description'),
                            'specs': specs,
                            'cve': vuln.get('cve')
                        })
                else:
                    vulnerabilities.append({
                        'id': vuln.get('id', 'Unknown'),
                        'advisory': vuln.get('advisory', 'No description'),
                        'specs': vuln.get('specs', []),
                        'cve': vuln.get('cve')
                    })
        
        return vulnerabilities
    
    def _version_matches(self, version: str, specs: List[str]) -> bool:
        """Verifica si una versión coincide con las especificaciones"""
        try:
            from packaging.specifiers import SpecifierSet
            from packaging.version import parse
            
            spec_set = SpecifierSet(','.join(specs))
            return parse(version) in spec_set
        except Exception:
            # Si no podemos verificar, asumimos que podría estar afectado
            return True


# ==============================================================================
# IMPORT SCANNER
# ==============================================================================

class ImportScanner:
    """Escanea archivos Python para encontrar imports"""
    
    def __init__(self):
        self.stdlib_modules = get_stdlib_modules()
        self.import_to_pypi = get_import_to_pypi_mapping()
        self.found_imports: Set[str] = set()
        self.import_locations: Dict[str, List[str]] = defaultdict(list)
        self.errors: List[str] = []
    
    def scan_file(self, filepath: Path) -> Set[str]:
        """Escanea un archivo Python para encontrar imports"""
        imports = set()
        
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        module = alias.name.split('.')[0]
                        imports.add(module)
                        self.import_locations[module].append(str(filepath))
                        
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module = node.module.split('.')[0]
                        imports.add(module)
                        self.import_locations[module].append(str(filepath))
                        
        except SyntaxError as e:
            self.errors.append(f"Syntax error in {filepath}: {e}")
        except Exception as e:
            self.errors.append(f"Error scanning {filepath}: {e}")
        
        self.found_imports.update(imports)
        return imports
    
    def scan_directory(self, directory: Path, 
                       exclude_patterns: Optional[List[str]] = None,
                       progress_callback: Optional[callable] = None) -> Dict[str, Set[str]]:
        """Escanea un directorio completo"""
        if exclude_patterns is None:
            exclude_patterns = [
                '__pycache__', '.git', '.hg', '.svn', 'node_modules',
                'venv', '.venv', 'env', '.env', '.tox', '.nox',
                'build', 'dist', '*.egg-info', '.eggs'
            ]
        
        results: Dict[str, Set[str]] = {}
        py_files = list(directory.rglob("*.py"))
        
        # Filtrar archivos excluidos
        def should_exclude(path: Path) -> bool:
            for pattern in exclude_patterns:
                if '*' in pattern:
                    if path.match(pattern):
                        return True
                else:
                    if pattern in path.parts:
                        return True
            return False
        
        py_files = [f for f in py_files if not should_exclude(f)]
        total = len(py_files)
        
        for idx, py_file in enumerate(py_files):
            imports = self.scan_file(py_file)
            results[str(py_file)] = imports
            
            if progress_callback:
                progress_callback(idx + 1, total, py_file.name)
        
        return results
    
    def get_pypi_name(self, import_name: str) -> str:
        """Obtiene el nombre del paquete PyPI para un import"""
        return self.import_to_pypi.get(import_name, import_name)
    
    def is_stdlib(self, import_name: str) -> bool:
        """Verifica si un import es de la biblioteca estándar"""
        return import_name in self.stdlib_modules
    
    def get_third_party_imports(self) -> Set[str]:
        """Obtiene solo los imports de terceros"""
        return {imp for imp in self.found_imports if not self.is_stdlib(imp)}
    
    def reset(self):
        """Reinicia el escáner"""
        self.found_imports.clear()
        self.import_locations.clear()
        self.errors.clear()


# ==============================================================================
# REQUIREMENTS PARSER
# ==============================================================================

class RequirementsParser:
    """Parser para diferentes formatos de archivos de requerimientos"""
    
    @staticmethod
    def parse_requirements_txt(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un archivo requirements.txt"""
        packages = []
        
        try:
            content = filepath.read_text(encoding='utf-8')
            
            for line in content.splitlines():
                line = line.strip()
                
                # Ignorar comentarios y líneas vacías
                if not line or line.startswith('#'):
                    continue
                
                # Ignorar opciones (-r, -e, etc.)
                if line.startswith('-'):
                    continue
                
                # Parsear nombre y versión
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*([<>=!~\[\]].*)?\s*(?:#.*)?$', line)
                if match:
                    packages.append({
                        'name': match.group(1),
                        'specifier': match.group(2) or '',
                        'source': str(filepath)
                    })
        except Exception:
            pass
        
        return packages
    
    @staticmethod
    def parse_setup_py(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un archivo setup.py"""
        packages = []
        
        try:
            content = filepath.read_text(encoding='utf-8')
            
            # Buscar install_requires
            match = re.search(r'install_requires\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                requires_str = match.group(1)
                for req in re.findall(r'["\']([^"\']+)["\']', requires_str):
                    pkg_match = re.match(r'^([a-zA-Z0-9_-]+)', req)
                    if pkg_match:
                        packages.append({
                            'name': pkg_match.group(1),
                            'specifier': req[len(pkg_match.group(1)):],
                            'source': str(filepath)
                        })
        except Exception:
            pass
        
        return packages
    
    @staticmethod
    def parse_pyproject_toml(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un archivo pyproject.toml"""
        packages = []
        
        try:
            # Intentar importar tomllib (Python 3.11+) o toml
            try:
                import tomllib
                with open(filepath, 'rb') as f:
                    data = tomllib.load(f)
            except ImportError:
                import toml
                data = toml.load(filepath)
            
            # PEP 621 dependencies
            if 'project' in data and 'dependencies' in data['project']:
                for dep in data['project']['dependencies']:
                    match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                    if match:
                        packages.append({
                            'name': match.group(1),
                            'specifier': dep[len(match.group(1)):],
                            'source': str(filepath)
                        })
            
            # Poetry dependencies
            if 'tool' in data and 'poetry' in data['tool']:
                poetry = data['tool']['poetry']
                for section in ['dependencies', 'dev-dependencies']:
                    if section in poetry:
                        for name, spec in poetry[section].items():
                            if name.lower() != 'python':
                                packages.append({
                                    'name': name,
                                    'specifier': spec if isinstance(spec, str) else '',
                                    'source': str(filepath)
                                })
        except Exception:
            pass
        
        return packages
    
    @staticmethod
    def parse_pipfile(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un Pipfile"""
        packages = []
        
        try:
            import toml
            data = toml.load(filepath)
            
            for section in ['packages', 'dev-packages']:
                if section in data:
                    for name, spec in data[section].items():
                        packages.append({
                            'name': name,
                            'specifier': spec if isinstance(spec, str) else '',
                            'source': str(filepath),
                            'dev': section == 'dev-packages'
                        })
        except Exception:
            pass
        
        return packages
    
    @staticmethod
    def parse_setup_cfg(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un archivo setup.cfg"""
        packages = []
        
        try:
            config = configparser.ConfigParser()
            config.read(filepath)
            
            if 'options' in config and 'install_requires' in config['options']:
                requires = config['options']['install_requires']
                for line in requires.strip().splitlines():
                    line = line.strip()
                    if line:
                        match = re.match(r'^([a-zA-Z0-9_-]+)', line)
                        if match:
                            packages.append({
                                'name': match.group(1),
                                'specifier': line[len(match.group(1)):],
                                'source': str(filepath)
                            })
        except Exception:
            pass
        
        return packages
    
    @staticmethod
    def parse_conda_yaml(filepath: Path) -> List[Dict[str, Any]]:
        """Parsea un archivo environment.yml de conda"""
        packages = []
        
        try:
            import yaml
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            
            if 'dependencies' in data:
                for dep in data['dependencies']:
                    if isinstance(dep, str):
                        match = re.match(r'^([a-zA-Z0-9_-]+)', dep.split('=')[0])
                        if match:
                            packages.append({
                                'name': match.group(1),
                                'specifier': '',
                                'source': str(filepath),
                                'conda': True
                            })
                    elif isinstance(dep, dict) and 'pip' in dep:
                        for pip_dep in dep['pip']:
                            match = re.match(r'^([a-zA-Z0-9_-]+)', pip_dep)
                            if match:
                                packages.append({
                                    'name': match.group(1),
                                    'specifier': pip_dep[len(match.group(1)):],
                                    'source': str(filepath)
                                })
        except Exception:
            pass
        
        return packages


# ==============================================================================
# REQUIREMENTS EXPORTER
# ==============================================================================

class RequirementsExporter:
    """Exporta dependencias a diferentes formatos"""
    
    @staticmethod
    def to_requirements_txt(packages: List[Dict[str, Any]], 
                           include_versions: bool = True) -> str:
        """Exporta a formato requirements.txt"""
        lines = ["# Generated by Auto Requirements Installer Pro"]
        lines.append(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        for pkg in sorted(packages, key=lambda x: x['name'].lower()):
            if include_versions and pkg.get('version'):
                lines.append(f"{pkg['name']}=={pkg['version']}")
            else:
                lines.append(pkg['name'])
        
        return '\n'.join(lines)
    
    @staticmethod
    def to_pipfile(packages: List[Dict[str, Any]], 
                   python_version: str = None) -> str:
        """Exporta a formato Pipfile"""
        import toml
        
        if python_version is None:
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        
        data = {
            "source": [{
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": True
            }],
            "packages": {},
            "dev-packages": {},
            "requires": {
                "python_version": python_version
            }
        }
        
        for pkg in packages:
            if pkg.get('version'):
                data["packages"][pkg['name']] = f"=={pkg['version']}"
            else:
                data["packages"][pkg['name']] = "*"
        
        return toml.dumps(data)
    
    @staticmethod
    def to_pyproject_toml(packages: List[Dict[str, Any]], 
                          project_name: str = "my-project",
                          python_version: str = None) -> str:
        """Exporta a formato pyproject.toml"""
        import toml
        
        if python_version is None:
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
        
        dependencies = []
        for pkg in packages:
            if pkg.get('version'):
                dependencies.append(f"{pkg['name']}>={pkg['version']}")
            else:
                dependencies.append(pkg['name'])
        
        data = {
            "build-system": {
                "requires": ["setuptools>=45", "wheel"],
                "build-backend": "setuptools.build_meta"
            },
            "project": {
                "name": project_name,
                "version": "0.1.0",
                "description": "Auto-generated by Requirements Installer Pro",
                "requires-python": f">={python_version}",
                "dependencies": sorted(dependencies)
            }
        }
        
        return toml.dumps(data)
    
    @staticmethod
    def to_poetry_pyproject(packages: List[Dict[str, Any]], 
                            project_name: str = "my-project",
                            python_version: str = None) -> str:
        """Exporta a formato pyproject.toml con Poetry"""
        import toml
        
        if python_version is None:
            python_version = f"^{sys.version_info.major}.{sys.version_info.minor}"
        
        dependencies = {"python": python_version}
        for pkg in packages:
            if pkg.get('version'):
                dependencies[pkg['name']] = f"^{pkg['version']}"
            else:
                dependencies[pkg['name']] = "*"
        
        data = {
            "tool": {
                "poetry": {
                    "name": project_name,
                    "version": "0.1.0",
                    "description": "Auto-generated by Requirements Installer Pro",
                    "authors": ["Your Name <you@example.com>"],
                    "dependencies": dependencies
                }
            },
            "build-system": {
                "requires": ["poetry-core>=1.0.0"],
                "build-backend": "poetry.core.masonry.api"
            }
        }
        
        return toml.dumps(data)


# ==============================================================================
# PACKAGE INSTALLER
# ==============================================================================

class PackageInstaller:
    """Gestor de instalación de paquetes"""
    
    def __init__(self, python_executable: str = None, history: HistoryManager = None):
        self.python = python_executable or sys.executable
        self.history = history
    
    def install(self, package: str, version: str = None, 
                upgrade: bool = False) -> Tuple[bool, str]:
        """Instala un paquete"""
        cmd = [self.python, "-m", "pip", "install"]
        
        if upgrade:
            cmd.append("--upgrade")
        
        if version:
            cmd.append(f"{package}=={version}")
        else:
            cmd.append(package)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            if self.history:
                self.history.log_operation(
                    "install", package,
                    "success" if success else "error",
                    output[:500]
                )
            
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, str(e)
    
    def install_from_requirements(self, filepath: str) -> Tuple[bool, str]:
        """Instala desde un archivo requirements.txt"""
        cmd = [self.python, "-m", "pip", "install", "-r", filepath]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            if self.history:
                self.history.log_operation(
                    "install_requirements", filepath,
                    "success" if success else "error",
                    output[:500]
                )
            
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Installation timed out"
        except Exception as e:
            return False, str(e)
    
    def uninstall(self, package: str) -> Tuple[bool, str]:
        """Desinstala un paquete"""
        cmd = [self.python, "-m", "pip", "uninstall", "-y", package]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            success = result.returncode == 0
            output = result.stdout if success else result.stderr
            
            if self.history:
                self.history.log_operation(
                    "uninstall", package,
                    "success" if success else "error",
                    output[:500]
                )
            
            return success, output
        except Exception as e:
            return False, str(e)
    
    def get_installed_packages(self) -> Dict[str, str]:
        """Obtiene la lista de paquetes instalados"""
        try:
            result = subprocess.run(
                [self.python, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                return {pkg['name'].lower(): pkg['version'] for pkg in packages}
        except Exception:
            pass
        return {}
    
    def get_outdated_packages(self) -> List[Dict[str, str]]:
        """Obtiene la lista de paquetes desactualizados"""
        try:
            result = subprocess.run(
                [self.python, "-m", "pip", "list", "--outdated", "--format=json"],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception:
            pass
        return []
    
    def freeze(self) -> str:
        """Genera un freeze de las dependencias actuales"""
        try:
            result = subprocess.run(
                [self.python, "-m", "pip", "freeze"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return result.stdout
        except Exception:
            pass
        return ""


# ==============================================================================
# VENV MANAGER
# ==============================================================================

class VenvManager:
    """Gestor de entornos virtuales"""
    
    @staticmethod
    def is_venv_active() -> bool:
        """Verifica si hay un entorno virtual activo"""
        return hasattr(sys, 'real_prefix') or \
               (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    @staticmethod
    def get_venv_path() -> Optional[str]:
        """Obtiene la ruta del entorno virtual actual"""
        if VenvManager.is_venv_active():
            return sys.prefix
        return None
    
    @staticmethod
    def get_python_executable(venv_path: str) -> str:
        """Obtiene el ejecutable de Python para un entorno virtual"""
        if platform.system() == "Windows":
            return os.path.join(venv_path, "Scripts", "python.exe")
        return os.path.join(venv_path, "bin", "python")
    
    @staticmethod
    def is_valid_venv(path: str) -> bool:
        """Verifica si una ruta es un entorno virtual válido"""
        python_exe = VenvManager.get_python_executable(path)
        return os.path.exists(python_exe)
    
    @staticmethod
    def create_venv(path: str, with_pip: bool = True) -> Tuple[bool, str]:
        """Crea un nuevo entorno virtual"""
        try:
            venv.create(path, with_pip=with_pip)
            
            # Actualizar pip
            python_exe = VenvManager.get_python_executable(path)
            subprocess.run(
                [python_exe, "-m", "pip", "install", "--upgrade", "pip"],
                capture_output=True, timeout=120
            )
            
            return True, f"Virtual environment created at {path}"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def get_venv_info(path: str) -> Dict[str, Any]:
        """Obtiene información sobre un entorno virtual"""
        python_exe = VenvManager.get_python_executable(path)
        
        info = {
            'path': path,
            'python': python_exe,
            'valid': VenvManager.is_valid_venv(path)
        }
        
        if info['valid']:
            try:
                result = subprocess.run(
                    [python_exe, "--version"],
                    capture_output=True, text=True, timeout=10
                )
                info['python_version'] = result.stdout.strip()
            except Exception:
                pass
        
        return info


# ==============================================================================
# THEME MANAGER
# ==============================================================================

class ThemeManager:
    """Gestor de temas para la interfaz"""
    
    THEMES = {
        'light': {
            'bg': '#f5f5f5',
            'fg': '#212121',
            'primary': '#1976D2',
            'secondary': '#455A64',
            'success': '#388E3C',
            'warning': '#F57C00',
            'error': '#D32F2F',
            'surface': '#ffffff',
            'border': '#e0e0e0',
            'text_muted': '#757575',
            'tree_bg': '#ffffff',
            'tree_selected': '#e3f2fd'
        },
        'dark': {
            'bg': '#121212',
            'fg': '#e0e0e0',
            'primary': '#90CAF9',
            'secondary': '#B0BEC5',
            'success': '#81C784',
            'warning': '#FFB74D',
            'error': '#E57373',
            'surface': '#1e1e1e',
            'border': '#333333',
            'text_muted': '#9e9e9e',
            'tree_bg': '#1e1e1e',
            'tree_selected': '#37474f'
        },
        'nord': {
            'bg': '#2e3440',
            'fg': '#eceff4',
            'primary': '#88c0d0',
            'secondary': '#81a1c1',
            'success': '#a3be8c',
            'warning': '#ebcb8b',
            'error': '#bf616a',
            'surface': '#3b4252',
            'border': '#4c566a',
            'text_muted': '#d8dee9',
            'tree_bg': '#3b4252',
            'tree_selected': '#434c5e'
        },
        'dracula': {
            'bg': '#282a36',
            'fg': '#f8f8f2',
            'primary': '#bd93f9',
            'secondary': '#8be9fd',
            'success': '#50fa7b',
            'warning': '#ffb86c',
            'error': '#ff5555',
            'surface': '#44475a',
            'border': '#6272a4',
            'text_muted': '#6272a4',
            'tree_bg': '#44475a',
            'tree_selected': '#6272a4'
        }
    }
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.current_theme = 'light'
        self.style = ttk.Style()
    
    def apply_theme(self, theme_name: str):
        """Aplica un tema a la interfaz"""
        if theme_name not in self.THEMES:
            theme_name = 'light'
        
        self.current_theme = theme_name
        theme = self.THEMES[theme_name]
        
        # Configurar estilo
        self.style.theme_use('clam')
        
        # Configurar colores del root
        self.root.configure(bg=theme['bg'])
        
        # Configurar estilos de widgets
        self.style.configure('.',
            background=theme['bg'],
            foreground=theme['fg'],
            fieldbackground=theme['surface']
        )
        
        self.style.configure('TFrame', background=theme['bg'])
        self.style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        self.style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        self.style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        
        self.style.configure('TButton',
            background=theme['primary'],
            foreground=theme['fg'],
            padding=6
        )
        self.style.map('TButton',
            background=[('active', theme['secondary'])],
            foreground=[('active', theme['fg'])]
        )
        
        self.style.configure('Success.TButton', background=theme['success'])
        self.style.configure('Warning.TButton', background=theme['warning'])
        self.style.configure('Error.TButton', background=theme['error'])
        
        self.style.configure('TEntry',
            fieldbackground=theme['surface'],
            foreground=theme['fg'],
            insertcolor=theme['fg']
        )
        
        self.style.configure('TCombobox',
            fieldbackground=theme['surface'],
            foreground=theme['fg'],
            selectbackground=theme['primary']
        )
        
        self.style.configure('TNotebook', background=theme['bg'])
        self.style.configure('TNotebook.Tab',
            background=theme['surface'],
            foreground=theme['fg'],
            padding=[10, 5]
        )
        self.style.map('TNotebook.Tab',
            background=[('selected', theme['primary'])],
            foreground=[('selected', theme['fg'])]
        )
        
        self.style.configure('Treeview',
            background=theme['tree_bg'],
            foreground=theme['fg'],
            fieldbackground=theme['tree_bg'],
            rowheight=25
        )
        self.style.map('Treeview',
            background=[('selected', theme['tree_selected'])],
            foreground=[('selected', theme['fg'])]
        )
        
        self.style.configure('Treeview.Heading',
            background=theme['surface'],
            foreground=theme['fg'],
            relief='flat'
        )
        
        self.style.configure('TCheckbutton',
            background=theme['bg'],
            foreground=theme['fg']
        )
        
        self.style.configure('TProgressbar',
            background=theme['primary'],
            troughcolor=theme['surface']
        )
        
        # Guardar colores para uso posterior
        self.colors = theme
        
        return theme


# ==============================================================================
# MAIN APPLICATION
# ==============================================================================

class RequirementsInstallerPro:
    """Aplicación principal del instalador de requerimientos"""
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1100x800")
        self.root.minsize(900, 600)
        
        # Inicializar componentes
        self.cache = CacheManager()
        self.history = HistoryManager()
        self.pypi_client = PyPIClient(self.cache)
        self.vuln_checker = VulnerabilityChecker()
        self.scanner = ImportScanner()
        self.theme_manager = ThemeManager(root)
        
        # Variables
        self.project_path = tk.StringVar()
        self.venv_path = tk.StringVar()
        self.current_python = sys.executable
        self.installed_packages: Dict[str, str] = {}
        self.package_infos: Dict[str, PackageInfo] = {}
        self.requirements_files: List[Path] = []
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Cargar configuración
        self.settings = self._load_settings()
        
        # Aplicar tema
        self.theme_manager.apply_theme(self.settings.get('theme', 'light'))
        
        # Crear interfaz
        self._create_widgets()
        
        # Detectar entorno virtual
        self._detect_venv()
        
        # Cargar paquetes instalados
        self._refresh_installed_packages()
        
        # Vincular evento de cierre
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    
    def _load_settings(self) -> Dict[str, Any]:
        """Carga la configuración desde archivo"""
        try:
            if SETTINGS_FILE.exists():
                with open(SETTINGS_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {'theme': 'light'}
    
    def _save_settings(self):
        """Guarda la configuración a archivo"""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception:
            pass
    
    def _on_close(self):
        """Maneja el cierre de la aplicación"""
        self._save_settings()
        self.executor.shutdown(wait=False)
        self.root.destroy()
    
    def _create_widgets(self):
        """Crea la interfaz gráfica"""
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # === HEADER ===
        self._create_header(main_frame)
        
        # === CONFIGURACIÓN ===
        self._create_config_section(main_frame)
        
        # === BOTONES PRINCIPALES ===
        self._create_action_buttons(main_frame)
        
        # === NOTEBOOK (PESTAÑAS) ===
        self._create_notebook(main_frame)
        
        # === BARRA DE ESTADO ===
        self._create_status_bar(main_frame)
    
    def _create_header(self, parent):
        """Crea el encabezado de la aplicación"""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header_frame.columnconfigure(1, weight=1)
        
        # Título
        title_label = ttk.Label(
            header_frame,
            text=f"🐍 {APP_NAME}",
            font=('Segoe UI', 18, 'bold')
        )
        title_label.grid(row=0, column=0, sticky="w")
        
        # Versión
        version_label = ttk.Label(
            header_frame,
            text=f"v{APP_VERSION}",
            font=('Segoe UI', 10)
        )
        version_label.grid(row=0, column=1, sticky="w", padx=10)
        
        # Selector de tema
        theme_frame = ttk.Frame(header_frame)
        theme_frame.grid(row=0, column=2, sticky="e")
        
        ttk.Label(theme_frame, text="Tema:").pack(side=tk.LEFT, padx=5)
        self.theme_combo = ttk.Combobox(
            theme_frame,
            values=list(ThemeManager.THEMES.keys()),
            state='readonly',
            width=10
        )
        self.theme_combo.set(self.settings.get('theme', 'light'))
        self.theme_combo.pack(side=tk.LEFT)
        self.theme_combo.bind('<<ComboboxSelected>>', self._on_theme_change)
    
    def _create_config_section(self, parent):
        """Crea la sección de configuración"""
        config_frame = ttk.LabelFrame(parent, text="⚙️ Configuración", padding="10")
        config_frame.grid(row=1, column=0, sticky="ew", pady=5)
        config_frame.columnconfigure(1, weight=1)
        
        # Proyecto
        ttk.Label(config_frame, text="📁 Proyecto:").grid(row=0, column=0, sticky="w", padx=5)
        
        project_entry = ttk.Entry(config_frame, textvariable=self.project_path, state='readonly')
        project_entry.grid(row=0, column=1, sticky="ew", padx=5)
        
        ttk.Button(config_frame, text="Seleccionar", command=self._select_project).grid(row=0, column=2, padx=5)
        
        # Entorno virtual
        ttk.Label(config_frame, text="🔧 Entorno:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        
        self.venv_label = ttk.Label(config_frame, text="Sistema", foreground="orange")
        self.venv_label.grid(row=1, column=1, sticky="w", padx=5)
        
        venv_btn_frame = ttk.Frame(config_frame)
        venv_btn_frame.grid(row=1, column=2, padx=5)
        
        ttk.Button(venv_btn_frame, text="Cambiar", command=self._select_venv).pack(side=tk.LEFT, padx=2)
        ttk.Button(venv_btn_frame, text="Crear", command=self._create_venv).pack(side=tk.LEFT, padx=2)
        ttk.Button(venv_btn_frame, text="Info", command=self._show_venv_info).pack(side=tk.LEFT, padx=2)
    
    def _create_action_buttons(self, parent):
        """Crea los botones de acción principales"""
        btn_frame = ttk.Frame(parent)
        btn_frame.grid(row=2, column=0, sticky="ew", pady=10)
        
        # Botones principales
        main_btns = ttk.Frame(btn_frame)
        main_btns.pack(side=tk.LEFT)
        
        ttk.Button(main_btns, text="🔍 Escanear", command=self._scan_project).pack(side=tk.LEFT, padx=3)
        ttk.Button(main_btns, text="📦 Instalar Faltantes", command=self._install_missing).pack(side=tk.LEFT, padx=3)
        ttk.Button(main_btns, text="📄 Desde Archivo", command=self._install_from_file).pack(side=tk.LEFT, padx=3)
        ttk.Button(main_btns, text="🔄 Actualizar Todos", command=self._update_all).pack(side=tk.LEFT, padx=3)
        ttk.Button(main_btns, text="🛡️ Check Seguridad", command=self._check_security).pack(side=tk.LEFT, padx=3)
        
        # Exportación
        export_frame = ttk.Frame(btn_frame)
        export_frame.pack(side=tk.RIGHT)
        
        ttk.Label(export_frame, text="Exportar:").pack(side=tk.LEFT, padx=3)
        
        self.export_format = ttk.Combobox(
            export_frame,
            values=['requirements.txt', 'Pipfile', 'pyproject.toml', 'poetry'],
            state='readonly',
            width=15
        )
        self.export_format.set('requirements.txt')
        self.export_format.pack(side=tk.LEFT, padx=3)
        
        ttk.Button(export_frame, text="💾 Exportar", command=self._export_requirements).pack(side=tk.LEFT, padx=3)
    
    def _create_notebook(self, parent):
        """Crea el notebook con pestañas"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=4, column=0, sticky="nsew", pady=10)
        
        # === Pestaña: Imports ===
        self._create_imports_tab()
        
        # === Pestaña: Archivos de Requerimientos ===
        self._create_requirements_tab()
        
        # === Pestaña: Paquetes Instalados ===
        self._create_installed_tab()
        
        # === Pestaña: Log ===
        self._create_log_tab()
        
        # === Pestaña: Historial ===
        self._create_history_tab()
    
    def _create_imports_tab(self):
        """Crea la pestaña de imports"""
        imports_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(imports_frame, text="📦 Imports Encontrados")
        
        imports_frame.columnconfigure(0, weight=1)
        imports_frame.rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(imports_frame)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Label(toolbar, text="🔎 Filtrar:").pack(side=tk.LEFT, padx=5)
        
        self.filter_var = tk.StringVar()
        self.filter_var.trace('w', self._filter_imports)
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=5)
        
        self.show_stdlib = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="Mostrar Stdlib", variable=self.show_stdlib,
                       command=self._filter_imports).pack(side=tk.LEFT, padx=10)
        
        self.show_installed = tk.BooleanVar(value=True)
        ttk.Checkbutton(toolbar, text="Mostrar Instalados", variable=self.show_installed,
                       command=self._filter_imports).pack(side=tk.LEFT, padx=10)
        
        # Stats
        self.stats_label = ttk.Label(toolbar, text="")
        self.stats_label.pack(side=tk.RIGHT, padx=10)
        
        # Treeview
        tree_frame = ttk.Frame(imports_frame)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('status', 'pypi', 'version', 'latest', 'locations')
        self.imports_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')
        
        self.imports_tree.heading('#0', text='Import')
        self.imports_tree.heading('status', text='Estado')
        self.imports_tree.heading('pypi', text='PyPI')
        self.imports_tree.heading('version', text='Instalada')
        self.imports_tree.heading('latest', text='Última')
        self.imports_tree.heading('locations', text='Archivos')
        
        self.imports_tree.column('#0', width=180)
        self.imports_tree.column('status', width=100)
        self.imports_tree.column('pypi', width=150)
        self.imports_tree.column('version', width=100)
        self.imports_tree.column('latest', width=100)
        self.imports_tree.column('locations', width=80)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.imports_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.imports_tree.xview)
        self.imports_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.imports_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        # Context menu
        self.imports_tree.bind('<Button-3>', self._show_import_context_menu)
        self.imports_tree.bind('<Double-1>', self._show_import_details)
        
        # Tags para colores
        self.imports_tree.tag_configure('stdlib', foreground='gray')
        self.imports_tree.tag_configure('installed', foreground='green')
        self.imports_tree.tag_configure('missing', foreground='red')
        self.imports_tree.tag_configure('vulnerable', foreground='red', background='#ffebee')
    
    def _create_requirements_tab(self):
        """Crea la pestaña de archivos de requerimientos"""
        req_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(req_frame, text="📄 Archivos de Reqs")
        
        req_frame.columnconfigure(0, weight=1)
        req_frame.rowconfigure(0, weight=1)
        
        # Lista de archivos
        list_frame = ttk.Frame(req_frame)
        list_frame.grid(row=0, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        self.req_listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE)
        self.req_listbox.grid(row=0, column=0, sticky="nsew")
        
        req_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.req_listbox.yview)
        self.req_listbox.configure(yscrollcommand=req_scroll.set)
        req_scroll.grid(row=0, column=1, sticky="ns")
        
        # Botones
        btn_frame = ttk.Frame(req_frame)
        btn_frame.grid(row=1, column=0, sticky="ew", pady=5)
        
        ttk.Button(btn_frame, text="👁️ Ver Contenido", command=self._view_req_file).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="📦 Instalar", command=self._install_selected_req).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_frame, text="📊 Analizar", command=self._analyze_req_file).pack(side=tk.LEFT, padx=3)
    
    def _create_installed_tab(self):
        """Crea la pestaña de paquetes instalados"""
        installed_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(installed_frame, text="✅ Instalados")
        
        installed_frame.columnconfigure(0, weight=1)
        installed_frame.rowconfigure(1, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(installed_frame)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Button(toolbar, text="🔄 Refrescar", command=self._refresh_installed_packages).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="⬆️ Actualizar Seleccionado", command=self._upgrade_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="🗑️ Desinstalar", command=self._uninstall_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="❄️ Freeze", command=self._freeze_packages).pack(side=tk.LEFT, padx=3)
        
        self.installed_count_label = ttk.Label(toolbar, text="")
        self.installed_count_label.pack(side=tk.RIGHT, padx=10)
        
        # Treeview
        tree_frame = ttk.Frame(installed_frame)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('version', 'latest', 'status')
        self.installed_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')
        
        self.installed_tree.heading('#0', text='Paquete')
        self.installed_tree.heading('version', text='Versión')
        self.installed_tree.heading('latest', text='Última')
        self.installed_tree.heading('status', text='Estado')
        
        self.installed_tree.column('#0', width=250)
        self.installed_tree.column('version', width=120)
        self.installed_tree.column('latest', width=120)
        self.installed_tree.column('status', width=120)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.installed_tree.yview)
        self.installed_tree.configure(yscrollcommand=vsb.set)
        
        self.installed_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        # Tags
        self.installed_tree.tag_configure('outdated', foreground='orange')
        self.installed_tree.tag_configure('uptodate', foreground='green')
        self.installed_tree.tag_configure('vulnerable', foreground='red', background='#ffebee')
    
    def _create_log_tab(self):
        """Crea la pestaña de log"""
        log_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(log_frame, text="📝 Log")
        
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(log_frame)
        toolbar.grid(row=1, column=0, sticky="ew", pady=5)
        
        ttk.Button(toolbar, text="🗑️ Limpiar", command=self._clear_log).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="💾 Guardar", command=self._save_log).pack(side=tk.LEFT, padx=3)
        
        # Text widget
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        
        # Configurar tags de colores
        colors = self.theme_manager.colors
        self.log_text.tag_configure('info', foreground=colors['fg'])
        self.log_text.tag_configure('success', foreground=colors['success'])
        self.log_text.tag_configure('warning', foreground=colors['warning'])
        self.log_text.tag_configure('error', foreground=colors['error'])
        self.log_text.tag_configure('header', foreground=colors['primary'], font=('Consolas', 10, 'bold'))
    
    def _create_history_tab(self):
        """Crea la pestaña de historial"""
        history_frame = ttk.Frame(self.notebook, padding="5")
        self.notebook.add(history_frame, text="📚 Historial")
        
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Toolbar
        toolbar = ttk.Frame(history_frame)
        toolbar.grid(row=1, column=0, sticky="ew", pady=5)
        
        ttk.Button(toolbar, text="🔄 Refrescar", command=self._refresh_history).pack(side=tk.LEFT, padx=3)
        ttk.Button(toolbar, text="🗑️ Limpiar Historial", command=self._clear_history).pack(side=tk.LEFT, padx=3)
        
        # Treeview
        tree_frame = ttk.Frame(history_frame)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('operation', 'package', 'status', 'details')
        self.history_tree = ttk.Treeview(tree_frame, columns=columns, show='tree headings')
        
        self.history_tree.heading('#0', text='Fecha')
        self.history_tree.heading('operation', text='Operación')
        self.history_tree.heading('package', text='Paquete')
        self.history_tree.heading('status', text='Estado')
        self.history_tree.heading('details', text='Detalles')
        
        self.history_tree.column('#0', width=150)
        self.history_tree.column('operation', width=100)
        self.history_tree.column('package', width=150)
        self.history_tree.column('status', width=80)
        self.history_tree.column('details', width=300)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=vsb.set)
        
        self.history_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        
        # Tags
        self.history_tree.tag_configure('success', foreground='green')
        self.history_tree.tag_configure('error', foreground='red')
    
    def _create_status_bar(self, parent):
        """Crea la barra de estado"""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=5, column=0, sticky="ew", pady=(5, 0))
        status_frame.columnconfigure(1, weight=1)
        
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress.grid(row=0, column=0, padx=5)
        
        self.status_label = ttk.Label(status_frame, text="Listo")
        self.status_label.grid(row=0, column=1, sticky="w", padx=10)
        
        self.python_label = ttk.Label(status_frame, text=f"Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        self.python_label.grid(row=0, column=2, sticky="e", padx=10)
    
    # =========================================================================
    # EVENT HANDLERS
    # =========================================================================
    
    def _on_theme_change(self, event=None):
        """Maneja el cambio de tema"""
        theme = self.theme_combo.get()
        self.settings['theme'] = theme
        self.theme_manager.apply_theme(theme)
        self._save_settings()
        
        # Actualizar colores del log
        colors = self.theme_manager.colors
        self.log_text.configure(bg=colors['surface'], fg=colors['fg'])
        self.log_text.tag_configure('info', foreground=colors['fg'])
        self.log_text.tag_configure('success', foreground=colors['success'])
        self.log_text.tag_configure('warning', foreground=colors['warning'])
        self.log_text.tag_configure('error', foreground=colors['error'])
        self.log_text.tag_configure('header', foreground=colors['primary'])
    
    def _select_project(self):
        """Selecciona la carpeta del proyecto"""
        folder = filedialog.askdirectory(title="Seleccionar carpeta del proyecto")
        if folder:
            self.project_path.set(folder)
            self.status_label.config(text=f"Proyecto: {os.path.basename(folder)}")
            self._log(f"Proyecto seleccionado: {folder}", 'info')
    
    def _detect_venv(self):
        """Detecta el entorno virtual actual"""
        if VenvManager.is_venv_active():
            venv_path = VenvManager.get_venv_path()
            venv_name = os.path.basename(venv_path)
            self.venv_path.set(venv_path)
            self.venv_label.config(text=f"✅ {venv_name}", foreground="green")
            self.current_python = sys.executable
        else:
            self.venv_label.config(text="⚠️ Sistema (sin venv)", foreground="orange")
    
    def _select_venv(self):
        """Selecciona un entorno virtual existente"""
        folder = filedialog.askdirectory(title="Seleccionar entorno virtual")
        if folder and VenvManager.is_valid_venv(folder):
            self.venv_path.set(folder)
            self.current_python = VenvManager.get_python_executable(folder)
            venv_name = os.path.basename(folder)
            self.venv_label.config(text=f"✅ {venv_name}", foreground="green")
            self._log(f"Entorno virtual cambiado: {venv_name}", 'success')
            self._refresh_installed_packages()
        elif folder:
            messagebox.showerror("Error", "La carpeta seleccionada no es un entorno virtual válido")
    
    def _create_venv(self):
        """Crea un nuevo entorno virtual"""
        if not self.project_path.get():
            messagebox.showwarning("Advertencia", "Primero selecciona una carpeta de proyecto")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Crear Entorno Virtual")
        dialog.geometry("400x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Nombre del entorno virtual:").pack(pady=10)
        name_var = tk.StringVar(value="venv")
        ttk.Entry(dialog, textvariable=name_var, width=30).pack(pady=5)
        
        def create():
            name = name_var.get()
            if name:
                path = os.path.join(self.project_path.get(), name)
                
                self.progress.start()
                self.status_label.config(text="Creando entorno virtual...")
                
                def do_create():
                    success, message = VenvManager.create_venv(path)
                    self.root.after(0, lambda: finish_create(success, message, path, name))
                
                def finish_create(success, message, path, name):
                    self.progress.stop()
                    if success:
                        self.venv_path.set(path)
                        self.current_python = VenvManager.get_python_executable(path)
                        self.venv_label.config(text=f"✅ {name}", foreground="green")
                        self._log(f"Entorno virtual creado: {name}", 'success')
                        self._refresh_installed_packages()
                        messagebox.showinfo("Éxito", f"Entorno virtual '{name}' creado")
                    else:
                        self._log(f"Error creando venv: {message}", 'error')
                        messagebox.showerror("Error", message)
                    self.status_label.config(text="Listo")
                
                threading.Thread(target=do_create, daemon=True).start()
            dialog.destroy()
        
        ttk.Button(dialog, text="Crear", command=create).pack(pady=10)
    
    def _show_venv_info(self):
        """Muestra información del entorno virtual"""
        if not self.venv_path.get():
            messagebox.showinfo("Info", "No hay entorno virtual seleccionado")
            return
        
        info = VenvManager.get_venv_info(self.venv_path.get())
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Información del Entorno Virtual")
        dialog.geometry("500x200")
        dialog.transient(self.root)
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text.insert(tk.END, f"📁 Ruta: {info['path']}\n\n")
        text.insert(tk.END, f"🐍 Python: {info.get('python_version', 'N/A')}\n\n")
        text.insert(tk.END, f"📦 Ejecutable: {info['python']}\n\n")
        text.insert(tk.END, f"✅ Válido: {'Sí' if info['valid'] else 'No'}\n")
        
        text.config(state='disabled')
    
    def _scan_project(self):
        """Escanea el proyecto en busca de imports"""
        if not self.project_path.get():
            messagebox.showwarning("Advertencia", "Selecciona una carpeta de proyecto primero")
            return
        
        self.progress.start()
        self.status_label.config(text="Escaneando proyecto...")
        self._log("\n" + "="*50, 'header')
        self._log("Iniciando escaneo de proyecto...", 'header')
        
        def scan():
            try:
                self.scanner.reset()
                self.package_infos.clear()
                
                project_path = Path(self.project_path.get())
                
                def progress_cb(current, total, filename):
                    self.root.after(0, lambda: self.status_label.config(
                        text=f"Escaneando: {filename} ({current}/{total})"
                    ))
                
                results = self.scanner.scan_directory(project_path, progress_callback=progress_cb)
                
                # Buscar archivos de requerimientos
                self.requirements_files.clear()
                req_patterns = ['requirements*.txt', 'setup.py', 'setup.cfg', 
                               'pyproject.toml', 'Pipfile', 'environment.yml']
                
                for pattern in req_patterns:
                    for f in project_path.rglob(pattern):
                        self.requirements_files.append(f)
                
                # Actualizar UI
                self.root.after(0, lambda: self._finish_scan(results))
                
            except Exception as e:
                self.root.after(0, lambda: self._handle_scan_error(e))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def _finish_scan(self, results: Dict):
        """Finaliza el escaneo y actualiza la UI"""
        self.progress.stop()
        
        # Limpiar árboles
        self.imports_tree.delete(*self.imports_tree.get_children())
        self.req_listbox.delete(0, tk.END)
        
        # Actualizar lista de archivos de requerimientos
        for f in self.requirements_files:
            rel_path = f.relative_to(self.project_path.get())
            self.req_listbox.insert(tk.END, str(rel_path))
        
        # Procesar imports
        total_imports = len(self.scanner.found_imports)
        third_party = self.scanner.get_third_party_imports()
        missing_count = 0
        
        for imp in sorted(self.scanner.found_imports):
            if self.scanner.is_stdlib(imp):
                status = PackageStatus.STDLIB
                version = "-"
                pypi_name = "-"
            else:
                pypi_name = self.scanner.get_pypi_name(imp)
                
                if pypi_name.lower() in self.installed_packages:
                    status = PackageStatus.INSTALLED
                    version = self.installed_packages[pypi_name.lower()]
                elif imp.lower() in self.installed_packages:
                    status = PackageStatus.INSTALLED
                    version = self.installed_packages[imp.lower()]
                else:
                    status = PackageStatus.MISSING
                    version = "-"
                    missing_count += 1
            
            # Guardar info del paquete
            pkg_info = PackageInfo(
                import_name=imp,
                pypi_name=pypi_name,
                status=status,
                version=version if version != "-" else None
            )
            self.package_infos[imp] = pkg_info
            
            # Determinar tag
            if status == PackageStatus.STDLIB:
                tag = 'stdlib'
                status_text = "📚 Stdlib"
            elif status == PackageStatus.INSTALLED:
                tag = 'installed'
                status_text = "✅ Instalado"
            else:
                tag = 'missing'
                status_text = "❌ Faltante"
            
            locations = len(self.scanner.import_locations.get(imp, []))
            
            self.imports_tree.insert('', 'end', text=imp,
                                    values=(status_text, pypi_name, version, "-", locations),
                                    tags=(tag,))
        
        # Registrar escaneo en historial
        self.history.log_scan(
            self.project_path.get(),
            len(results),
            total_imports,
            missing_count
        )
        
        # Actualizar estadísticas
        self.stats_label.config(
            text=f"Total: {total_imports} | Terceros: {len(third_party)} | Faltantes: {missing_count}"
        )
        
        # Aplicar filtro inicial
        self._filter_imports()
        
        # Log
        self._log(f"Escaneo completado:", 'success')
        self._log(f"  • Archivos Python: {len(results)}", 'info')
        self._log(f"  • Imports únicos: {total_imports}", 'info')
        self._log(f"  • Paquetes de terceros: {len(third_party)}", 'info')
        self._log(f"  • Paquetes faltantes: {missing_count}", 'warning' if missing_count > 0 else 'info')
        self._log(f"  • Archivos de reqs: {len(self.requirements_files)}", 'info')
        
        if self.scanner.errors:
            self._log(f"\n⚠️ Errores durante el escaneo:", 'warning')
            for err in self.scanner.errors[:5]:
                self._log(f"  • {err}", 'warning')
        
        self.status_label.config(text=f"Escaneo completado: {total_imports} imports encontrados")
    
    def _handle_scan_error(self, error: Exception):
        """Maneja errores durante el escaneo"""
        self.progress.stop()
        self._log(f"Error durante el escaneo: {error}", 'error')
        self._log(traceback.format_exc(), 'error')
        self.status_label.config(text="Error durante el escaneo")
        messagebox.showerror("Error", f"Error durante el escaneo:\n{error}")
    
    def _filter_imports(self, *args):
        """Filtra los imports mostrados"""
        filter_text = self.filter_var.get().lower()
        show_stdlib = self.show_stdlib.get()
        show_installed = self.show_installed.get()
        
        # Obtener todos los items
        all_items = list(self.imports_tree.get_children())
        
        for item in all_items:
            text = self.imports_tree.item(item, 'text').lower()
            tags = self.imports_tree.item(item, 'tags')
            
            show = True
            
            # Filtro de texto
            if filter_text and filter_text not in text:
                show = False
            
            # Filtro de stdlib
            if 'stdlib' in tags and not show_stdlib:
                show = False
            
            # Filtro de instalados
            if 'installed' in tags and not show_installed:
                show = False
            
            if show:
                self.imports_tree.reattach(item, '', 'end')
            else:
                self.imports_tree.detach(item)
    
    def _show_import_context_menu(self, event):
        """Muestra el menú contextual para un import"""
        item = self.imports_tree.identify_row(event.y)
        if not item:
            return
        
        self.imports_tree.selection_set(item)
        
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="📦 Instalar", command=self._install_selected_import)
        menu.add_command(label="ℹ️ Ver Detalles", command=self._show_import_details)
        menu.add_command(label="🌐 Ver en PyPI", command=self._open_pypi_page)
        menu.add_separator()
        menu.add_command(label="📋 Copiar nombre", command=lambda: self._copy_to_clipboard(
            self.imports_tree.item(item, 'text')
        ))
        
        menu.tk_popup(event.x_root, event.y_root)
    
    def _show_import_details(self, event=None):
        """Muestra detalles de un import"""
        selection = self.imports_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        import_name = self.imports_tree.item(item, 'text')
        values = self.imports_tree.item(item, 'values')
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Detalles: {import_name}")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text.insert(tk.END, f"📦 Import: {import_name}\n\n")
        text.insert(tk.END, f"Estado: {values[0]}\n")
        text.insert(tk.END, f"PyPI: {values[1]}\n")
        text.insert(tk.END, f"Versión instalada: {values[2]}\n\n")
        
        # Ubicaciones
        locations = self.scanner.import_locations.get(import_name, [])
        if locations:
            text.insert(tk.END, f"📁 Usado en {len(locations)} archivo(s):\n")
            for loc in locations[:10]:
                rel_path = Path(loc).relative_to(self.project_path.get()) if self.project_path.get() else loc
                text.insert(tk.END, f"  • {rel_path}\n")
            if len(locations) > 10:
                text.insert(tk.END, f"  ... y {len(locations) - 10} más\n")
        
        # Información de PyPI
        text.insert(tk.END, "\n🌐 Obteniendo información de PyPI...\n")
        
        def fetch_pypi():
            pypi_name = values[1] if values[1] != "-" else import_name
            info = self.pypi_client.get_package_info(pypi_name)
            
            def update():
                if info and info.get('exists'):
                    text.insert(tk.END, f"\nℹ️ Información de PyPI:\n")
                    text.insert(tk.END, f"  Nombre: {info.get('name', 'N/A')}\n")
                    text.insert(tk.END, f"  Última versión: {info.get('version', 'N/A')}\n")
                    text.insert(tk.END, f"  Descripción: {info.get('summary', 'N/A')}\n")
                    text.insert(tk.END, f"  Autor: {info.get('author', 'N/A')}\n")
                    text.insert(tk.END, f"  Licencia: {info.get('license', 'N/A')}\n")
                    text.insert(tk.END, f"  Python requerido: {info.get('requires_python', 'N/A')}\n")
                else:
                    text.insert(tk.END, f"\n⚠️ No se encontró en PyPI\n")
            
            self.root.after(0, update)
        
        threading.Thread(target=fetch_pypi, daemon=True).start()
        
        text.config(state='disabled')
    
    def _install_selected_import(self):
        """Instala el import seleccionado"""
        selection = self.imports_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.imports_tree.item(item, 'values')
        pypi_name = values[1]
        
        if pypi_name == "-":
            pypi_name = self.imports_tree.item(item, 'text')
        
        self._install_package(pypi_name)
    
    def _open_pypi_page(self):
        """Abre la página de PyPI del paquete seleccionado"""
        import webbrowser
        
        selection = self.imports_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        values = self.imports_tree.item(item, 'values')
        pypi_name = values[1]
        
        if pypi_name == "-":
            pypi_name = self.imports_tree.item(item, 'text')
        
        webbrowser.open(f"https://pypi.org/project/{pypi_name}/")
    
    def _copy_to_clipboard(self, text: str):
        """Copia texto al portapapeles"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
    
    def _install_missing(self):
        """Instala todos los paquetes faltantes"""
        missing = []
        
        for item in self.imports_tree.get_children():
            tags = self.imports_tree.item(item, 'tags')
            if 'missing' in tags:
                values = self.imports_tree.item(item, 'values')
                pypi_name = values[1]
                if pypi_name != "-":
                    missing.append(pypi_name)
        
        if not missing:
            messagebox.showinfo("Info", "No hay paquetes faltantes para instalar")
            return
        
        if not messagebox.askyesno("Confirmar", f"¿Instalar {len(missing)} paquetes faltantes?"):
            return
        
        self._install_packages(missing)
    
    def _install_package(self, package: str):
        """Instala un paquete"""
        self._install_packages([package])
    
    def _install_packages(self, packages: List[str]):
        """Instala múltiples paquetes"""
        self.progress.start()
        self.status_label.config(text=f"Instalando {len(packages)} paquetes...")
        self._log(f"\n📦 Instalando {len(packages)} paquetes...", 'header')
        
        installer = PackageInstaller(self.current_python, self.history)
        
        def install():
            success_count = 0
            
            for pkg in packages:
                self.root.after(0, lambda p=pkg: self.status_label.config(text=f"Instalando: {p}"))
                self.root.after(0, lambda p=pkg: self._log(f"  Instalando {p}...", 'info'))
                
                success, output = installer.install(pkg)
                
                if success:
                    success_count += 1
                    self.root.after(0, lambda p=pkg: self._log(f"    ✅ {p} instalado", 'success'))
                else:
                    self.root.after(0, lambda p=pkg, o=output: self._log(f"    ❌ Error: {o[:100]}", 'error'))
            
            self.root.after(0, lambda: self._finish_install(success_count, len(packages)))
        
        threading.Thread(target=install, daemon=True).start()
    
    def _finish_install(self, success: int, total: int):
        """Finaliza la instalación"""
        self.progress.stop()
        self.status_label.config(text=f"Instalación completada: {success}/{total}")
        
        self._log(f"\n✅ Instalación completada: {success}/{total} paquetes", 
                 'success' if success == total else 'warning')
        
        if success > 0:
            self._refresh_installed_packages()
            # Re-escanear para actualizar estados
            if self.project_path.get():
                self._scan_project()
    
    def _install_from_file(self):
        """Instala desde un archivo de requerimientos"""
        file_path = filedialog.askopenfilename(
            title="Seleccionar archivo de requerimientos",
            filetypes=[
                ("Archivos de requerimientos", "*.txt"),
                ("Pipfile", "Pipfile"),
                ("pyproject.toml", "*.toml"),
                ("YAML", "*.yml;*.yaml"),
                ("Todos", "*.*")
            ]
        )
        
        if file_path:
            self.progress.start()
            self.status_label.config(text=f"Instalando desde {os.path.basename(file_path)}...")
            
            installer = PackageInstaller(self.current_python, self.history)
            
            def install():
                success, output = installer.install_from_requirements(file_path)
                
                def finish():
                    self.progress.stop()
                    if success:
                        self._log(f"✅ Instalación desde archivo completada", 'success')
                        self._log(output, 'info')
                        self.status_label.config(text="Instalación completada")
                        self._refresh_installed_packages()
                    else:
                        self._log(f"❌ Error: {output}", 'error')
                        self.status_label.config(text="Error en instalación")
                
                self.root.after(0, finish)
            
            threading.Thread(target=install, daemon=True).start()
    
    def _update_all(self):
        """Actualiza todos los paquetes"""
        outdated = PackageInstaller(self.current_python).get_outdated_packages()
        
        if not outdated:
            messagebox.showinfo("Info", "Todos los paquetes están actualizados")
            return
        
        msg = f"Se encontraron {len(outdated)} paquetes desactualizados:\n\n"
        for pkg in outdated[:10]:
            msg += f"• {pkg['name']}: {pkg['version']} → {pkg['latest_version']}\n"
        if len(outdated) > 10:
            msg += f"\n... y {len(outdated) - 10} más"
        msg += "\n\n¿Actualizar todos?"
        
        if not messagebox.askyesno("Actualizar paquetes", msg):
            return
        
        packages = [pkg['name'] for pkg in outdated]
        
        self.progress.start()
        self.status_label.config(text="Actualizando paquetes...")
        self._log(f"\n⬆️ Actualizando {len(packages)} paquetes...", 'header')
        
        installer = PackageInstaller(self.current_python, self.history)
        
        def update():
            success_count = 0
            
            for pkg in packages:
                self.root.after(0, lambda p=pkg: self.status_label.config(text=f"Actualizando: {p}"))
                
                success, _ = installer.install(pkg, upgrade=True)
                if success:
                    success_count += 1
                    self.root.after(0, lambda p=pkg: self._log(f"  ✅ {p} actualizado", 'success'))
                else:
                    self.root.after(0, lambda p=pkg: self._log(f"  ❌ Error actualizando {p}", 'error'))
            
            self.root.after(0, lambda: self._finish_update(success_count, len(packages)))
        
        threading.Thread(target=update, daemon=True).start()
    
    def _finish_update(self, success: int, total: int):
        """Finaliza la actualización"""
        self.progress.stop()
        self.status_label.config(text=f"Actualización completada: {success}/{total}")
        self._log(f"\n✅ Actualización completada: {success}/{total}", 
                 'success' if success == total else 'warning')
        self._refresh_installed_packages()
    
    def _check_security(self):
        """Verifica vulnerabilidades de seguridad"""
        self.progress.start()
        self.status_label.config(text="Verificando vulnerabilidades...")
        self._log("\n🛡️ Verificando vulnerabilidades de seguridad...", 'header')
        
        def check():
            if not self.vuln_checker.load_database():
                self.root.after(0, lambda: self._log("  ⚠️ No se pudo cargar la base de datos de vulnerabilidades", 'warning'))
                self.root.after(0, lambda: self.progress.stop())
                return
            
            vulnerable_packages = []
            
            for name, version in self.installed_packages.items():
                vulns = self.vuln_checker.check_package(name, version)
                if vulns:
                    vulnerable_packages.append((name, version, vulns))
            
            self.root.after(0, lambda: self._finish_security_check(vulnerable_packages))
        
        threading.Thread(target=check, daemon=True).start()
    
    def _finish_security_check(self, vulnerable: List[Tuple]):
        """Finaliza la verificación de seguridad"""
        self.progress.stop()
        
        if not vulnerable:
            self._log("  ✅ No se encontraron vulnerabilidades conocidas", 'success')
            self.status_label.config(text="Sin vulnerabilidades conocidas")
            messagebox.showinfo("Seguridad", "No se encontraron vulnerabilidades conocidas")
        else:
            self._log(f"  ⚠️ Se encontraron {len(vulnerable)} paquetes vulnerables:", 'warning')
            
            for name, version, vulns in vulnerable:
                self._log(f"\n  📦 {name} ({version}):", 'error')
                for v in vulns[:3]:
                    self._log(f"    • {v['id']}: {v['advisory'][:100]}...", 'error')
            
            self.status_label.config(text=f"⚠️ {len(vulnerable)} vulnerabilidades encontradas")
            
            # Actualizar árbol de instalados
            for item in self.installed_tree.get_children():
                pkg_name = self.installed_tree.item(item, 'text').lower()
                if any(v[0].lower() == pkg_name for v in vulnerable):
                    self.installed_tree.item(item, tags=('vulnerable',))
            
            messagebox.showwarning(
                "Vulnerabilidades encontradas",
                f"Se encontraron {len(vulnerable)} paquetes con vulnerabilidades conocidas.\n"
                "Revisa el log para más detalles."
            )
    
    def _view_req_file(self):
        """Muestra el contenido de un archivo de requerimientos"""
        selection = self.req_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Selecciona un archivo")
            return
        
        file_path = self.requirements_files[selection[0]]
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Contenido: {file_path.name}")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        try:
            content = file_path.read_text(encoding='utf-8')
            text.insert(tk.END, content)
        except Exception as e:
            text.insert(tk.END, f"Error: {e}")
        
        text.config(state='disabled')
    
    def _install_selected_req(self):
        """Instala desde el archivo de requerimientos seleccionado"""
        selection = self.req_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Selecciona un archivo")
            return
        
        file_path = str(self.requirements_files[selection[0]])
        
        self.progress.start()
        self.status_label.config(text=f"Instalando desde {Path(file_path).name}...")
        
        installer = PackageInstaller(self.current_python, self.history)
        
        def install():
            success, output = installer.install_from_requirements(file_path)
            
            def finish():
                self.progress.stop()
                if success:
                    self._log(f"✅ Instalación completada", 'success')
                    self.status_label.config(text="Instalación completada")
                    self._refresh_installed_packages()
                else:
                    self._log(f"❌ Error: {output}", 'error')
                    self.status_label.config(text="Error en instalación")
            
            self.root.after(0, finish)
        
        threading.Thread(target=install, daemon=True).start()
    
    def _analyze_req_file(self):
        """Analiza un archivo de requerimientos"""
        selection = self.req_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Selecciona un archivo")
            return
        
        file_path = self.requirements_files[selection[0]]
        
        # Determinar tipo y parsear
        if file_path.name == 'Pipfile':
            packages = RequirementsParser.parse_pipfile(file_path)
        elif file_path.suffix == '.toml':
            packages = RequirementsParser.parse_pyproject_toml(file_path)
        elif file_path.suffix in ['.yml', '.yaml']:
            packages = RequirementsParser.parse_conda_yaml(file_path)
        elif file_path.name == 'setup.py':
            packages = RequirementsParser.parse_setup_py(file_path)
        elif file_path.name == 'setup.cfg':
            packages = RequirementsParser.parse_setup_cfg(file_path)
        else:
            packages = RequirementsParser.parse_requirements_txt(file_path)
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Análisis: {file_path.name}")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text.insert(tk.END, f"📄 Archivo: {file_path.name}\n")
        text.insert(tk.END, f"📦 Paquetes encontrados: {len(packages)}\n\n")
        
        installed_count = 0
        missing_count = 0
        
        for pkg in packages:
            name = pkg['name']
            spec = pkg.get('specifier', '')
            
            if name.lower() in self.installed_packages:
                status = "✅"
                installed_count += 1
                version = self.installed_packages[name.lower()]
            else:
                status = "❌"
                missing_count += 1
                version = "no instalado"
            
            text.insert(tk.END, f"{status} {name}{spec} (actual: {version})\n")
        
        text.insert(tk.END, f"\n📊 Resumen:\n")
        text.insert(tk.END, f"  • Instalados: {installed_count}\n")
        text.insert(tk.END, f"  • Faltantes: {missing_count}\n")
        
        text.config(state='disabled')
    
    def _refresh_installed_packages(self):
        """Refresca la lista de paquetes instalados"""
        self.progress.start()
        self.status_label.config(text="Obteniendo paquetes instalados...")
        
        installer = PackageInstaller(self.current_python)
        
        def refresh():
            self.installed_packages = installer.get_installed_packages()
            outdated = installer.get_outdated_packages()
            outdated_dict = {p['name'].lower(): p for p in outdated}
            
            self.root.after(0, lambda: self._update_installed_tree(outdated_dict))
        
        threading.Thread(target=refresh, daemon=True).start()
    
    def _update_installed_tree(self, outdated_dict: Dict):
        """Actualiza el árbol de paquetes instalados"""
        self.progress.stop()
        self.installed_tree.delete(*self.installed_tree.get_children())
        
        for name, version in sorted(self.installed_packages.items()):
            if name.lower() in outdated_dict:
                latest = outdated_dict[name.lower()]['latest_version']
                status = "⬆️ Actualizable"
                tag = 'outdated'
            else:
                latest = version
                status = "✅ Actualizado"
                tag = 'uptodate'
            
            self.installed_tree.insert('', 'end', text=name,
                                       values=(version, latest, status),
                                       tags=(tag,))
        
        self.installed_count_label.config(text=f"Total: {len(self.installed_packages)}")
        self.status_label.config(text=f"{len(self.installed_packages)} paquetes instalados")
    
    def _upgrade_selected(self):
        """Actualiza el paquete seleccionado"""
        selection = self.installed_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Selecciona un paquete")
            return
        
        pkg_name = self.installed_tree.item(selection[0], 'text')
        
        self.progress.start()
        self.status_label.config(text=f"Actualizando {pkg_name}...")
        
        installer = PackageInstaller(self.current_python, self.history)
        
        def upgrade():
            success, output = installer.install(pkg_name, upgrade=True)
            
            def finish():
                self.progress.stop()
                if success:
                    self._log(f"✅ {pkg_name} actualizado", 'success')
                    self._refresh_installed_packages()
                else:
                    self._log(f"❌ Error: {output}", 'error')
                self.status_label.config(text="Listo")
            
            self.root.after(0, finish)
        
        threading.Thread(target=upgrade, daemon=True).start()
    
    def _uninstall_selected(self):
        """Desinstala el paquete seleccionado"""
        selection = self.installed_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Selecciona un paquete")
            return
        
        pkg_name = self.installed_tree.item(selection[0], 'text')
        
        if not messagebox.askyesno("Confirmar", f"¿Desinstalar {pkg_name}?"):
            return
        
        self.progress.start()
        self.status_label.config(text=f"Desinstalando {pkg_name}...")
        
        installer = PackageInstaller(self.current_python, self.history)
        
        def uninstall():
            success, output = installer.uninstall(pkg_name)
            
            def finish():
                self.progress.stop()
                if success:
                    self._log(f"✅ {pkg_name} desinstalado", 'success')
                    self._refresh_installed_packages()
                else:
                    self._log(f"❌ Error: {output}", 'error')
                self.status_label.config(text="Listo")
            
            self.root.after(0, finish)
        
        threading.Thread(target=uninstall, daemon=True).start()
    
    def _freeze_packages(self):
        """Genera un freeze de las dependencias"""
        installer = PackageInstaller(self.current_python)
        freeze_output = installer.freeze()
        
        if not freeze_output:
            messagebox.showinfo("Info", "No hay paquetes instalados")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile="requirements-frozen.txt"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(f"# Frozen requirements generated by {APP_NAME}\n")
                    f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write(freeze_output)
                
                self._log(f"✅ Freeze guardado: {file_path}", 'success')
                messagebox.showinfo("Éxito", f"Archivo guardado:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {e}")
    
    def _export_requirements(self):
        """Exporta las dependencias al formato seleccionado"""
        if not self.scanner.found_imports:
            messagebox.showinfo("Info", "Primero escanea un proyecto")
            return
        
        format_type = self.export_format.get()
        
        # Recopilar paquetes
        packages = []
        for imp, info in self.package_infos.items():
            if info.status != PackageStatus.STDLIB and info.pypi_name != "-":
                packages.append({
                    'name': info.pypi_name,
                    'version': info.version
                })
        
        if not packages:
            messagebox.showinfo("Info", "No hay paquetes externos para exportar")
            return
        
        # Generar contenido
        project_name = os.path.basename(self.project_path.get()) if self.project_path.get() else "my-project"
        
        if format_type == 'requirements.txt':
            content = RequirementsExporter.to_requirements_txt(packages)
            ext = ".txt"
            filename = "requirements.txt"
        elif format_type == 'Pipfile':
            content = RequirementsExporter.to_pipfile(packages)
            ext = ""
            filename = "Pipfile"
        elif format_type == 'pyproject.toml':
            content = RequirementsExporter.to_pyproject_toml(packages, project_name)
            ext = ".toml"
            filename = "pyproject.toml"
        elif format_type == 'poetry':
            content = RequirementsExporter.to_poetry_pyproject(packages, project_name)
            ext = ".toml"
            filename = "pyproject.toml"
        else:
            return
        
        # Guardar archivo
        file_path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[("All files", "*.*")],
            initialfile=filename
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                
                self._log(f"✅ Archivo exportado: {file_path}", 'success')
                messagebox.showinfo("Éxito", f"Archivo exportado:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al exportar: {e}")
    
    def _refresh_history(self):
        """Refresca el historial"""
        self.history_tree.delete(*self.history_tree.get_children())
        
        operations = self.history.get_recent_operations(100)
        
        for op in operations:
            timestamp, operation, package, status, details = op
            
            # Formatear timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M")
            except:
                formatted_time = timestamp[:16]
            
            tag = 'success' if status == 'success' else 'error'
            
            self.history_tree.insert('', 'end', text=formatted_time,
                                    values=(operation, package or '-', status, details[:50]),
                                    tags=(tag,))
    
    def _clear_history(self):
        """Limpia el historial"""
        if messagebox.askyesno("Confirmar", "¿Limpiar todo el historial?"):
            self.history.clear_history()
            self.history_tree.delete(*self.history_tree.get_children())
            self._log("Historial limpiado", 'info')
    
    def _log(self, message: str, level: str = 'info'):
        """Agrega un mensaje al log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.log_text.insert(tk.END, f"[{timestamp}] ", 'info')
        self.log_text.insert(tk.END, f"{message}\n", level)
        self.log_text.see(tk.END)
    
    def _clear_log(self):
        """Limpia el log"""
        self.log_text.delete('1.0', tk.END)
    
    def _save_log(self):
        """Guarda el log a un archivo"""
        content = self.log_text.get('1.0', tk.END)
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Éxito", f"Log guardado:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar: {e}")


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    """Función principal"""
    # Instalar dependencias necesarias
    required = ['toml']
    
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            print(f"Instalando dependencia: {pkg}")
            subprocess.run([sys.executable, "-m", "pip", "install", pkg], 
                          capture_output=True)
    
    # Crear ventana principal
    root = tk.Tk()
    
    # Establecer icono si existe
    try:
        if platform.system() == "Windows":
            root.iconbitmap(default='')
    except:
        pass
    
    # Crear aplicación
    app = RequirementsInstallerPro(root)
    
    # Ejecutar
    root.mainloop()


if __name__ == "__main__":
    main()
