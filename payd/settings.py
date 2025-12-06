from os import getenv
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(".env")

SECRET_KEY = getenv("SECRET_KEY")
DEBUG = getenv("DEBUG", "True") == "True"
ALLOWED_HOSTS = getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'payd.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'payd.wsgi.application'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": getenv("DB_NAME"),
        "USER": getenv("DB_USER"),
        "PASSWORD": getenv("DB_PASSWORD"),
        "HOST": getenv("DB_HOST", "localhost"),
        "PORT": getenv("DB_PORT", "5432"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'

AUTH_USER_MODEL = "api.User"

GOOGLE_CLIENT_ID = getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = getenv("GOOGLE_REDIRECT_URI")
PAYSTACK_SECRET_KEY = getenv("PAYSTACK_SECRET_KEY")
PAYSTACK_PUBLIC_KEY = getenv("PAYSTACK_PUBLIC_KEY")
PAYSTACK_WEBHOOK_SECRET = getenv("PAYSTACK_WEBHOOK_SECRET")

REQUIRED_SETTINGS = {
    "SECRET_KEY": SECRET_KEY,
    "DB_NAME": DATABASES["default"]["NAME"],
    "DB_USER": DATABASES["default"]["USER"],
    "DB_PASSWORD": DATABASES["default"]["PASSWORD"],
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET,
    "GOOGLE_REDIRECT_URI": GOOGLE_REDIRECT_URI,
    "PAYSTACK_SECRET_KEY": PAYSTACK_SECRET_KEY,
    "PAYSTACK_PUBLIC_KEY": PAYSTACK_PUBLIC_KEY,
    "PAYSTACK_WEBHOOK_SECRET": PAYSTACK_WEBHOOK_SECRET,
}

missing_settings = [key for key, value in REQUIRED_SETTINGS.items() if not value]
if missing_settings:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured(
        f"Missing required environment variables: {', '.join(missing_settings)}"
    )

if not DEBUG:
    if GOOGLE_REDIRECT_URI and not GOOGLE_REDIRECT_URI.startswith("https://"):
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            "GOOGLE_REDIRECT_URI must use HTTPS in production."
        )

GOOGLE_OAUTH_CLIENT_ID = GOOGLE_CLIENT_ID
GOOGLE_OAUTH_CLIENT_SECRET = GOOGLE_CLIENT_SECRET
GOOGLE_OAUTH_REDIRECT_URI = GOOGLE_REDIRECT_URI

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "payd.log",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "api": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
