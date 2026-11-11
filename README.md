# AEGIS AI Security

<p align="center">
  <img src="apps/desktop/public/logo.png" alt="AEGIS AI Security Logo" width="160" />
</p>

<p align="center">
  <strong>Yeni Nesil Yerel Uç Nokta Koruması & AI Destekli Antivirüs Paketi (Windows 10/11)</strong><br />
  <em>Next-Generation Local-First Endpoint Protection & AI Antivirus for Windows 10/11</em>
</p>

<p align="center">
  <a href="https://github.com/Kaankrl/AEGIS-Anti-Virus-AI/releases/latest"><img src="https://img.shields.io/badge/Download-AEGIS%20Setup%20v0.1.0-cyan?style=for-the-badge&logo=windows" alt="Download AEGIS Setup" /></a>
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(64--bit)-blue?style=for-the-badge&logo=windows" alt="Platform Windows 10/11" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary%20%2F%20AegisVerse-purple?style=for-the-badge" alt="License" /></a>
  <img src="https://img.shields.io/badge/VirusTotal-0%2F70%20Clean-brightgreen?style=for-the-badge&logo=virustotal" alt="VirusTotal Clean" />
</p>

---

## ⬇️ İndirme ve Kurulum (Download Official Release)

AEGIS AI Security'yi hemen bilgisayarınıza kurup yeni nesil korumayı başlatabilirsiniz:

| Paket / İndirme Linki | Tür | Boyut | Açıklama |
|---|---|---|---|
| 🚀 **[AEGIS AI Security Setup 0.1.0.exe](https://github.com/Kaankrl/AEGIS-Anti-Virus-AI/releases/latest/download/AEGIS.AI.Security.Setup.0.1.0.exe)** | **Resmi Windows Kurulum Sihirbazı** | ~130 MB | Lisans onaylı, saydam logolu açılış ve masaüstü kısayollu otomatik resmi kurulum. |

> 🛡️ **Web Kalkanı & Reklam Engelleyici:**  
> Tarayıcı koruma eklentisi (Brave, Chrome, Edge için YouTube reklam atlayıcı ve zararlı link kalkanı) uygulama ile birlikte otomatik olarak gelir; AEGIS masaüstü uygulamasının içinden doğrudan tek tıkla aktif edilebilir.
> 
> 🔒 **Dosya Bütünlüğü Doğrulama (SHA-256 Checksum):**  
> `0D9930E8C2BE5961FD06ED61A3E85B522C2DE5663301E324C354EEC4AE5F6D13`

---

## 🚨 HUKUKİ YASAL UYARI & ANTİ-PİRASİ BİLDİRİMİ (LEGAL NOTICE)

> [!WARNING]
> ### ⚖️ FİKRİ MÜLKİYET VE TELİF HAKKI KORUMASI (AEGISVERSE)
> Bu projenin tüm kaynak kodları, arayüz tasarımları, markası, logoları, yapay zeka analiz modelleri ve antivirüs motoru **AegisVerse** mülkiyetindedir.
> 
> **BU DEPO NEDEN AÇIK PAYLAŞILDI?**  
> Siber güvenlik platformunda yeni bir yerli proje olduğumuz için kullanıcılarımızın ve bağımsız güvenlik araştırmacılarının **projede hiçbir gizli arka kapı, casus yazılım (spyware) veya veri sızıntısı olmadığını bizzat denetleyebilmesi ve %100 güvenebilmesi** amacıyla şeffaflık ilkemiz gereği halka açık sunulmuştur.
>
> **KESİNLİKLE YASAK OLAN EYLEMLER:**
> 1. Bu projenin kodlarını kopyalamak, çalmak, adını/logosunu değiştirip kendi adına yeniden dağıtmak (**Rebranding / Cloning**).
> 2. Projeyi ücretli ya da ücretsiz satmak, ticari bir ürün haline getirmek veya ticari platformlara lisanssız entegre etmek.
>
> 🛑 **HUKUKİ YAPTIRIMLAR:**  
> Herhangi bir yetkisiz kopyalama, forklayıp isim değiştirme veya ticari sömürü tespit edildiğinde; **WIPO, Berne Konvansiyonu ve DMCA (Digital Millennium Copyright Act)** kapsamında anında tüm küresel platformlardan kaldırtma (Global Takedown) uygulanacak ve yetkili mahkemelerde maddi/manevi tazminat davaları açılacaktır. Detaylar için lütfen **[LICENSE](LICENSE)** metnini inceleyiniz.

---

## 🛡️ Proje Mimarisi ve Koruma Katmanları

AEGIS, arka planda hiçbir bulut aboneliğine veya sunucuya ihtiyaç duymadan **tamamen yerel makinenizde** çalışan çok katmanlı bir uç nokta koruma sistemidir:

```
       +-----------------------------------------------------------+
       |           AEGIS AI Security Desktop UI (React 19)         |
       +-----------------------------------------------------------+
                                   | IPC Köprüsü
       +-----------------------------------------------------------+
       |            AEGIS Arka Plan Servisi / Çekirdek Motor       |
       |  - YARA-X Kural Motoru     - Gerçek Zamanlı Dosya İzleyici|
       |  - PE Sezgisel Analizi     - Fidye Yazılımı Kalkanı       |
       |  - RAT & Casus Avcısı      - Ağ ve Soket Denetçisi        |
       |  - Başlangıç Koruyucusu    - USB ve Çıkarılabilir Bellek  |
       |  - Şifreli Karantina       - YouTube & Web Reklam Kalkanı |
       |  - Yerel AI Analisti       - Windows Defender Tam Uyum    |
       +-----------------------------------------------------------+
```

---

## ⚡ Temel Koruma Yetenekleri

| Koruma Katmanı | Teknoloji & Mimari | Açıklama |
|---|---|---|
| **Çoklu Motor Tarayıcı** | YARA-X, PE Analizi, Hash | ZIP arşiv içi tarama, bellek sınırlandırmalı yüksek hızlı dosya taraması. |
| **Gerçek Zamanlı Kalkan** | Windows `ReadDirectoryChangesW` | Kritik sistem dizinlerine yazılan zararlıları anında yakalar. |
| **Fidye Yazılımı Kalkanı** | 5 Saniyelik Kayan Pencere Algoritması | Kısa sürede çok sayıda dosyayı şifrelemeye çalışan süreçleri bloke eder. |
| **RAT & Casus Yazılım Avcısı** | Süreç Hiyerarşisi & LOLBins | Tarayıcı veya Office üzerinden `powershell.exe`/`cmd.exe` açılmasını engeller. |
| **Web & YouTube Kalkanı** | Manifest V3 Eklentisi & Network Rules | YouTube video reklamlarını 0ms sessiz atlar, izinsiz açılan sekmeleri kapatır. |
| **Ağ ve Port Denetimi** | `GetExtendedTcpTable` Soket Eşleme | Hangi programın hangi IP ve porta bağlandığını gerçek zamanlı denetler. |
| **Başlangıç Koruyucusu** | Kayıt Defteri (Registry) Kalkanı | Windows başlangıcına eklenen bilinmeyen kayıtları tespit edip raporlar. |
| **USB Güvenliği** | `DRIVE_REMOVABLE` Bildirimi | Takılan flash belleklerdeki `autorun.inf` ve gizli scriptleri yakalar. |
| **Güvenli Karantina** | 32-Byte Anahtarlı XOR Şifreleme | Yakalanan zararlıyı şifreleyerek etkisiz hale getirir, güvenli geri yükleme sunar. |
| **Defender ile Tam Uyum** | Windows Güvenlik Merkezi Entegrasyonu | Microsoft Defender'ı kapatmaz, Windows ile çakışmadan tam uyum içinde çalışır. |

---

## 🤝 Windows Defender ile Güvenli Birlikte Çalışma

AEGIS AI Security, Windows'un kendi güvenlik mekanizmalarını asla zayıflatmaz:
- **Defender'ı Kapatmaz:** Microsoft Defender birincil koruma olarak çalışmaya devam eder.
- **UAC ve SmartScreen'e Müdahale Etmez:** Sistem bütünlüğü politikaları korunur.
- **Sistem Dosyalarını Korur:** `explorer.exe`, `svchost.exe`, `csrss.exe` gibi kritik Windows çekirdek dosyalarının kazara karantinaya alınması hardcoded kurallarla engellenmiştir.

---

## 💻 Sistem Gereksinimleri

- **İşletim Sistemi**: Windows 10 (Build 19041+) veya Windows 11 (64-bit x64).
- **Bellek**: Minimum 4 GB RAM (8 GB önerilir).
- **Disk Alanı**: 500 MB boş alan.
- **Çalışma Modu**: Standart Kullanıcı Modunda doğrudan çalışır; isteğe bağlı Windows Arka Plan Servisi için Yönetici izni kullanılır.

---

## 🔒 Gizlilik Politikası (Zero Cloud Telemetry)

- **Sıfır Bulut Gönderimi:** Taranan dosyalarınız, şifreleriniz veya geçmişiniz asla hiçbir harici sunucuya veya bulut yapay zekasına iletilmez.
- **Gizli Arka Kapı Yoktur:** Sisteme sızma, uzaktan kabuk (reverse shell) veya yetkisiz erişim araçları içermez.
- **Yerel SQLite Günlüğü:** Bütün olaylar sadece kendi bilgisayarınızdaki şifreli SQLite veritabanında tutulur.

---

## 📄 Lisans & Telif Hakkı (License)

Bu proje **AegisVerse Özel ve Savunma Topluluğu Lisansı** altında korunmaktadır.  
Tam yasal metin ve kısıtlamalar için lütfen **[LICENSE](LICENSE)** belgesini okuyunuz.  
Üçüncü taraf açık kaynak bileşenleri (YARA-X, SQLite, Tokio, React) **[LICENSES.md](LICENSES.md)** dosyasında listelenmiştir.

Copyright © 2026 **AegisVerse** (`krlkaan@outlook.com`). Tüm Hakları Saklıdır.
