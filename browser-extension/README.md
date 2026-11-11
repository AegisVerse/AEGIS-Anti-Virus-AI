# AEGIS AI Web Shield (Chromium Manifest V3)

**AEGIS AI Web Shield**, AEGIS AI Security endpoint koruma ekosisteminin Chromium tabanlı tarayıcılar (Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi) için geliştirilmiş yerel web koruma eklentisidir.

---

## 🛡️ Temel Özellikler

1. **Zararlı Alan Adı ve C2 Engelleme**: Truva atı dağıtım noktaları, fidye yazılımı ödeme portalları ve komuta kontrol sunucularını engeller.
2. **Oltalama (Phishing) Koruması**: Sahte bankacılık ve kimlik avı sayfalarına erişimi durdurur.
3. **Telemetri ve İzleyici Kalkanı**: Kullanıcıyı profilleyen üçüncü taraf casus pikselleri ve analitik betiklerini bloke eder.
4. **Reklam ve Sahte Yönlendirmeler**: İstenmeyen açılır pencereleri ve yönlendirme ağlarını temizler.
5. **%100 Yerel ve Gizlilik Odaklı**: Hiçbir tarama geçmişi veya web verisi uzak sunuculara gönderilmez. Kural eşlemeleri doğrudan cihaz üzerinde `declarativeNetRequest` motoru ile yürütülür.
6. **Microsoft Defender Uyumluluğu**: Windows Defender SmartScreen ile çakışmaz; savunmayı derinleştiren ek bir yerel katman olarak çalışır.

---

## 🚀 Kurulum (Geliştirici Modu)

Chromium tabanlı tarayıcınıza yüklemek için:

1. Tarayıcınızın eklentiler sayfasına gidin:
   - **Google Chrome**: `chrome://extensions/`
   - **Microsoft Edge**: `edge://extensions/`
   - **Brave Browser**: `brave://extensions/`
2. Sağ üst veya sol menüdeki **"Geliştirici Modu" (Developer Mode)** anahtarını açık konuma getirin.
3. **"Paketlenmemiş Öğe Yükle" (Load unpacked)** düğmesine tıklayın.
4. Proje dizinindeki `browser-extension` klasörünü seçin.
5. AEGIS AI Web Shield tarayıcı araç çubuğunuza eklenecektir.

---

## 📁 Dizin Yapısı

- `manifest.json`: Manifest V3 yapılandırması ve izin bildirimleri.
- `background.js`: Arka plan servis çalışanı (service worker), kural seti kontrolü ve istatistik yönetimi.
- `popup.html`, `popup.css`, `popup.js`: Araç çubuğu hızlı durum ve kontrol paneli.
- `options.html`, `options.css`, `options.js`: Genişletilmiş kural yönetimi ve engelleme günlüğü sayfası.
- `blocked.html`, `blocked.css`, `blocked.js`: Engellenen zararlı alan adlarında gösterilen uyarı sayfası.
- `rules/`:
  - `malware.json`: Yüksek öncelikli zararlı C2 ve oltalama kuralları.
  - `trackers.json`: İzleyici ve telemetri engelleyicileri.
  - `ads.json`: İstenmeyen reklam ağı kuralları.
- `icons/`: Çoklu çözünürlük simgeleri (16x16, 32x32, 48x48, 128x128).

---

## 🔒 Güvenlik Notları
- Bu eklenti hiçbir üçüncü taraf uzaktan kod yürütme (`eval`, uzak betik yükleme) içermez.
- İzinler yalnızca kural eşleştirme için gereken minimum düzeyde tutulmuştur.

