# FoxyVPN Windows — نسخهٔ موبایل‌نما (Phone UI)

کلاینت ویندوزی با پنجرهٔ عمودی کوچک دقیقاً مثل اپ اندروید (بدون WebView2/مرورگر — نقاشی مستقیم GDI روی walk CustomWidget).

- `FoxyVPN.exe` آماده در [Releases](../../releases) تگ `windows-v2.0.0-phone`
- بیلد: به Go 1.26 نیاز دارد — `GOOS=windows go build -ldflags="-H windowsgui" -o FoxyVPN.exe .`
- منابع PE (آیکون/مانیفست/نسخه) با go-winres از `winres/` ساخته می‌شوند (`rsrc_windows_amd64.syso` ضمیمه است)
- ماژول‌های خارجی (lxn/walk, x/net) با `go mod download` گرفته می‌شوند؛ vendor در ریپو نیست
- UI ها: `--ui phone` (پیش‌فرض، مثل اندروید) / `--ui native` (پنل کلاسیک) / `--ui browser`
