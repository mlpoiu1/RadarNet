# RadarNet

RadarNet یک ابزار سبک برای امتیازدهی ریسک در شبکه‌های سرویس‌محور است.

## Features

- مدل typed برای تعریف `Network`، `Node` و `Service`
- اعتبارسنجی ورودی (پورت، criticality، تکراری نبودن node id و port)
- موتور امتیازدهی ریسک با خروجی severity (`low` تا `critical`)
- CLI برای تحلیل فایل JSON با خروجی `text` یا `json`
- قابلیت `--fail-on` برای CI (شکست دادن pipeline بر اساس شدت ریسک)
- پشتیبانی از ورودی `stdin` با `-` و خروجی خلاصه با `--summary-only`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
radarnet examples/sample-network.json
radarnet examples/sample-network.json --format json
cat examples/sample-network.json | radarnet - --format json --summary-only
pytest -q
```

## CLI

```bash
radarnet <input.json|-> [--format text|json] [--summary-only] [--fail-on low|medium|high|critical]
```

- اگر `--fail-on high` بدهید و severity گزارش `high` یا `critical` باشد، کد خروجی 2 برمی‌گردد.
- در صورت ورودی نامعتبر، CLI با پیام خطای واضح متوقف می‌شود.

## JSON schema (simplified)

```json
{
  "name": "network-name",
  "nodes": [
    {
      "id": "node-id",
      "role": "gateway|backend|...",
      "services": [
        {
          "name": "https",
          "port": 443,
          "public": true,
          "encrypted": true,
          "authenticated": true,
          "criticality": 1
        }
      ]
    }
  ]
}
```

## License

MIT
