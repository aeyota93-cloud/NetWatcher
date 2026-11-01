# Сторонние компоненты и данные

## Cloudflare speedtest — методика оценок AIM

Пороги баллов и правила оценок «игры / звонки / видео» (`src/NetWatcher.Core/Link/Aim.cs`) перенесены из
<https://github.com/cloudflare/speedtest> (`src/config/internalConfig.ts`, `src/Results/ScoresCalculations.ts`).

```
MIT License

Copyright (c) 2023 Cloudflare

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Данные

- База владельцев IP: [iptoasn.com](https://iptoasn.com).
- База стран: IP Geolocation by [DB-IP](https://db-ip.com), лицензия [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
- Каталог доменов: [DuckDuckGo Tracker Blocklists](https://github.com/duckduckgo/tracker-blocklists), © Duck Duck Go, Inc., лицензия [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/); производный файл каталога распространяется на тех же условиях.
- Телеметрия Windows: [WindowsSpyBlocker](https://github.com/crazy-max/WindowsSpyBlocker), MIT, © CrazyMax.
