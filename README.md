# OpenHashTab

[![License](https://img.shields.io/github/license/axiomshiftbit/OpenHashTab)](COPYING) [![Build and test](https://github.com/axiomshiftbit/OpenHashTab/actions/workflows/ci.yml/badge.svg)](https://github.com/axiomshiftbit/OpenHashTab/actions/workflows/ci.yml)

## Авторство и происхождение проекта

Эта версия OpenHashTab основана на проекте **[OpenHashTab](https://github.com/namazso/OpenHashTab)**, созданном **[namazso](https://github.com/namazso)**. Оригинальный автор и участники исходного проекта сохраняют авторство своего кода.

Репозиторий **[axiomshiftbit/OpenHashTab](https://github.com/axiomshiftbit/OpenHashTab)** поддерживается независимо. Исходная ветка `master` перенесена из **[MarkDDi/OpenHashTab](https://github.com/MarkDDi/OpenHashTab)** с сохранением истории изменений. Доработки в этом репозитории не означают участия или одобрения со стороны оригинального автора.

Проект распространяется на условиях **GNU GPL версии 3 или более поздней**; см. [COPYING](COPYING). Существующие уведомления об авторских правах и лицензии сторонних компонентов сохранены.

## About

OpenHashTab is a shell extension for conveniently calculating and checking file hashes from file properties.

## Features

* Support for 31 algorithms, see **Algorithms**
* High performance hash calculation
* Native Windows looks
* High DPI screen support
* Long path support\*
* Multilingual (Consider contributing to translation!)
* Check hashes against VirusTotal with a button
* Hash checking against a checksum file (Supported: hex hash next to file, \*sum output (hex or base64), corz .hash, SFV)
* Hash export to file or clipboard (Supported: \*sum output, corz .hash, SFV)
* Optional context menu option for faster access
* File associations and standalone mode

\* to the extent Windows and configuration supports it. [Enable long paths](https://www.tenforums.com/tutorials/51704-enable-disable-win32-long-paths-windows-10-a.html) on 1607+ for better support.

## System requirements

* Windows 7 or later (x86 / x64 / ARM64)
* 1 GB RAM or more (for efficient hashing of more than 512 files at a time)

## Usage

Most of the actions should be obvious. Some not-so-obvious features are listed here:

* You can select multiple files or folders, all files will be hashed, directories traversed
* Double click hash to copy it
* Double click name or algorithm to copy the line in sumfile format
* Right click for popup menu: copy hash, copy filename, copy line, copy everything
* The counters next to the status text is in the format `(match/mismatch/nothing to check against/error)`
* Columns sort lexicographically, except the hash column which sorts by match type
* Selecting the tab on a sumfile will interpret it as such and hash the files listed in it.
* If a hashed file has a sumfile with same filename plus one of the recognized sumfile extensions and the option for it is enabled, the file hash is checked against it.

### Advanced features

#### Override Windows language selection

Add a `DWORD` named `LangIdOverride` to `HKEY_CURRENT_USER\SOFTWARE\OpenHashTab` (create if it does not exist) with your preferred [LCID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lcid/70feba9f-294e-491e-b6eb-56532684c37f)

#### Disable VirusTotal button for all users on a machine

Add a `DWORD` named `ForceDisableVT` to `HKEY_LOCAL_MACHINE\SOFTWARE\OpenHashTab` (create if it does not exist) with a nonzero value

## Algorithms

* CRC32, CRC64 (xz)
* xxHash (XXH32, XXH64)
* xxHash3 (64 and 128 bit variants)
* MD4, MD5
* RipeMD160
* Blake2sp
* SHA-1
* SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512)
* SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
* BLAKE3 (256 bit, 512 bit)
* KangarooTwelve (264 bit, 256 bit, 512 bit)
* ParallelHash128 (264 bit) and ParallelHash256 (528 bit)
* Streebog (GOST R 34.11-12) (256 bit, 512 bit)

## Download

[Releases of this independently maintained version](https://github.com/axiomshiftbit/OpenHashTab/releases)

[Build candidates and test results](https://github.com/axiomshiftbit/OpenHashTab/actions/workflows/ci.yml)

Build candidates are unsigned and are not a published stable release.

## Screenshot

![Screenshot](https://github.com/namazso/OpenHashTab/assets/8676443/727943b2-8070-4dcc-b0a4-e1149fca0245) ![Algorithms](https://github.com/namazso/OpenHashTab/assets/8676443/878c9b30-ed94-4d8b-9370-75b3be02e2cb)

## Translation

![Weblate translation status](https://hosted.weblate.org/widgets/openhashtab/-/main/multi-auto.svg)

Translate the project at [Weblate](https://hosted.weblate.org/projects/openhashtab/main/)

## Building

See [build_all.ps1](build_all.ps1)

## Relationship to HashTab

HashTab was a similar purpose proprietary application. The original OpenHashTab README described it as an inspiration. This repository preserves the original authorship and license notices; those notices are not an independent determination of copyright ownership. The original repository is subject to a [published DMCA notice](https://github.com/github/dmca/blob/master/2026/05/2026-05-07-source-code-3.md).

## License

All original code in this repo is licensed under the following license, unless explicitly stated otherwise in the file:

    Copyright 2019-2025 namazso <admin@namazso.eu>
    OpenHashTab - File hashing shell extension

    OpenHashTab is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    OpenHashTab is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with OpenHashTab.  If not, see <https://www.gnu.org/licenses/>.

This software also contains or uses code from various other sources, for a complete list see [InstallerLicense.rtf](Setup/InstallerLicense.rtf)

## Сборка и проверка

Версия пакетов задаётся в файле `VERSION`. Сборка выполняется командой `pwsh ./build_all.ps1` на Windows с Visual Studio C++, Clang, CMake, Ninja, .NET SDK и Windows SDK/WDK 10.0.26100.0. Требуется PowerShell 7.3 или новее. Перед сборкой необходимо загрузить подмодули: `git submodule update --init --recursive`.

GitHub Actions собирает варианты x86, x64 и ARM64, запускает тесты алгоритмов и обработки файлов. Для проверки установщика предусмотрены отдельные виртуальные машины Windows 11 25H2 и 26H2 на основе официальных оценочных ISO Microsoft. Образы Windows создаются заново для испытаний и не включаются в распространяемые артефакты проекта. Конкретные версии ОС и результаты каждого запуска указаны в журнале Actions; успешная компиляция сама по себе не подтверждает совместимость.

В Windows 11 классический пункт контекстного меню доступен через «Показать дополнительные параметры». Расширение также предоставляет вкладку в свойствах файла и отдельное приложение `StandaloneStub.exe`.

Проверка зависимостей через [OSV](https://osv.dev/) выполняется при сборке и еженедельно. Она проверяет закреплённые коммиты подмодулей и Actions, версии пакетов WiX/NuGet, а после восстановления пакетов — также транзитивные зависимости NuGet. При недоступности базы проверка завершается ошибкой. Локальный запуск: `python3 automation/Check-Vulnerabilities.py`; после сборки — с параметром `--assets`. Отсутствие совпадений в базе не гарантирует отсутствия уязвимостей.

Для собранного C/C++ включён CodeQL с набором `security-extended`. В одноразовых Windows VM предусмотрены сканирование Microsoft Defender с актуальными сигнатурами и проверка событий Sysmon во время вычисления хешей, установки, обновления, восстановления и удаления. Проверяются сетевые обращения, запуск дочерних процессов, операции с реестром, доступ к физическим дискам и создание потоков в других процессах. Эти сценарии ограничены синтетическими тестовыми данными и не доказывают безопасность всех возможных путей исполнения.

Обычное вычисление хешей выполняется локально. Кнопка VirusTotal использует внешнюю службу: после согласия пользователя исходная интеграция отправляет хеш, путь и дату создания файла. Не используйте её для конфиденциальных путей; администратор может отключить кнопку параметром `ForceDisableVT`, описанным выше. Проверка обновлений обращается к GitHub по отдельному действию пользователя.
