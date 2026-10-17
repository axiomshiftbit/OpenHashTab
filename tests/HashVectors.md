# Источники тестовых векторов

`OfficialHashVectors.h` содержит 287 примеров с заранее опубликованными результатами:

- SHA-512/224 и SHA-512/256: все 129 примеров `ShortMsg` и первые/последние два примера `LongMsg` для каждого алгоритма из [NIST CAVP SHS](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip).
- SHAKE128-256 и SHAKE256-512: все 9 и 5 примеров `VariableOut` с выходом соответственно 256 и 512 бит из [NIST CAVP SHAKE](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip). SHAKE позволяет брать префиксы выхода, но здесь сравнивается весь запрошенный результат.
- Стрибог-256 и Стрибог-512: оба сообщения из раздела 10 [RFC 6986](https://www.rfc-editor.org/rfc/rfc6986.html). Порядок байтов полных сообщений и результатов развёрнут относительно записи битовых векторов в RFC; биты внутри байта не переставляются. RFC имеет информационный статус.
- `belt-hash`: три примера [спецификации СТБ 34.101.31](https://github.com/bcrypto/belt/blob/master/spec/9111TestHash.tex), длины сообщений 13, 32 и 48 байтов. Описание алгоритма: [раздел «Хэширование»](https://github.com/bcrypto/belt/blob/master/spec/0708Hash.tex).

SHA-256 загруженных архивов NIST:

```text
929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8  shabytetestvectors.zip
debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7  shakebytetestvectors.zip
```

Каждый официальный пример проверяется через производственный адаптер алгоритма при размерах порции 1, 31, 127 и 8192 байта. Проверяется размер результата и защитная область после выходного буфера.

`AdditionalHashVectors.h` дополняет официальные примеры 72 результатами независимой реализации Python `hashlib`/OpenSSL: четыре новых алгоритма SHA-512/t и SHAKE, 18 размеров от пустого сообщения до 2 МиБ + 17 байтов, включая границы блоков и дополнения. Генератор `GenerateHashVectors.py --check` проверяет неизменность этих значений в CI. Данные воспроизводимы: байт с индексом `i` равен `(i * 71 + 19) & 255`.

Начальные значения SHA-512/t сверены с §5.3.6 [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf). Параметры SHAKE и разделение доменов сверены с §6.2 [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). SHA-512/t не является обычным усечённым SHA-512; SHAKE не является усечённым SHA3.

Прохождение этих тестов не означает сертификацию FIPS/CAVP или сертификацию по национальным стандартам.
