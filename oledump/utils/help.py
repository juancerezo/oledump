import textwrap

def PrintManual():
    manual = r'''
Manual:

oledump is a tool to analyze OLE files (officially: Compound File Binary Format, CFBF). Many file formats are in fact OLE files, like Microsoft Office files, MSI files, ... Even the new Microsoft Office Open XML (OOXML) format uses OLE files for VBA macros.
oledump can analyze OLE files directly, or indirectly when they are contained in some file format (like .docm, .xml, ...).

A cheat sheet can be found here: https://www.sans.org/security-resources/posters/oledumppy-quick-reference/325/download

oledump uses 2 modules that are not part of Python 2: olefile (http://www.decalage.info/python/olefileio) and YARA.
You need to install the olefile module for this program to work.
The YARA module is not mandatory if you don't use YARA rules.

Running oledump with a spreadsheet (.xls binary format) lists al the streams found in the OLE file (an OLE file is a virtual filesystem with folders and files, known as streams), like this:

C:\Demo>oledump.py Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation'
  2:      4096 '\\x05SummaryInformation'
  3:      4096 'Workbook'

The first column is an index assigned to the stream by oledump. This index is used to select streams. The second column is the size of the stream (number of bytes inside the stream), and the last column is the name of the stream.

To select a stream for analysis, use option -s with the index (number of the stream, or a for all streams), like this:
C:\Demo>oledump.py -s 1 Book1.xls
00000000: FE FF 00 00 05 01 02 00  00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  01 00 00 00 02 D5 CD D5  .............i-i
00000020: 9C 2E 1B 10 93 97 08 00  2B 2C F9 AE 30 00 00 00  ........+,..0...
00000030: E4 00 00 00 09 00 00 00  01 00 00 00 50 00 00 00  ............P...
00000040: 0F 00 00 00 58 00 00 00  17 00 00 00 70 00 00 00  ....X.......p...
...

When selecting a stream, its content is shown as an ASCII dump (this can also be done with option -a).
Option -x produces a hexadecimal dump instead of an ASCII dump.

C:\Demo>oledump.py -s 1 -x Book1.xls
FE FF 00 00 05 01 02 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 01 00 00 00 02 D5 CD D5
9C 2E 1B 10 93 97 08 00 2B 2C F9 AE 30 00 00 00
E4 00 00 00 09 00 00 00 01 00 00 00 50 00 00 00
0F 00 00 00 58 00 00 00 17 00 00 00 70 00 00 00
...

Option -A does an ASCII dump (like option -a), but with duplicate lines removed.

Option -S dumps the strings.

Option -d produces a raw dump of the content of the stream. This content can be redirected to a file, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls > content.bin

or it can be piped into another command, like this:
C:\Demo>oledump.py -s 1 -d Book1.xls | pdfid.py -f

If the raw dump needs to be processed by a string codec, like utf16, use option -t instead of -d and provide the codec:
C:\Demo>oledump.py -s 1 -t utf16 Book1.xls

Streams can also be selected by their full name (example: -s 'VBA/ThisWorkkbook').

Option -C (--cut) allows for the partial selection of a stream. Use this option to "cut out" part of the stream.
The --cut option takes an argument to specify which section of bytes to select from the stream. This argument is composed of 2 terms separated by a colon (:), like this:
termA:termB
termA and termB can be:
- nothing (an empty string)
- a positive decimal number; example: 10
- an hexadecimal number (to be preceded by 0x); example: 0x10
- a case sensitive ASCII string to search for (surrounded by square brackets and single quotes); example: ['MZ']
- a case sensitive UNICODE string to search for (surrounded by square brackets and single quotes prefixed with u); example: [u'User']
- an hexadecimal string to search for (surrounded by square brackets); example: [d0cf11e0]
If termA is nothing, then the cut section of bytes starts with the byte at position 0.
If termA is a number, then the cut section of bytes starts with the byte at the position given by the number (first byte has index 0).
If termA is a string to search for, then the cut section of bytes starts with the byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
If termB is nothing, then the cut section of bytes ends with the last byte.
If termB is a number, then the cut section of bytes ends with the byte at the position given by the number (first byte has index 0).
When termB is a number, it can have suffix letter l. This indicates that the number is a length (number of bytes), and not a position.
termB can also be a negative number (decimal or hexademical): in that case the position is counted from the end of the file. For example, :-5 selects the complete file except the last 5 bytes.
If termB is a string to search for, then the cut section of bytes ends with the last byte at the position where the string is first found. If the string is not found, the cut is empty (0 bytes).
No checks are made to assure that the position specified by termA is lower than the position specified by termB. This is left up to the user.
Search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an instance (a number equal to 1 or greater) to indicate which instance needs to be taken. For example, ['ABC']2 will search for the second instance of string 'ABC'. If this instance is not found, then nothing is selected.
Search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an offset (+ or - a number) to add (or substract) an offset to the found instance. This number can be a decimal or hexadecimal (prefix 0x) value. For example, ['ABC']+3 will search for the first instance of string 'ABC' and then select the bytes after ABC (+ 3).
Finally, search string expressions (ASCII, UNICODE and hexadecimal) can be followed by an instance and an offset.
Examples:
This argument can be used to dump the first 256 bytes of a PE file located inside the stream: ['MZ']:0x100l
This argument can be used to dump the OLE file located inside the stream: [d0cf11e0]:
When this option is not used, the complete stream is selected.

When analyzing a Microsoft Office document with VBA macros, you will see output similar to this:

C:\Demo>oledump.py Book2-vba.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:      2484 'Workbook'
  5:       529 '_VBA_PROJECT_CUR/PROJECT'
  6:       104 '_VBA_PROJECT_CUR/PROJECTwm'
  7: M    1196 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: m     977 '_VBA_PROJECT_CUR/VBA/Sheet2'
  9: m     977 '_VBA_PROJECT_CUR/VBA/Sheet3'
 10: m     985 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
 11:      2651 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:       549 '_VBA_PROJECT_CUR/VBA/dir'

The letter M next to the index of some of the streams (streams 7, 8, 9 and 10) is a macro indicator.
If you select a macro stream, the ASCII dump will not help you much. This is because of compression. VBA macros are stored inside streams using a proprietary compression method. To decompress the VBA macros source code, you use option -v, like this:
C:\Demo>oledump.py -s 7 -v Book2-vba.xls
Attribute VB_Name = "Sheet1"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
Sub Workbook_Open()
    MsgBox "VBA macro"
End Sub

If the VBA macro code is only composed of Attribute or Option statements, and no other statements, then the indicator is a lower case letter m. Example:
C:\Demo>oledump.py -s 8 -v Book2-vba.xls
Attribute VB_Name = "Sheet2"
Attribute VB_Base = "0{00020820-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True

If the VBA code contains other statements than Attribute or Options statements, then the indicator is a upper case letter M.
This M/m indicator allows you to focus first on interesting VBA macros.
A ! indicator means that the stream is a VBA module, but that no VBA code was detected that starts with one or more attributes.

To decompress the macros and skip the initial attributes, use option --vbadecompressskipattributes.

When compressed VBA code is corrupted, the status indicatore will be E (error).
C:\Demo>oledump.py Book2-vba.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:      2484 'Workbook'
  5:       529 '_VBA_PROJECT_CUR/PROJECT'
  6:       104 '_VBA_PROJECT_CUR/PROJECTwm'
  7: E    1196 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: m     977 '_VBA_PROJECT_CUR/VBA/Sheet2'
  9: m     977 '_VBA_PROJECT_CUR/VBA/Sheet3'
 10: m     985 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
 11:      2651 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:       549 '_VBA_PROJECT_CUR/VBA/dir'

To view the VBA code up til the corruption, use option --vbadecompresscorrupt.
C:\Demo>oledump.py -s 7 --vbadecompresscorrupt Book2-vba.xls

Option -i (without option -s) displays extra information for modules:
C:\Demo>oledump.py -i Book2-vba.xls
  1:       107             '\\x01CompObj'
  2:       256             '\\x05DocumentSummaryInformation'
  3:       216             '\\x05SummaryInformation'
  4:     15615             'Workbook'
  5:       435             '_VBA_PROJECT_CUR/PROJECT'
  6:        62             '_VBA_PROJECT_CUR/PROJECTwm'
  7: m     985     813+172 '_VBA_PROJECT_CUR/VBA/Sheet1'
  8: M    1767    1545+222 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
  9:      2413             '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 10:      1253             '_VBA_PROJECT_CUR/VBA/__SRP_0'
 11:       106             '_VBA_PROJECT_CUR/VBA/__SRP_1'
 12:       504             '_VBA_PROJECT_CUR/VBA/__SRP_2'
 13:       103             '_VBA_PROJECT_CUR/VBA/__SRP_3'
 14:       524             '_VBA_PROJECT_CUR/VBA/dir'

Modules can contain compiled code and source code (usually, both). In this example, stream 7 and 8 have extra information: the size of the compiled code (left of the + sign) and the size of de source code (right of the + sign).
Stream 7 is a module with size 985, the first 813 bytes are the compiled code and the last 172 bytes are the source code.

When selecting the content of modules, the index can be suffixed with c to select only the bytes of the compiled code, or with s to select only the bytes of the source code:
C:\Demo>oledump.py -s 7s Book2-vba.xls
00000000: 01 A8 B0 00 41 74 74 72  69 62 75 74 00 65 20 56  ....Attribut.e V
00000010: 42 5F 4E 61 6D 00 65 20  3D 20 22 53 68 65 40 65  B_Nam.e = "She@e
00000020: 74 31 22 0D 0A 0A E8 42  04 61 73 02 74 30 7B 30  t1"....B.as.t0{0
00000030: 30 30 C0 32 30 38 32 30  2D 00 20 04 08 0E 43 00  00.20820-. ...C.
00000040: 14 02 1C 01 24 30 30 34  36 02 7D 0D 7C 47 6C 6F  ....$0046.}.|Glo
00000050: 62 61 6C 21 01 C4 53 70  61 63 01 92 46 61 08 6C  bal!..Spac..Fa.l
00000060: 73 65 0C 64 43 72 65 61  10 74 61 62 6C 15 1F 50  se.dCrea.tabl..P
00000070: 72 65 20 64 65 63 6C 61  00 06 49 64 11 00 AB 54  re decla..Id...T
00000080: 72 75 0D 42 45 78 70 08  6F 73 65 14 1C 54 65 6D  ru.BExp.ose..Tem
00000090: 70 00 6C 61 74 65 44 65  72 69 06 76 02 24 92 42  p.lateDeri.v.$.B
000000A0: 75 73 74 6F 6D 0C 69 7A  04 44 03 32              ustom.iz.D.2

Option -r can be used together with option -v to decompress a VBA macro stream that was extracted through some other mean than oledump. In such case, you provide the file that contains the compressed macro, instead of the OLE file.

ole files can contain streams that are not connected to the root entry. This can happen when a maldoc is cleaned by anti-virus. oledump will mark such streams as orphaned:
C:\Demo>oledump.py Book2-vba.xls
  1:       114 '\\x01CompObj'
  2:    107608 '\\x05DocumentSummaryInformation'
  3:     52900 '\\x05SummaryInformation'
  4:     11288 '1Table'
  5:    131068 'Data'
  6:      7726 'WordDocument'
  7:       567 Orphan: 'dir'
  8:      2282 Orphan: '__SRP_0'
  9:        84 Orphan: '__SRP_1'
 10:      3100 Orphan: '__SRP_2'
 11:       188 Orphan: '__SRP_3'
 12: M    9443 Orphan: 'NewMacros'
 13: m     940 Orphan: 'ThisDocument'
 14:      3835 Orphan: 'XVBA_PROJECT'
 15:       484 Orphan: 'PROJECT'
 16:        71 Orphan: 'PROJECTwm'

Microsoft Office files can contain embedded objects. They show up like this (notice stream 6 Ole10Native with indicator O):
C:\Demo>oledump.py Book1-insert-object-calc-rol3.exe.xls
  1:       109 '\\x01CompObj'
  2:       276 '\\x05DocumentSummaryInformation'
  3:       224 '\\x05SummaryInformation'
  4:        80 'MBD0004D0D1/\\x01CompObj'
  5:        20 'MBD0004D0D1/\\x01Ole'
  6: O  114798 'MBD0004D0D1/\\x01Ole10Native'
  7:     11312 'Workbook'

To get more info about the embedded object, use option -i like this:
C:\Demo>oledump.py -s 6 -i Book1-insert-object-calc-rol3.exe.xls
String 1: calc-rol3.exe
String 2: C:\Demo\ole\CALC-R~1.EXE
String 3: C:\Demo\ole\CALC-R~1.EXE
Size embedded file: 114688
MD5 embedded file: bef425b95e45c54d649a19a7c55556a0
SHA256 embedded file: 211b63ae126411545f9177ec80114883d32f7e3c7ccf81ee4e5dd6ffe3a10e2d

To extract the embedded file, use option -e and redirect the output to a file like this:
C:\Demo>oledump.py -s 6 -e Book1-insert-object-calc-rol3.exe.xls > extracted.bin

Use option --storages to display storages (by default, oledump only lists streams). Indicator . is used for storages except for the Root Entry which has indicator R.

Option -f can be used to find embedded OLE files. This is useful, for example, in the following scenario:
AutoCAD drawing files (.dwg) can contain VBA macros. Although the .dwg file format is a proprietary format, VBA macros are stored as an embedded OLE file. The header of a DWG file contains a pointer to the embedded OLE file, but since an OLE file starts with a MAGIC sequence (D0CF11E0), you can just scan the input file for this sequence.
This can be done using option -f (--find). This option takes a value: letter l or a positive integer.
To have an overview of embedded OLE files, use option "-f l" (letter l) like this:

C:\Demo>oledump.py -f l Drawing1vba.dwg
Position of potential embedded OLE files:
 1 0x00008090

This will report the position of every (potential) embedded OLE file inside the input file. Here you can see that there is one file at position 0x8090.
You can then select this file and analyze it, using -f 1 (integer 1):

C:\Demo>oledump.py -f 1 Drawing1vba.dwg
  1:       374 'VBA_Project/PROJECT'
  2:        38 'VBA_Project/PROJECTwm'
  3: M    1255 'VBA_Project/VBA/ThisDrawing'
  4:      1896 'VBA_Project/VBA/_VBA_PROJECT'
  5:       315 'VBA_Project/VBA/dir'
  6:        16 'VBA_Project_Version'

And then you can use option -s to select streams and analyze them.

Analyzing the content of streams (and VBA macros) can be quite challenging. To help with the analysis, oledump provides support for plugins and YARA rules.

plugins are Python programs that take the stream content as input and try to analyze it. Plugins can analyze the raw stream content or the decompressed VBA macro source code. Plugins analyze all streams, you don't need to select a particular stream.
VBA macros code in malicious documents is often obfuscated, and hard to understand. plugin_http_heuristics is a plugin for VBA macros that tries to recover the URL used to download the trojan in a malicious Office document. This URL is often obfuscated, for example by using hexadecimal or base64 strings to represent the URL. plugin_http_heuristics tries several heuristics to recover a URL.
Example:
C:\Demo>oledump.py -p plugin_http_heuristics sample.xls
  1:       104 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       228 '\\x05SummaryInformation'
  4:      4372 'Workbook'
  5:       583 '_VBA_PROJECT_CUR/PROJECT'
  6:        83 '_VBA_PROJECT_CUR/PROJECTwm'
  7: m     976 '_VBA_PROJECT_CUR/VBA/????1'
               Plugin: HTTP Heuristics plugin
  8: m     976 '_VBA_PROJECT_CUR/VBA/????2'
               Plugin: HTTP Heuristics plugin
  9: m     976 '_VBA_PROJECT_CUR/VBA/????3'
               Plugin: HTTP Heuristics plugin
 10: M  261251 '_VBA_PROJECT_CUR/VBA/????????'
               Plugin: HTTP Heuristics plugin
                 http://???.???.???.??:8080/stat/lld.php
 11:      8775 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
 12:      1398 '_VBA_PROJECT_CUR/VBA/__SRP_0'
 13:       212 '_VBA_PROJECT_CUR/VBA/__SRP_1'
 14:       456 '_VBA_PROJECT_CUR/VBA/__SRP_2'
 15:       385 '_VBA_PROJECT_CUR/VBA/__SRP_3'
 16:       550 '_VBA_PROJECT_CUR/VBA/dir'

Option -q (quiet) only displays output from the plugins, it suppresses output from oledump. This makes it easier to spot URLs:
C:\Demo>oledump.py -p plugin_http_heuristics -q sample.xls
http://???.???.???.??:8080/stat/lld.php

When specifying plugins, you do not need to give the full path nor the .py extension (it's allowed though). If you just give the filename without a path, oledump will search for the plugin in the current directory and in the directory where oledump.py is located. You can specify more than one plugin by separating their names with a comma (,), or by using a at-file. A at-file is a text file containing the names of the plugins (one per line). If plugins are located in a different directory, you could specify it with the --plugindir option. To indicate to oledump that a text file is a at-file, you prefix iw with @, like this:
oledump.py -p @all-plugins.txt sample.xls

Some plugins take options too. Use --pluginoptions to specify these options.

oledump can scan the content of the streams with YARA rules (the YARA Python module must be installed). You provide the YARA rules with option -y. You can provide one file with YARA rules, an at-file (@file containing the filenames of the YARA files) or a directory. In case of a directory, all files inside the directory are read as YARA files. Or you can provide the YARA rule with the option value (and adhoc rule) if it starts with # (literal), #s# (string), #x# (hexadecimal string), #r# (regex string), #q# (quote), #h# (hexadecimal) or #b# (base64). Example: -y "#rule demo {strings: $a=\"demo\" condition: $a}"
Using #s#demo will instruct oledump to generate a rule to search for string demo (rule string {strings: $a = "demo" ascii wide nocase condition: $a) and use that rule.
All streams are scanned with the provided YARA rules, you can not use option -s to select an individual stream.

Example:
C:\Demo>oledump.py -y contains_pe_file.yara Book1-insert-object-exe.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule: Contains_PE_File
  6:     19567 'Workbook'

In this example, you use YARA rule contains_pe_file.yara to find PE files (executables) inside Microsoft Office files. The rule triggered for stream 5, because it contains an EXE file embedded as OLE object.

If you want more information about what was detected by the YARA rule, use option --yarastrings like in this example:
C:\Demo>oledump.py -y contains_pe_file.yara --yarastrings Book1-insert-object-exe.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule: Contains_PE_File
               000064 $a:
                4d5a
                'MZ'
  6:     19567 'Workbook'

YARA rule contains_pe_file detects PE files by finding string MZ followed by string PE at the correct offset (AddressOfNewExeHeader).
The rule looks like this:
rule Contains_PE_File
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a PE file inside a byte sequence"
        method = "Find string MZ followed by string PE at the correct offset (AddressOfNewExeHeader)"
    strings:
        $a = "MZ"
    condition:
        for any i in (1..#a): (uint32(@a[i] + uint32(@a[i] + 0x3C)) == 0x00004550)
}

Distributed together with oledump are the YARA rules maldoc.yara. These are YARA rules to detect shellcode, based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

Two external variables are declared for use in YARA rules: streamname contains the stream name, and VBA is True when the YARA engine is given VBA source code to scan.

When looking for traces of Windows executable code (PE files, shellcode, ...) with YARA rules, one must take into account the fact that the executable code might have been encoded (for example via XOR and a key) to evade detection.
To deal with this possibility, oledump supports decoders. A decoder is another type of plugin, that will bruteforce a type of encoding on each stream. For example, decoder_xor1 will encode each stream via XOR and a key of 1 byte. So effectively, 256 different encodings of the stream will be scanned by the YARA rules. 256 encodings because: XOR key 0x00, XOR key 0x01, XOR key 0x02, ..., XOR key 0xFF
Here is an example:
C:\Demo>oledump.py -y contains_pe_file.yara -D decoder_xor1 Book1-insert-object-exe-xor14.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule (stream decoder: XOR 1 byte key 0x14): Contains_PE_File
  6:     19567 'Workbook'

The YARA rule triggers on stream 5. It contains a PE file encoded via XORing each byte with 0x14.

You can specify decoders in exactly the same way as plugins, for example specifying more than one decoder separated by a comma ,.
If decoders are located in a different directory, you could specify it with the --decoderdir option.
C:\Demo>oledump.py -y contains_pe_file.yara -D decoder_xor1,decoder_rol1,decoder_add1 Book1-insert-object-exe-xor14.xls
  1:       107 '\\x01CompObj'
  2:       256 '\\x05DocumentSummaryInformation'
  3:       216 '\\x05SummaryInformation'
  4:        76 'MBD0049DB15/\\x01CompObj'
  5: O   60326 'MBD0049DB15/\\x01Ole10Native'
               YARA rule (stream decoder: XOR 1 byte key 0x14): Contains_PE_File
  6:     19567 'Workbook'

Some decoders take options, to be provided with option --decoderoptions.

OLE files contain metadata. Use option -M to display it.

Example:
C:\Demo>oledump.py -M Book1.xls
Properties SummaryInformation:
 codepage: 1252 ANSI Latin 1; Western European (Windows)
 author: Didier Stevens
 last_saved_by: Didier Stevens
 create_time: 2014-08-21 09:16:10
 last_saved_time: 2014-08-21 10:26:40
 creating_application: Microsoft Excel
 security: 0
Properties DocumentSummaryInformation:
 codepage_doc: 1252 ANSI Latin 1; Western European (Windows)
 scale_crop: False
 company: Didier Stevens Labs
 links_dirty: False
 shared_doc: False
 hlinks_changed: False
 version: 730895

Option -c calculates extra data per stream. This data is displayed per stream. Only the MD5 hash of the content of the stream is calculated.
Example:
C:\Demo>oledump.py -c Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation' ff1773dce227027d410b09f8f3224a56
  2:      4096 '\\x05SummaryInformation' b46068f38a3294ca9163442cb8271028
  3:      4096 'Workbook' d6a5bebba74fb1adf84c4ee66b2bf8dd

If you need more data than the MD5 of each stream, use option -E (extra). This option takes a parameter describing the extra data that needs to be calculated and displayed for each stream. The following variables are defined:
  %INDEX%: the index of the stream
  %INDICATOR%: macro indicator
  %LENGTH%': the length of the stream
  %NAME%: the printable name of the stream
  %MD5%: calculates MD5 hash
  %SHA1%: calculates SHA1 hash
  %SHA256%: calculates SHA256 hash
  %ENTROPY%: calculates entropy
  %HEADHEX%: display first 20 bytes of the stream as hexadecimal
  %HEADASCII%: display first 20 bytes of the stream as ASCII
  %TAILHEX%: display last 20 bytes of the stream as hexadecimal
  %TAILASCII%: display last 20 bytes of the stream as ASCII
  %HISTOGRAM%: calculates a histogram
                 this is the prevalence of each byte value (0x00 through 0xFF)
                 at least 3 numbers are displayed separated by a comma:
                 number of values with a prevalence > 0
                 minimum values with a prevalence > 0
                 maximum values with a prevalence > 0
                 each value with a prevalence > 0
  %BYTESTATS%: calculates byte statistics
                 byte statistics are 5 numbers separated by a comma:
                 number of NULL bytes
                 number of control bytes
                 number of whitespace bytes
                 number of printable bytes
                 number of high bytes
  %CLSID%: storage/stream class ID
  %CLSIDDESC%: storage/stream class ID description
  %MODULEINFO%: for module streams: size of compiled code & size of compressed code; otherwise 'N/A' (you must use option -i)
  %CTIME%: creation time
  %MTIME%: modification time
  %CTIMEHEX%: creation time in hexadecimal
  %MTIMEHEX%: modification time in hexadecimal

The parameter for -E may contain other text than the variables, which will be printed. Escape characters \\n and \\t are supported.
Example displaying the MD5 and SHA256 hash per stream, separated by a space character:
C:\Demo>oledump.py -E "%MD5% %SHA256%" Book1.xls
  1:      4096 '\\x05DocumentSummaryInformation' ff1773dce227027d410b09f8f3224a56 2817c0fbe2931a562be17ed163775ea5e0b12aac203a095f51ffdbd5b27e7737
  2:      4096 '\\x05SummaryInformation' b46068f38a3294ca9163442cb8271028 2c3009a215346ae5163d5776ead3102e49f6b5c4d29bd1201e9a32d3bfe52723
  3:      4096 'Workbook' d6a5bebba74fb1adf84c4ee66b2bf8dd 82157e87a4e70920bf8975625f636d84101bbe8f07a998bc571eb8fa32d3a498

If the extra parameter starts with !, then it replaces the complete output line (in stead of being appended to the output line).
Example:
C:\Demo>oledump.py -E "!%INDEX% %MD5%" Book1.xls
1 ff1773dce227027d410b09f8f3224a56
2 b46068f38a3294ca9163442cb8271028
3 d6a5bebba74fb1adf84c4ee66b2bf8dd

Option -v can be used together with option -c or -E to perform the calculations on the decompressed macro streams (m and M) in stead of the raw macro streams.

To include extra data with each use of oledump, define environment variable OLEDUMP_EXTRA with the parameter that should be passed to -E. When environment variable OLEDUMP_EXTRA is defined, option -E can be ommited. When option -E is used together with environment variable OLEDUMP_EXTRA, the parameter of option -E is used and the environment variable is ignored.

Sometimes during the analysis of an OLE file, you might come across compressed data inside the stream. For example, an indicator of ZLIB compressed DATA is byte 0x78.
Option --decompress instructs oledump to search for compressed data inside the selected stream, and then decompress it. If this fails, the original data is displayed.

Option -u can be used to include unused data found in the last sector of a stream, after the stream data.

oledump can handle several types of files. OLE files are supported, but also the new Office Open XML standard: these are XML files inside a ZIP container, but VBA macros are still stored as OLE files inside the ZIP file. In such case, the name of the OLE file inside the ZIP file will be displayed, and the indices will be prefixed by a letter (A for the first OLE file, B for the second OLE file, ...).
Example:
C:\Demo>oledump.py Book1.xlsm
A: xl/vbaProject.bin
 A1:       462 'PROJECT'
 A2:        86 'PROJECTwm'
 A3: M     974 'VBA/Module1'
 A4: m     977 'VBA/Sheet1'
 A5: m     985 'VBA/ThisWorkbook'
 A6:      2559 'VBA/_VBA_PROJECT'
 A7:      1111 'VBA/__SRP_0'
 A8:        74 'VBA/__SRP_1'
 A9:       136 'VBA/__SRP_2'
A10:       103 'VBA/__SRP_3'
A11:       566 'VBA/dir'

oledump can also handle XML files that contain OLE files stored as base64 inside XML files.

Finally, all of these file types may be stored inside a password protected ZIP file (password infected). Storing malicious files inside a password protected ZIP file is common practice amongst malware researchers. Not only does it prevent accidental infection, but it also prevents anti-virus programs from deleting the sample.
oledump supports the analysis of samples stored in password protected ZIP files (password infected). Do not store more than one sample inside a password protected ZIP file. Each sample should be in its own ZIP container.

oledump also supports input/output redirection. This way, oledump can be used in a pipe.
Say for example that the sample OLE file is GZIP compressed. oledump can not handle GZIP files directly, but you can decompress and cat it with zcat and then pipe it into oledump for analysis, like this:
zcat sample.gz | oledump.py

With option -T (--headtail), output can be truncated to the first 10 lines and last 10 lines of output.

With option -j, oledump will output the content of the ole file as a JSON object that can be piped into other tools that support this JSON format. When option -v is used together with option -j, the produced JSON object contains decompressed VBA code.

Overview of indicators:
 M: Macro (attributes and code)
 m: macro (attributes without code)
 E: Error (code that throws an error when decompressed)
 !: Unusual macro (code without attributes)
 O: object (embedded file)
 .: storage
 R: root entry

More info: https://blog.didierstevens.com/2020/11/15/oledump-indicators/

The return codes of oledump are:
 -1 when an error occured
 0 when the file is not an ole file (or does not contain an ole file)
 1 when an ole file without macros was analyzed
 2 when an ole file with macros was analyzed
'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))