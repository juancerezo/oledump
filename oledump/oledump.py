import importlib
import sys
import zipfile

from typing import Generator
from pathlib import Path
from io import BytesIO

import olefile

from oledump import plugins as plugins_module
from oledump import utils
from oledump import constants
from oledump.classes import cPluginMetaclass

from .options import OleDumpOptions


class OLEDump:
    plugins: list
    pluginsOle: list
    decoders: list

    def __init__(self):
        self.plugins = []
        self.pluginsOle = []
        self.decoders = []

    def load_plugins(self, *, plugins: list[str], plugindir: Path | None, verbose: bool):
        if plugindir is None:
            plugindir = Path(list(plugins_module.__path__)[0])

        for plugin in plugins:
            try:
                self.plugins.append(importlib.import_module(plugin))
            except ImportError as e:
                print(f"Error importing plugin: {plugin}")
                if verbose:
                    raise e

    def __run_raw(
        self, filename: Path | None, options: OleDumpOptions
    ) -> Generator[tuple[constants.ExitCode, str | None], None, None]:
        if filename is None:
            utils.if_win32_setbinary(sys.stdin)
            data = sys.stdin.buffer.read()
        else:
            data = filename.read_bytes()

        if options["vdadecompress"]:
            positions = utils.find_all(data, b"\x00Attribut\x00e ")
            vba = b""
            if options["vbadecompresscorrupt"]:
                for position in positions:
                    result, error = utils.search_and_decompress(
                        data=data[position - 3 :],
                        ignore_errors=True,
                        skip_attributes=options["vbadecompressskipattributes"],
                    )

                    if error == None and result is not None:
                        vba += result
            else:
                for position in positions:
                    result, error = utils.search_and_decompress(
                        data=data[position - 3 :],
                        skip_attributes=options["vbadecompressskipattributes"],
                    )

                    if error == None and result is not None:
                        vba += result

            if len(options["plugins"]) == 0:
                yield constants.ExitCode.NO_ERROR, vba.decode(errors="ignore")
                return

            data = vba

        for cPlugin in cPluginMetaclass.plugins():
            oPlugin = None

            try:
                if cPlugin.macroOnly:
                    oPlugin = cPlugin(
                        filename=filename, data=data, options=options["pluginoptions"]
                    )
                elif not cPlugin.macroOnly:
                    oPlugin = cPlugin(
                        filename=filename, data=data, options=options["pluginoptions"]
                    )
                else:
                    oPlugin = None

            except Exception as e:
                if options["verbose"]:
                    raise e

                yield constants.ExitCode.PLUGIN_ERROR, f"Error instantiating plugin: {repr(cPlugin)}"

            if oPlugin is not None:
                result = oPlugin.analize()
                if oPlugin.ran:
                    if options["quiet"]:
                        for line in result:
                            yield constants.ExitCode.NO_ERROR, utils.my_repr(line)

                    else:
                        yield constants.ExitCode.NO_ERROR, f"Plugin: {repr(oPlugin)}"
                        for line in result:
                            yield constants.ExitCode.NO_ERROR, f" {utils.my_repr(line)}"

        yield constants.ExitCode.NO_ERROR, ""

    def __run_ole(
        self,
        *,
        ole: olefile.OleFileIO,
        data: bytes,
        prefix: str,
        rules: list | None,
        options: OleDumpOptions,
    ) -> Generator[tuple[constants.ExitCode, str | None], None, None]:
        pass

    def __call__(
        self,
        *,
        filename: Path | None,
        options: OleDumpOptions,
    ) -> Generator[tuple[constants.ExitCode, str | None], None, None]:
        return_code = constants.ExitCode.NO_ERROR

        self.load_plugins(
            plugins=options["plugins"],
            plugindir=options["plugindir"],
            verbose=options["verbose"],
        )

        if filename is not None and not filename.exists():
            yield constants.ExitCode.UNKNOWN_ERROR, f"Error: {filename} doesn't exists."
            return

        if filename is not None and not filename.is_file():
            yield constants.ExitCode.UNKNOWN_ERROR, f"Error: {filename} is not a file."
            return

        if options["raw"]:
            yield from self.__run_raw(filename, options)
            return

        rules = None
        if options["yara"]:
            rules = utils.yara_compile(options["yara"])

        if filename is None:
            utils.if_win32_setbinary(sys.stdin)
            data_io = BytesIO(sys.stdin.buffer.read())

        elif filename.suffix.lower() == ".zip":
            zip_file = zipfile.ZipFile(str(filename), "r")
            zip_content = zip_file.open(
                zip_file.infolist()[0], "r", utils.c2bip3(options["password"])
            )

            data_io = BytesIO(zip_content.read())
            zip_content.close()
            zip_file.close()

        else:
            data_io = BytesIO(filename.read_bytes())

        if options["find"]:
            file_content = data_io.read()
            locations = utils.find_all(file_content, constants.OLEFILE_MAGIC)

            if len(locations) == 0:
                yield constants.ExitCode.NO_ERROR, "No embedded OLE files found"
                return

            if options["find"] == "l":
                yield constants.ExitCode.NO_ERROR, "Position of potential embedded OLE files:"
                for index, position in enumerate(locations):
                    yield constants.ExitCode.NO_ERROR, f" {index + 1} 0x{position:08x}"
                return

            try:
                index = int(options["find"])
            except ValueError:
                yield constants.ExitCode.UNKNOWN_ERROR, f"Wrong index, must be between 1 and {len(locations)}"
                return

            if index <= 0 or index > len(locations):
                yield constants.ExitCode.UNKNOWN_ERROR, f"Wrong index, must be between 1 and {len(locations)}"
                return

            ole = olefile.OleFileIO(BytesIO(file_content[locations[int(options["find"]) - 1] :]))
            return_code, selection_counter = self.__run_ole(ole, b"", "", rules, options)

        yield return_code, ""


def OLEDump_(filename, options):
    returnCode = 0

    if filename != "" and not os.path.isfile(filename):
        print("Error: %s is not a file." % filename)
        return returnCode

    global plugins
    global pluginsOle
    plugins = []
    pluginsOle = []
    LoadPlugins(options.plugins, options.plugindir, True)

    global decoders
    decoders = []
    LoadDecoders(options.decoders, options.decoderdir, True)

    if options.raw:
        if filename == "":
            if_win32_setbinary(sys.stdin)
            if sys.version_info[0] > 2:
                data = sys.stdin.buffer.read()
            else:
                data = sys.stdin.read()
        else:
            data = File2String(filename)
        if options.vbadecompress:
            positions = find_all(data, b"\x00Attribut\x00e ")
            vba = ""
            if options.vbadecompresscorrupt:
                for position in positions:
                    result = search_and_decompress(
                        data[position - 3 :],
                        None,
                        skipAttributes=options.vbadecompressskipattributes,
                    )
                    if result != None:
                        vba += result
            else:
                for position in positions:
                    result = (
                        search_and_decompress(
                            data[position - 3 :], skipAttributes=options.vbadecompressskipattributes
                        )
                        + "\n\n"
                    )
                    if result != None:
                        vba += result
            if options.plugins == "":
                print(vba)
                return returnCode
            else:
                data = vba
        for cPlugin in plugins:
            try:
                if cPlugin.macroOnly:
                    oPlugin = cPlugin(filename, data, options.pluginoptions)
                elif not cPlugin.macroOnly:
                    oPlugin = cPlugin(filename, data, options.pluginoptions)
                else:
                    oPlugin = None
            except Exception as e:
                print("Error instantiating plugin: %s" % cPlugin.name)
                if options.verbose:
                    raise e
                return returnCode
            if oPlugin != None:
                result = oPlugin.Analyze()
                if oPlugin.ran:
                    if options.quiet:
                        for line in result:
                            print(MyRepr(line))
                    else:
                        print("Plugin: %s " % oPlugin.name)
                        for line in result:
                            print(" " + MyRepr(line))
        return returnCode

    rules = None
    if options.yara != None:
        if not "yara" in sys.modules:
            print("Error: option yara requires the YARA Python module.")
            if sys.version >= "2.7.9":
                print(
                    "You can use PIP to install yara-python like this: pip install yara-python\npip is located in Python's Scripts folder.\n"
                )
            return returnCode
        rules, rulesVerbose = YARACompile(options.yara)
        if options.verbose:
            print(rulesVerbose)

    if filename == "":
        if_win32_setbinary(sys.stdin)
        if sys.version_info[0] > 2:
            oStringIO = DataIO(sys.stdin.buffer.read())
        else:
            oStringIO = DataIO(sys.stdin.read())
    elif filename.lower().endswith(".zip"):
        oZipfile = CreateZipFileObject(filename, "r")
        try:
            oZipContent = oZipfile.open(oZipfile.infolist()[0], "r", C2BIP3(options.password))
        except NotImplementedError:
            print(
                "This ZIP file is possibly not readable with module zipfile.\nTry installing module pyzipper: pip install pyzipper"
            )
            return returnCode
        oStringIO = DataIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = DataIO(open(filename, "rb").read())

    if options.find != "":
        filecontent = oStringIO.read()
        locations = find_all(filecontent, OLEFILE_MAGIC)
        if len(locations) == 0:
            print("No embedded OLE files found")
        else:
            if options.find == "l":
                print("Position of potential embedded OLE files:")
                for index, position in enumerate(locations):
                    print(" %d 0x%08x" % (index + 1, position))
            else:
                index = int(options.find)
                if index <= 0 or index > len(locations):
                    print("Wrong index, must be between 1 and %d" % len(locations))
                else:
                    ole = olefile.OleFileIO(DataIO(filecontent[locations[int(options.find) - 1] :]))
                    returnCode, selectionCounter = OLESub(ole, b"", "", rules, options)
                    PrintWarningSelection(options.select, selectionCounter)
                    ole.close()
    else:
        magic = oStringIO.read(6)
        oStringIO.seek(0)
        if magic[0:4] == OLEFILE_MAGIC:
            ole = olefile.OleFileIO(oStringIO)
            oStringIO.seek(0)
            returnCode, selectionCounter = OLESub(ole, oStringIO.read(), "", rules, options)
            PrintWarningSelection(options.select, selectionCounter)
            ole.close()
        elif magic[0:2] == b"PK":
            oZipfile = CreateZipFileObject(oStringIO, "r")
            counter = 0
            selectionCounterTotal = 0
            oleFileFound = False
            OPCFound = False
            for info in oZipfile.infolist():
                oZipContent = oZipfile.open(info, "r")
                content = oZipContent.read()
                if info.filename == "[Content_Types].xml":
                    OPCFound = True
                if content[0:4] == OLEFILE_MAGIC:
                    letter = chr(P23Ord("A") + counter)
                    counter += 1
                    if options.select == "":
                        if not options.quiet and not options.jsonoutput:
                            print("%s: %s" % (letter, info.filename))
                    ole = olefile.OleFileIO(DataIO(content))
                    returnCodeSub, selectionCounter = OLESub(ole, content, letter, rules, options)
                    returnCode = max(returnCode, returnCodeSub)
                    selectionCounterTotal += selectionCounter
                    oleFileFound = True
                    ole.close()
                oZipContent.close()
            if not oleFileFound:
                print(
                    "Warning: no OLE file was found inside this ZIP container%s"
                    % IFF(OPCFound, " (OPC)", "")
                )
            PrintWarningSelection(options.select, selectionCounterTotal)
            oZipfile.close()
        else:
            data = oStringIO.read()
            oStringIO.seek(0)
            if (
                b"<?xml" in data
                and not b"<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
                in data
            ):
                try:
                    oXML = xml.dom.minidom.parse(oStringIO)
                except:
                    print("Error: parsing %s as XML." % filename)
                    return -1
                counter = 0
                for oElement in oXML.getElementsByTagName("*"):
                    if oElement.firstChild and oElement.firstChild.nodeValue:
                        try:
                            data = binascii.a2b_base64(oElement.firstChild.nodeValue)
                        except binascii.Error:
                            data = ""
                        except UnicodeEncodeError:
                            data = ""
                        content = C2BIP3(data)
                        if content.startswith(ACTIVEMIME_MAGIC):
                            content = HeuristicZlibDecompress(content)
                        if content[0:4] == OLEFILE_MAGIC:
                            letter = chr(P23Ord("A") + counter)
                            counter += 1
                            if options.select == "":
                                if not options.quiet:
                                    nameValue = ""
                                    for key, value in oElement.attributes.items():
                                        if key.endswith(":name"):
                                            nameValue = value
                                            break
                                    print("%s: %s" % (letter, nameValue))
                            ole = olefile.OleFileIO(DataIO(content))
                            returnCodeSub, selectionCounter = OLESub(
                                ole, content, letter, rules, options
                            )
                            returnCode = max(returnCode, returnCodeSub)
                            PrintWarningSelection(options.select, selectionCounter)
                            ole.close()
            elif data.startswith(ACTIVEMIME_MAGIC):
                content = HeuristicZlibDecompress(data)
                if content[0:4] == OLEFILE_MAGIC:
                    ole = olefile.OleFileIO(DataIO(content))
                    returnCode, selectionCounter = OLESub(ole, content, "", rules, options)
                    PrintWarningSelection(options.select, selectionCounter)
                    ole.close()
            else:
                print("Error: %s is not a valid OLE file." % filename)

    return returnCode
