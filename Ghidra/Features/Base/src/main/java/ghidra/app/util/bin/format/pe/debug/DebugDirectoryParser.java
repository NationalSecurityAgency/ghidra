/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.OffsetValidator;

import java.io.IOException;
import java.util.ArrayList;

/**
 * A helper class to parsing different types of 
 * debug information from a debug directory
 */
public class DebugDirectoryParser {

	/**
	 * Unknown debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_UNKNOWN = 0;
	/**
	 * COFF debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_COFF = 1;
	/**
	 * CodeView debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_CODEVIEW = 2;
	/**
	 * FPO debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_FPO = 3;
	/**
	 * Misc debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_MISC = 4;
	/**
	 * Exception debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_EXCEPTION = 5;
	/**
	 * Fixup debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_FIXUP = 6;
	/**
	 * OMAP-To-Source debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7;
	/**
	 * OMAP-From-Source debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8;
	/**
	 * Borland debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_BORLAND = 9;
	/**
	 * Reserved debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_RESERVED10 = 10;
	/**
	 * CLS ID debug type.
	 */
	public final static byte IMAGE_DEBUG_TYPE_CLSID = 11;

	private ArrayList<DebugDirectory> debugFormatList = new ArrayList<DebugDirectory>();
	private DebugMisc miscDebug;
	private DebugCodeView codeViewDebug;
	private DebugCOFFSymbolsHeader coffDebug;
	private DebugFixup fixupDebug;

	/**
	 * Constructs a new debug directory parser.
	 * @param reader the binary reader
	 * @param ptr the pointer into the binary reader
	 * @param size the size of the directory
	 * @param validator the validator for the directory
	 * @throws IOException if an I/O error occurs
	 */
	public static DebugDirectoryParser createDebugDirectoryParser(
			FactoryBundledWithBinaryReader reader, long ptr, int size, OffsetValidator validator)
			throws IOException {
		DebugDirectoryParser debugDirectoryParser =
			(DebugDirectoryParser) reader.getFactory().create(DebugDirectoryParser.class);
		debugDirectoryParser.initDebugDirectoryParser(reader, ptr, size, validator);
		return debugDirectoryParser;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DebugDirectoryParser() {
	}

	private void initDebugDirectoryParser(FactoryBundledWithBinaryReader reader, long ptr,
			int size, OffsetValidator validator) throws IOException {
		int debugFormatsCount = size / DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY;

		for (int i = 0; i < debugFormatsCount; ++i) {
			DebugDirectory debugDir = DebugDirectory.createDebugDirectory(reader, ptr, validator);
			if (debugDir.getSizeOfData() == 0)
				break;

			ptr += DebugDirectory.IMAGE_SIZEOF_DEBUG_DIRECTORY;

			switch (debugDir.getType()) {
				case IMAGE_DEBUG_TYPE_CLSID:
					debugDir.setDescription("CLSID");
					break;
				case IMAGE_DEBUG_TYPE_RESERVED10:
					debugDir.setDescription("Reserved");
					break;
				case IMAGE_DEBUG_TYPE_BORLAND:
					debugDir.setDescription("Borland");
					break;
				case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
					debugDir.setDescription("OMAPfromSrc");
					break;
				case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
					debugDir.setDescription("OMAPtoSrc");
					break;
				case IMAGE_DEBUG_TYPE_FIXUP:
					debugDir.setDescription("Fixup");
					fixupDebug = DebugFixup.createDebugFixup(reader, debugDir, validator);
					break;
				case IMAGE_DEBUG_TYPE_EXCEPTION:
					debugDir.setDescription("Exception");
					break;
				case IMAGE_DEBUG_TYPE_MISC:
					debugDir.setDescription("Misc");
					miscDebug = DebugMisc.createDebugMisc(reader, debugDir, validator);
					break;
				case IMAGE_DEBUG_TYPE_FPO:
					debugDir.setDescription("FPO");
					break;
				case IMAGE_DEBUG_TYPE_CODEVIEW:
					debugDir.setDescription("CodeView");
					codeViewDebug = DebugCodeView.createDebugCodeView(reader, debugDir, validator);
					break;
				case IMAGE_DEBUG_TYPE_COFF:
					debugDir.setDescription("COFF");
					coffDebug =
						DebugCOFFSymbolsHeader.createDebugCOFFSymbolsHeader(reader, debugDir,
							validator);
					break;
				case IMAGE_DEBUG_TYPE_UNKNOWN:
					debugDir.setDescription("Unknown");
					break;
				default:
					debugDir.setDescription("DebugType-" + debugDir.getType());
					break;
			}
			debugFormatList.add(debugDir);
		}
	}

	public DebugDirectory[] getDebugDirectories() {
		DebugDirectory[] ddArr = new DebugDirectory[debugFormatList.size()];
		debugFormatList.toArray(ddArr);
		return ddArr;
	}

	/**
	 * Returns the miscellaneous debug information, or null if it does not exists.
	 * @return the miscellaneous debug information
	 */
	public DebugMisc getDebugMisc() {
		return miscDebug;
	}

	/**
	 * Returns the CodeView debug information, or null if it does not exists.
	 * @return the CodeView debug information
	 */
	public DebugCodeView getDebugCodeView() {
		return codeViewDebug;
	}

	/**
	 * Returns the COFF debug information, or null if it does not exists.
	 * @return the COFF debug information
	 */
	public DebugCOFFSymbolsHeader getDebugCOFFSymbolsHeader() {
		return coffDebug;
	}

	/**
	 * Returns the Fixup debug information, or null if it does not exists.
	 * @return the Fixup debug information
	 */
	public DebugFixup getDebugFixup() {
		return fixupDebug;
	}
}
