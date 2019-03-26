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
package ghidra.app.util.bin.format.elf;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;

public class ElfString {

	/**
	 * Read an ElfString at the readers current position.  ElfString only supports
	 * null-terminated ASCII strings.
	 * @param reader reader positioned at start of string
	 * @param stringOffset string offset from start of string table
	 * @param header Elf header object
	 * @return Elf string object
	 * @throws IOException
	 */
	public static ElfString createElfString(FactoryBundledWithBinaryReader reader, int stringOffset,
			ElfHeader header) throws IOException {
		ElfString elfString = (ElfString) reader.getFactory().create(ElfString.class);
		elfString.initElfString(reader, stringOffset, header);
		return elfString;
	}

	private ElfHeader header;
	private int stringOffset;
	private String string;

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ElfString() {
	}

	private void initElfString(FactoryBundledWithBinaryReader reader, int stringOffset,
			ElfHeader header) throws IOException {
		this.header = header;
		this.stringOffset = stringOffset;
		this.string = reader.readAsciiString(0);
	}

	/**
	 * @return string object
	 */
	public String getString() {
		return string;
	}

	/**
	 * @return string offset within string table
	 */
	public int getStringOffset() {
		return stringOffset;
	}

}
