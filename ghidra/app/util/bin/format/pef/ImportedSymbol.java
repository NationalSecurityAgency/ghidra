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
package ghidra.app.util.bin.format.pef;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class ImportedSymbol extends AbstractSymbol {
	public final static int SIZEOF = 4;

	private int symbolClass;
	private int symbolNameOffset;

	private String _name;

	ImportedSymbol(BinaryReader reader, LoaderInfoHeader loader) throws IOException {
		int value = reader.readNextInt();

		symbolClass      = ((value & 0xff000000) >> 24) & 0xff;
		symbolNameOffset = ((value & 0x00ffffff));

		long offset = loader.getSection().getContainerOffset()+loader.getLoaderStringsOffset()+symbolNameOffset;
		_name = reader.readAsciiString(offset);
	}

	@Override
	public String getName() {
		return _name;
	}

	@Override
	public SymbolClass getSymbolClass() {
		return SymbolClass.get(symbolClass & 0xf);
	}
	/**
	 * The imported symbol does not have to 
	 * be present at fragment preparation time in 
	 * order for execution to continue. 
	 * @return if the symbol is weak
	 */
	public boolean isWeak() {
		return (symbolClass & kPEFWeakImportSymMask) != 0;
	}
	/**
	 * The offset (in bytes) from the beginning of the loader 
	 * string table to the null-terminated name of the symbol.
	 * @return offset to the null-terminated name of the symbol
	 */
	public int getSymbolNameOffset() {
		return symbolNameOffset;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return new TypedefDataType("ImportedSymbol", DWORD);
	}
}
