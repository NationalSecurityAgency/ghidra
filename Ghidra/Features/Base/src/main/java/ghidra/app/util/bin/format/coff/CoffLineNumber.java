/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.coff;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class CoffLineNumber implements StructConverter {
	public final static int SIZEOF = 4 + 2;

	private int   l_addr; // address of line number
	private short l_lnno; // line number

	CoffLineNumber(BinaryReader reader) throws IOException {
		l_addr = reader.readNextInt();
		l_lnno = reader.readNextShort();
	}

	public int getAddress() {
		return l_addr;
	}

	public long getFunctionNameSymbolIndex() {
		return l_addr;
	}

	public short getLineNumber() {
		return l_lnno;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		return StructConverterUtil.toDataType(CoffLineNumber.class);
	}
}
