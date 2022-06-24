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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class TokenListStream implements StructConverter {

	public final static String NAME = "MINIDUMP_TOKEN_LIST";

	private int tokenListSize;
	private int tokenListEntries;
	private int listHeaderSize;
	private int elementHeaderSize;
	private Token[] tokens;

	private DumpFileReader reader;
	private long index;

	TokenListStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setTokenListSize(reader.readNextInt());
		setTokenListEntries(reader.readNextInt());
		setListHeaderSize(reader.readNextInt());
		setElementHeaderSize(reader.readNextInt());
		tokens = new Token[getTokenListEntries()];
		for (int i = 0; i < getTokenListEntries(); i++) {
			setToken(new Token(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "TokenListSize", null);
		struct.add(DWORD, 4, "TokenListEntries", null);
		struct.add(DWORD, 4, "ListHeaderSize", null);
		struct.add(DWORD, 4, "ElementHeaderSize", null);
		DataType t = tokens[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, getTokenListEntries(), t.getLength());
		struct.add(a, a.getLength(), "Tokens", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public Token getToken(int idx) {
		return tokens[idx];
	}

	public void setToken(Token token, int index) {
		this.tokens[index] = token;
	}

	public int getTokenListSize() {
		return tokenListSize;
	}

	public void setTokenListSize(int tokenListSize) {
		this.tokenListSize = tokenListSize;
	}

	public int getTokenListEntries() {
		return tokenListEntries;
	}

	public void setTokenListEntries(int tokenListEntries) {
		this.tokenListEntries = tokenListEntries;
	}

	public int getListHeaderSize() {
		return listHeaderSize;
	}

	public void setListHeaderSize(int listHeaderSize) {
		this.listHeaderSize = listHeaderSize;
	}

	public int getElementHeaderSize() {
		return elementHeaderSize;
	}

	public void setElementHeaderSize(int elementHeaderSize) {
		this.elementHeaderSize = elementHeaderSize;
	}
}
