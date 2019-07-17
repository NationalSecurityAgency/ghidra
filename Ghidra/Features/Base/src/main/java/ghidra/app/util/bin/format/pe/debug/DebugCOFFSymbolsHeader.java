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

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OffsetValidator;
import ghidra.util.Msg;

import java.io.IOException;

/**
 * A class to represent the COFF Symbols Header.
 * <br>
 * <pre>
 * typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
 *   DWORD   NumberOfSymbols;
 *   DWORD   LvaToFirstSymbol;
 *   DWORD   NumberOfLinenumbers;
 *   DWORD   LvaToFirstLinenumber;
 *   DWORD   RvaToFirstByteOfCode;
 *   DWORD   RvaToLastByteOfCode;
 *   DWORD   RvaToFirstByteOfData;
 *   DWORD   RvaToLastByteOfData;
 * } IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;
 * </pre>
 */
public class DebugCOFFSymbolsHeader {
	private int numberOfSymbols;
	private int lvaToFirstSymbol;
	private int numberOfLinenumbers;
	private int lvaToFirstLinenumber;
	private int rvaToFirstByteOfCode;
	private int rvaToLastByteOfCode;
	private int rvaToFirstByteOfData;
	private int rvaToLastByteOfData;

	private DebugCOFFSymbolTable symbolTable;
	private DebugCOFFLineNumber[] lineNumbers;

	/**
	 * Constructor
	 * @param reader the binary reader
	 * @param debugDir the debug directory associated to this COFF symbol header
	 * @param ntHeader 
	 */
	static DebugCOFFSymbolsHeader createDebugCOFFSymbolsHeader(
			FactoryBundledWithBinaryReader reader, DebugDirectory debugDir,
			OffsetValidator validator) throws IOException {
		DebugCOFFSymbolsHeader debugCOFFSymbolsHeader =
			(DebugCOFFSymbolsHeader) reader.getFactory().create(DebugCOFFSymbolsHeader.class);
		debugCOFFSymbolsHeader.initDebugCOFFSymbolsHeader(reader, debugDir, validator);
		return debugCOFFSymbolsHeader;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public DebugCOFFSymbolsHeader() {
	}

	private void initDebugCOFFSymbolsHeader(FactoryBundledWithBinaryReader reader,
			DebugDirectory debugDir, OffsetValidator validator) throws IOException {
		int ptr = debugDir.getPointerToRawData();
		if (!validator.checkPointer(ptr)) {
			Msg.error(this, "Invalid pointer " + Long.toHexString(ptr));
			return;
		}

		numberOfSymbols = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		lvaToFirstSymbol = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		numberOfLinenumbers = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		lvaToFirstLinenumber = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		rvaToFirstByteOfCode = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		rvaToLastByteOfCode = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		rvaToFirstByteOfData = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;
		rvaToLastByteOfData = reader.readInt(ptr);
		ptr += BinaryReader.SIZEOF_INT;

		if (numberOfLinenumbers > 0 && numberOfLinenumbers < NTHeader.MAX_SANE_COUNT) {
			lineNumbers = new DebugCOFFLineNumber[numberOfLinenumbers];
			for (int i = 0; i < numberOfLinenumbers; ++i) {
				lineNumbers[i] = DebugCOFFLineNumber.createDebugCOFFLineNumber(reader, ptr);
				ptr += DebugCOFFLineNumber.IMAGE_SIZEOF_LINENUMBER;
			}
		}

		symbolTable =
			DebugCOFFSymbolTable.createDebugCOFFSymbolTable(reader, this,
				debugDir.getPointerToRawData());
	}

	/**
	 * Returns the COFF symbol table.
	 * @return the COFF symbol table
	 */
	public DebugCOFFSymbolTable getSymbolTable() {
		return symbolTable;
	}

	/**
	 * Returns the COFF line numbers.
	 * @return the COFF line numbers
	 */
	public DebugCOFFLineNumber[] getLineNumbers() {
		return lineNumbers;
	}

	/**
	 * Returns the number of symbols in this header.
	 * @return the number of symbols in this header
	 */
	public int getNumberOfSymbols() {
		return numberOfSymbols;
	}

	/**
	 * Returns the LVA of the first symbol.
	 * @return the LVA of the first symbol
	 */
	public int getFirstSymbolLVA() {
		return lvaToFirstSymbol;
	}

	/**
	 * Returns the number of line numbers in this header.
	 * @return the number of line numbers in this header
	 */
	public int getNumberOfLinenumbers() {
		return numberOfLinenumbers;
	}

	/**
	 * Returns the LVA of the first line number.
	 * @return the LVA of the first line number
	 */
	public int getFirstLinenumberLVA() {
		return lvaToFirstLinenumber;
	}

	/**
	 * Returns the RVA of the first code byte.
	 * @return the RVA of the first code byte
	 */
	public int getFirstByteOfCodeRVA() {
		return rvaToFirstByteOfCode;
	}

	/**
	 * Returns the RVA of the last code byte.
	 * @return the RVA of the last code byte
	 */
	public int getLastByteOfCodeRVA() {
		return rvaToLastByteOfCode;
	}

	/**
	 * Returns the RVA of the first data byte.
	 * @return the RVA of the first data byte
	 */
	public int getFirstByteOfDataRVA() {
		return rvaToFirstByteOfData;
	}

	/**
	 * Returns the RVA of the last data byte.
	 * @return the RVA of the last data byte
	 */
	public int getLastByteOfDataRVA() {
		return rvaToLastByteOfData;
	}
}
