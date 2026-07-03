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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

/**
 * JumpTable found as part of the decompilation of a function
 * 
 * 
 *
 */

public class JumpTable {

	public class LoadTable {
		Address addr;		// Starting address of table
		int size;			// Size of a table entry in bytes
		int num;				// Number of entries in table

		LoadTable() {
		}

		/**
		 * @return Starting address of table
		 */
		public Address getAddress() {
			return addr;
		}

		/**
		 * @return Size of a table entry in bytes
		 */
		public int getSize() {
			return size;
		}

		/**
		 * @return Number of entries in table
		 */
		public int getNum() {
			return num;
		}

		public void decode(Decoder decoder) throws DecoderException {
			int el = decoder.openElement(ELEM_LOADTABLE);
			size = (int) decoder.readSignedInteger(ATTRIB_SIZE);
			num = (int) decoder.readSignedInteger(ATTRIB_NUM);
			addr = AddressXML.decode(decoder);
			decoder.closeElement(el);
		}
	}

	public class BasicOverride {
		private Address[] destlist;		// List of jump destinations, must be addresses of instructions

		public BasicOverride(ArrayList<Address> dlist) {
			destlist = new Address[dlist.size()];
			dlist.toArray(destlist);
		}

		public Address[] getDestinations() {
			return destlist;
		}

		public void encode(Encoder encoder) throws IOException {
			encoder.openElement(ELEM_BASICOVERRIDE);
			for (Address element : destlist) {
				encoder.openElement(ELEM_DEST);
				AddressXML.encodeAttributes(encoder, element);
				encoder.closeElement(ELEM_DEST);
			}
			// We could add  <normaddr> and <normhash> elements to specify switch variable
			// We could add a <startval> tag to indicate starting value of the switch variable
			encoder.closeElement(ELEM_BASICOVERRIDE);
		}
	}

	private Address opAddress;

	// Address corresponds to label entries.  If DEFAULT_VALUE, then entry is the default guard case, not a jump target.
	private Address addressTable[];
	private Integer labelTable[];
	private LoadTable loadTable[];
	private BasicOverride override;
	private int displayFormat;		// Default format for displaying integer case values

	public JumpTable() {
		opAddress = null;
		addressTable = null;
		labelTable = null;
		loadTable = null;
		override = null;
		displayFormat = 0;
	}

	public JumpTable(Address addr, ArrayList<Address> destlist, boolean override, int format) {
		opAddress = addr;
		labelTable = null;
		loadTable = null;
		displayFormat = format;
		if (override) {
			addressTable = null;
			this.override = new BasicOverride(destlist);
		}
		else {
			addressTable = new Address[destlist.size()];
			destlist.toArray(addressTable);
			this.override = null;
		}
	}

	public boolean isEmpty() {
		if (addressTable == null) {
			return true;
		}
		if (addressTable.length == 0) {
			return true;
		}
		return false;
	}

	/**
	 * Decode a JumpTable object from the stream.
	 * @param decoder is the stream decoder
	 * @throws DecoderException for invalid encodings
	 */
	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_JUMPTABLE);
		if (decoder.getNextAttributeId() == ATTRIB_FORMAT.id()) {
			displayFormat = (int) decoder.readUnsignedInteger();
		}
		if (decoder.peekElement() == 0) {		// Empty jumptable
			decoder.closeElement(el);
			return;
		}
		ArrayList<Address> aTable = new ArrayList<>();
		ArrayList<Integer> lTable = new ArrayList<>();
		ArrayList<LoadTable> ldTable = new ArrayList<>();

		Address switchAddr = AddressXML.decode(decoder);

		for (;;) {
			int subel = decoder.peekElement();
			if (subel == 0) {
				break;
			}
			if (subel == ELEM_DEST.id()) {
				decoder.openElement();
				Address caseAddr = AddressXML.decodeFromAttributes(decoder);
				aTable.add(caseAddr);
				decoder.rewindAttributes();
				for (;;) {
					int attribId = decoder.getNextAttributeId();
					if (attribId == 0) {
						break;
					}
					if (attribId == ATTRIB_LABEL.id()) {
						int label = (int) decoder.readUnsignedInteger();
						lTable.add(label);
					}
				}
				decoder.closeElement(subel);
			}
			else if (subel == ELEM_LOADTABLE.id()) {
				LoadTable loadtable = new LoadTable();
				loadtable.decode(decoder);
				ldTable.add(loadtable);
			}
			else {
				decoder.skipElement();
			}
		}

		opAddress = switchAddr;
		addressTable = new Address[aTable.size()];
		aTable.toArray(addressTable);
		labelTable = new Integer[lTable.size()];
		lTable.toArray(labelTable);
		loadTable = new LoadTable[ldTable.size()];
		ldTable.toArray(loadTable);
		decoder.closeElement(el);
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_JUMPTABLE);
		if (displayFormat != 0) {
			encoder.writeUnsignedInteger(ATTRIB_FORMAT, displayFormat);
		}
		AddressXML.encode(encoder, opAddress);
		if (addressTable != null) {
			for (Address element : addressTable) {
				encoder.openElement(ELEM_DEST);
				AddressXML.encodeAttributes(encoder, element);
				encoder.closeElement(ELEM_DEST);
			}
		}
		if (override != null) {
			override.encode(encoder);
		}
		encoder.closeElement(ELEM_JUMPTABLE);
	}

	public Address getSwitchAddress() {
		return opAddress;
	}

	public Address[] getCases() {
		return addressTable.clone();
	}

	public Integer[] getLabelValues() {
		return labelTable.clone();
	}

	public LoadTable[] getLoadTables() {
		return loadTable.clone();
	}

	/**
	 * Find or create a namespace for a specific jumptable
	 * @param func is the function with the jumptable
	 * @param opAddress is the address of the call point using the table
	 * @param symtab is the symbol table
	 * @return the jumptable namespace
	 * @throws InvalidInputException for any problems creating the namespace
	 */
	private static Namespace getSwitchNamespace(Function func, Address opAddress,
			SymbolTable symtab)
			throws InvalidInputException {
		if (!func.getBody().contains(opAddress)) {
			throw new InvalidInputException("Switch is not in function body");
		}
		Namespace space = HighFunction.findCreateOverrideSpace(func);
		if (space == null) {
			throw new InvalidInputException("Could not create \"override\" namespace");
		}
		return HighFunction.findCreateNamespace(symtab, space, "jmp_" + opAddress.toString());
	}

	/**
	 * Get any case format override for this jumptable.
	 * @param func is the function with the jumptable
	 * @param opAddress is the address of the call point using the table
	 * @return the overriding format if it exists or EquateSymbol.FORMAT_DEFAULT otherwise
	 */
	public static int getFormatOverride(Function func, Address opAddress) {
		Namespace space = HighFunction.findOverrideSpace(func);
		if (space == null)
			return EquateSymbol.FORMAT_DEFAULT;
		SymbolTable symtab = func.getProgram().getSymbolTable();
		space = HighFunction.findNamespace(symtab, space, "jmp_" + opAddress.toString());
		if (space == null)
			return EquateSymbol.FORMAT_DEFAULT;
		SymbolIterator iter = symtab.getSymbols(space);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (sym.getName().startsWith("format")) {
				String format = sym.getName().substring(7);
				return EquateSymbol.getFormatStringValue(format);
			}
		}
		return EquateSymbol.FORMAT_DEFAULT;
	}

	/**
	 * Write/update the current display format for a JumpTable.
	 * The format is stored as a symbol with a name like "format_dec" or "format_char"
	 * Any previous existing symbol is removed.
	 * @param func is the function containing the switch
	 * @param opAddress is the address of the CALLIND
	 * @param displayFormat is the new desired format
	 * @throws InvalidInputException for problems writing to the database
	 */
	public static void writeFormat(Function func, Address opAddress, int displayFormat)
			throws InvalidInputException {
		Program program = func.getProgram();
		SymbolTable symtab = program.getSymbolTable();

		Namespace space = getSwitchNamespace(func, opAddress, symtab);
		SymbolIterator iter = symtab.getSymbols(space);
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (sym.getName().startsWith("format")) {
				HighFunction.deleteSymbol(symtab, sym.getAddress(), sym.getName(), space);
				break;
			}
		}
		if (displayFormat != EquateSymbol.FORMAT_DEFAULT) {
			String nm = "format_" + EquateSymbol.getIntegerFormatString(displayFormat);
			HighFunction.createLabelSymbol(symtab, opAddress, nm, space, SourceType.USER_DEFINED,
				false);
		}
	}

	public void writeOverride(Function func) throws InvalidInputException {
		if (override == null) {
			throw new InvalidInputException("Jumptable is not an override");
		}
		Address[] destlist = override.getDestinations();
		if (destlist.length == 0) {
			throw new InvalidInputException("Jumptable has no destinations");
		}
		Program program = func.getProgram();
		SymbolTable symtab = program.getSymbolTable();

		Namespace space = getSwitchNamespace(func, opAddress, symtab);
		if (!HighFunction.clearNamespace(symtab, space)) {
			throw new InvalidInputException(
				"Jumptable override namespace contains non-label symbols.");
		}
		HighFunction.createLabelSymbol(symtab, opAddress, "switch", space, SourceType.USER_DEFINED,
			false);
		for (int i = 0; i < destlist.length; ++i) {
			String nm = "case_" + Integer.toString(i);
			HighFunction.createLabelSymbol(symtab, destlist[i], nm, space, SourceType.USER_DEFINED,
				false);
		}
		if (displayFormat != EquateSymbol.FORMAT_DEFAULT) {
			String nm = "format_" + EquateSymbol.getIntegerFormatString(displayFormat);
			HighFunction.createLabelSymbol(symtab, opAddress, nm, space, SourceType.USER_DEFINED,
				false);
		}
	}

	public static JumpTable readOverride(Namespace space, SymbolTable symtab) {
		Address branchind = null;
		ArrayList<Address> destlist = new ArrayList<>();
		SymbolIterator iter = symtab.getSymbols(space);
		int displayFormat = 0;
		while (iter.hasNext()) {
			Symbol sym = iter.next();
			if (!(sym instanceof CodeSymbol)) {
				continue;
			}
			Address addr = sym.getAddress();
			if (sym.getName().equals("switch")) {
				branchind = addr;
			}
			else if (sym.getName().startsWith("case")) {
				destlist.add(addr);
			}
			else if (sym.getName().startsWith("format")) {
				branchind = addr;
				displayFormat = EquateSymbol.getFormatStringValue(sym.getName().substring(7));
			}
		}
		if ((branchind != null) && (destlist.size() > 0 || displayFormat != 0)) {
			boolean override = destlist.size() > 0;
			return new JumpTable(branchind, destlist, override, displayFormat);
		}
		return null;
	}

}
