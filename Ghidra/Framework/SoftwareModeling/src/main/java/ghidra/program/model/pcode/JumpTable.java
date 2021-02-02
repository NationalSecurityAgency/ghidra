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

import java.util.ArrayList;

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * JumpTable found as part of the decompilation of a function
 * 
 * 
 *
 */

public class JumpTable {

	/** 
	 * Translate address into preferred memory space (JumpTable.preferredSpace) 
	 * @param addr is the given Address
	 * @return preferred address or original addr
	 */
	private Address translateOverlayAddress(Address addr) {
		if (addr != null && preferredSpace.isOverlaySpace()) {
			OverlayAddressSpace overlaySpace = (OverlayAddressSpace) preferredSpace;
			return overlaySpace.getOverlayAddress(addr);
		}
		return addr;
	}

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

		public void restoreXml(XmlPullParser parser, AddressFactory addrFactory) {
			XmlElement el = parser.start("loadtable");
			size = SpecXmlUtils.decodeInt(el.getAttribute("size"));
			num = SpecXmlUtils.decodeInt(el.getAttribute("num"));
			XmlElement subel = parser.start("addr");
			addr = translateOverlayAddress(AddressXML.readXML(subel, addrFactory));
			parser.end(subel);
			parser.end(el);
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

		public void buildXml(StringBuilder buf) {
			buf.append("<basicoverride>\n");
			for (Address element : destlist) {
				buf.append("<dest");
				AddressXML.appendAttributes(buf, element);
				buf.append("/>\n");
			}
			// We could add  <normaddr> and <normhash> tags to specify switch variable
			// We could add a <startval> tag to indicate starting value of the switch variable
			buf.append("</basicoverride>\n");
		}
	}

	private AddressSpace preferredSpace;
	private Address opAddress;

	// Address corresponds to label entries.  If DEFAULT_VALUE, then entry is the default guard case, not a jump target.
	private Address addressTable[];
	private Integer labelTable[];
	private LoadTable loadTable[];
	private BasicOverride override;

	public JumpTable(AddressSpace preferredSpace) {
		this.preferredSpace = preferredSpace;
		opAddress = null;
		addressTable = null;
		labelTable = null;
		loadTable = null;
		override = null;
	}

	public JumpTable(Address addr, ArrayList<Address> destlist, boolean override) {
		opAddress = addr;
		preferredSpace = opAddress.getAddressSpace();
		labelTable = null;
		loadTable = null;
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
	 * Create a JumpTable object by parsing the XML elements
	 * @param parser is the XML parser
	 * @param addrFactory is used to look-up address spaces
	 * @throws PcodeXMLException for improperly formed XML
	 */
	public void restoreXml(XmlPullParser parser, AddressFactory addrFactory)
			throws PcodeXMLException {
		XmlElement el = parser.start("jumptable");
		try {
			ArrayList<Address> aTable = new ArrayList<>();
			ArrayList<Integer> lTable = new ArrayList<>();
			ArrayList<LoadTable> ldTable = new ArrayList<>();

			if (!parser.peek().isStart()) {		// Empty jumptable
				return;
			}

			XmlElement addrel = parser.start("addr");
			Address switchAddr = translateOverlayAddress(AddressXML.readXML(addrel, addrFactory));
			parser.end(addrel);

			while (parser.peek().isStart()) {
				if (parser.peek().getName().equals("dest")) {
					XmlElement subel = parser.start("dest");
					Address caseAddr =
						translateOverlayAddress(AddressXML.readXML(subel, addrFactory));
					aTable.add(caseAddr);
					String slabel = subel.getAttribute("label");
					if (slabel != null) {
						int label = SpecXmlUtils.decodeInt(slabel);
						lTable.add(label);
					}
					parser.end(subel);
				}
				else if (parser.peek().getName().equals("loadtable")) {
					LoadTable loadtable = new LoadTable();
					loadtable.restoreXml(parser, addrFactory);
					ldTable.add(loadtable);
				}
				else {
					parser.discardSubTree();
				}
			}

			opAddress = switchAddr;
			addressTable = new Address[aTable.size()];
			aTable.toArray(addressTable);
			labelTable = new Integer[lTable.size()];
			lTable.toArray(labelTable);
			loadTable = new LoadTable[ldTable.size()];
			ldTable.toArray(loadTable);
		}
		finally {
			parser.end(el);
		}
	}

	public void buildXml(StringBuilder buf) {
		buf.append("<jumptable>\n");
		AddressXML.buildXML(buf, opAddress);
		buf.append('\n');
		if (addressTable != null) {
			for (Address element : addressTable) {
				buf.append("<dest");
				AddressXML.appendAttributes(buf, element);
				buf.append("/>\n");
			}
		}
		if (override != null) {
			override.buildXml(buf);
		}
		buf.append("</jumptable>\n");
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

	public void writeOverride(Function func) throws InvalidInputException {
		if (override == null) {
			throw new InvalidInputException("Jumptable is not an override");
		}
		Address[] destlist = override.getDestinations();
		if (destlist.length == 0) {
			throw new InvalidInputException("Jumptable has no destinations");
		}
		if (!func.getBody().contains(opAddress)) {
			throw new InvalidInputException("Switch is not in function body");
		}
		Program program = func.getProgram();
		SymbolTable symtab = program.getSymbolTable();

		Namespace space = HighFunction.findCreateOverrideSpace(func);
		if (space == null) {
			throw new InvalidInputException("Could not create \"override\" namespace");
		}
		space = HighFunction.findCreateNamespace(symtab, space, "jmp_" + opAddress.toString());

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
	}

	public static JumpTable readOverride(Namespace space, SymbolTable symtab) {
		Address branchind = null;
		ArrayList<Address> destlist = new ArrayList<>();
		SymbolIterator iter = symtab.getSymbols(space);
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
		}
		if ((branchind != null) && (destlist.size() > 0)) {
			return new JumpTable(branchind, destlist, true);
		}
		return null;
	}

}
