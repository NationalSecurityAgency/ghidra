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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public abstract class HighSymbol {
	
	public static final long ID_BASE = 0x4000000000000000L;	// Put keys in the dynamic symbol portion of the key space
	protected String name;
	protected DataType type;
	protected int size;				// Size of this variable
	protected Address pcaddr;			// first-use address
	protected HighFunction function;	// associated function
	private boolean namelock;		// Is this variable's name locked
	private boolean typelock;		// Is this variable's datatype locked
	private boolean readonly;
	private long id;				// Unique id of this symbol
	
	private HighVariable highVariable;

	public HighSymbol() {	// For use with restoreXML
	}

	public HighSymbol(long uniqueId, String nm, DataType tp, int sz, Address pc,
			HighFunction func) {
		name = nm;
		type = tp;
		size = sz;
		pcaddr = pc;
		namelock = false;
		typelock = false;
		function = func;
		id = uniqueId;
	}

	public long getId() {
		return id;
	}

	public void setHighVariable(HighVariable high) {
		this.highVariable = high;
	}
	
	public HighVariable getHighVariable() {
		return highVariable;
	}

	public String getName() {
		return name;
	}
	
	public DataType getDataType() {
		return type;
	}

	public int getSize() {
		return size;
	}
	
	public Address getPCAddress() {
		return pcaddr;
	}

	public HighFunction getHighFunction() {
		return function;
	}

	public void setTypeLock(boolean typelock) {
		this.typelock = typelock;
	}

	public void setNameLock(boolean namelock) {
		this.namelock = namelock;
	}
	
	public void setReadOnly(boolean readOnly) {
		this.readonly = readOnly;
	}
	
	public boolean isTypeLocked() {
		return typelock;
	}

	public boolean isNameLocked() {
		return namelock;
	}
	
	public boolean isReadOnly() {
		return readonly;
	}

	public abstract String buildXML();
	
	public abstract void restoreXML(XmlPullParser parser, HighFunction func)
			throws PcodeXMLException;
	
	protected void restoreSymbolXML(XmlElement symel, HighFunction func) throws PcodeXMLException {
		function = func;
		id = SpecXmlUtils.decodeLong(symel.getAttribute("id"));
		if (id == 0) {
			throw new PcodeXMLException("missing unique symbol id");
		}
		typelock = false;
		String typelockstr = symel.getAttribute("typelock");
		if ((typelockstr != null) && (SpecXmlUtils.decodeBoolean(typelockstr))) {
			typelock = true;
		}
		namelock = false;
		String namelockstr = symel.getAttribute("namelock");
		if ((namelockstr != null) && (SpecXmlUtils.decodeBoolean(namelockstr))) {
			namelock = true;
		}
		name = symel.getAttribute("name");
	}

	protected Address parseRangeList(XmlPullParser parser) {
		Address addr = null;
		XmlElement rangelistel = parser.start("rangelist");
		if (parser.peek().isStart()) {
			// we only use this to establish first-use
			XmlElement rangeel = parser.start("range");
			String spc = rangeel.getAttribute("space");
			long offset = SpecXmlUtils.decodeLong(rangeel.getAttribute("first"));
			addr = function.getAddressFactory().getAddressSpace(spc).getAddress(offset);
			addr = function.getFunction().getEntryPoint().getAddressSpace().getOverlayAddress(addr);
			parser.end(rangeel);
		}

		parser.end(rangelistel);
		return addr;
	}

	public static void buildMapSymXML(StringBuilder res, String addrHashRes, Address pc, String sym) {
		res.append("<mapsym>\n");
		res.append(sym);
		res.append(addrHashRes);
		if (pc == null || pc.isExternalAddress()) {
			res.append("<rangelist/>");
		}
		else {
			buildRangelistXML(res, pc);
		}
		res.append("</mapsym>\n");
	}

	public static void buildRangelistXML(StringBuilder res, Address pc) {
		res.append("<rangelist>");
		if (pc != null) {
			AddressSpace space = pc.getAddressSpace();
			if (space.isOverlaySpace()) {
				space = space.getPhysicalSpace();
				pc = space.getAddress(pc.getOffset());
			}
			res.append("<range");
			SpecXmlUtils.encodeStringAttribute(res, "space", space.getName());
			long off = pc.getUnsignedOffset();
			SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "first", off);
			SpecXmlUtils.encodeUnsignedIntegerAttribute(res, "last", off);
			res.append("/>");
		}
		res.append("</rangelist>\n");
	}
}
