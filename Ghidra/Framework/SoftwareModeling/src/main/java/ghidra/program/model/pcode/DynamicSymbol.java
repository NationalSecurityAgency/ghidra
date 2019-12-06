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
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Decompiler symbol whose references are encoded as dynamic hashes into the PcodeSyntaxTree
 *
 */
public class DynamicSymbol extends HighSymbol {
	protected long hash;			// Hash encoding the specific Varnode
		
	public DynamicSymbol(HighFunction func) {		// For use with restoreXML
		super(func);
	}

	public DynamicSymbol(long uniqueId, String nm, DataType tp, int size, HighFunction func,
			Address addr, long hash) {
		super(uniqueId, nm, tp, size, addr, func);
		this.hash = hash;
	}

	public long getHash() {
		return hash;
	}

	protected void buildHashXML(StringBuilder buf) {
		buf.append("<hash val=\"0x").append(Long.toHexString(hash)).append("\"/>");
		buildRangelistXML(buf, pcaddr);
	}

	@Override
	public String buildXML() {
		String sym = buildSymbolXML(function.getDataTypeManager(), name, type, size,
									isTypeLocked(), isNameLocked(), isReadOnly(), false, 0);
		StringBuilder res = new StringBuilder();
		res.append("<mapsym type=\"dynamic\">\n");
		res.append(sym);
		buildHashXML(res);
		res.append("</mapsym>\n");
		return res.toString();
	}

	@Override
	public void restoreXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement symel = parser.start("symbol");
		restoreSymbolXML(symel);
		type = function.getDataTypeManager().readXMLDataType(parser);
		size = type.getLength();
		parser.end(symel);

		if (size == 0) {
			throw new PcodeXMLException("Invalid symbol 0-sized data-type: " + type.getName());
		}
		restoreEntryXML(parser);
		while(parser.peek().isStart()) {
			parser.discardSubTree();
		}
	}

	@Override
	protected void restoreEntryXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement addrel = parser.start("hash");
		hash = SpecXmlUtils.decodeLong(addrel.getAttribute("val"));
		parser.end(addrel);
		pcaddr = parseRangeList(parser);
	}

	@Override
	public VariableStorage getStorage() {
		Program program = function.getFunction().getProgram();
		try {
			return new VariableStorage(program, AddressSpace.HASH_SPACE.getAddress(getHash()),
				getSize());
		}
		catch (InvalidInputException e) {
			throw new AssertException("Unexpected exception", e);
		}
	}

	public static String buildSymbolXML(PcodeDataTypeManager dtmanage, String nm,
			DataType dt, int length, boolean tl, boolean nl, boolean ro, boolean isVolatile,
			int format) {
		StringBuilder res = new StringBuilder();
		res.append("<symbol");
		if (nm != null) {
			SpecXmlUtils.xmlEscapeAttribute(res, "name", nm);
		}
		SpecXmlUtils.encodeBooleanAttribute(res, "typelock", tl);
		SpecXmlUtils.encodeBooleanAttribute(res, "namelock", nl);
		SpecXmlUtils.encodeBooleanAttribute(res, "readonly", ro);
		if (isVolatile) {
			SpecXmlUtils.encodeBooleanAttribute(res, "volatile", true);
		}
		res.append(">\n");
		res.append(dtmanage.buildTypeRef(dt, length));
		res.append("</symbol>\n");
		return res.toString();
	}

	/**
	 * Build dynamic VariableStorage for a unique variable
	 * @param vn is the variable in the unique space
	 * @param high is the HighFunction containing the variable
	 * @return the dynamic VariableStorage
	 */
	public static VariableStorage buildDynamicStorage(Varnode vn, HighFunction high) {
		DynamicHash dynamicHash = new DynamicHash(vn, high);
		Program program = high.getFunction().getProgram();
		long ourHash = dynamicHash.getHash();
		try {
			return new VariableStorage(program, AddressSpace.HASH_SPACE.getAddress(ourHash),
				vn.getSize());
		}
		catch (InvalidInputException e) {
			throw new AssertException("Unexpected exception", e);
		}
	}
}
