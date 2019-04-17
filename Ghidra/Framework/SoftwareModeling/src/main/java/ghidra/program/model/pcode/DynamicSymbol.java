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
import ghidra.program.model.data.DataType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Decompiler symbol whose references are encoded as dynamic hashes into the PcodeSyntaxTree
 *
 */
public class DynamicSymbol extends HighSymbol {
	public static class Entry {
		public final Address pcaddr;
		public final long hash;
		public final int format;
		
		public Entry(Address addr,long h,int f) {
			pcaddr = addr;
			hash = h;
			format = f;
		}
	}

	private Entry[] refs;

	public DynamicSymbol() {		// For use with restoreXML
		refs = new Entry[0];
	}

	public DynamicSymbol(String nm,DataType tp,int size,HighFunction func,Address addr,long hash,int format) {
		super(nm,tp,size,addr,func);
		refs = new Entry[1];
		refs[0] = new Entry(addr,hash,format);
	}

	public long getHash() {
		return refs[0].hash;
	}

	public void addReference(Address addr,long hash,int format) {
		Entry[] newrefs = new Entry[refs.length + 1];
		for(int i=0;i<refs.length;++i)
			newrefs[i] = refs[i];
		newrefs[refs.length] = new Entry(addr,hash,format);
		refs = newrefs;
		if (refs.length == 1)
			pcaddr = addr;		// Store first address as official pcaddr for symbol
	}

	protected void buildHashXML(StringBuilder buf) {
		for(int i=0;i<refs.length;++i) {
			buf.append("<hash val=\"0x").append(Long.toHexString(refs[i].hash)).append("\"/>");
			buildRangelistXML(buf, refs[i].pcaddr);
		}		
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
	public int restoreXML(XmlPullParser parser, HighFunction func) throws PcodeXMLException {
		XmlElement symel = parser.start("symbol");
		int symbolId = restoreSymbolXML(symel, func);
		type = func.getDataTypeManager().readXMLDataType(parser);
		size = type.getLength();
		parser.end(symel);

		if (size == 0)
			throw new PcodeXMLException("Invalid symbol 0-sized data-type: " + type.getName());
		while(parser.peek().isStart()) {
			long hash = 0;
			int format = 0;
			XmlElement addrel = parser.start("hash");
			hash = SpecXmlUtils.decodeLong(addrel.getAttribute("val"));
			format = SpecXmlUtils.decodeInt(symel.getAttribute("format"));
			parser.end(addrel);
			Address addr = parseRangeList(parser);
			addReference(addr,hash,format);
		}
		return symbolId;
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
		if (isVolatile)
			SpecXmlUtils.encodeBooleanAttribute(res, "volatile", true);
		res.append(">\n");
		res.append(dtmanage.buildTypeRef(dt, length));
		res.append("</symbol>\n");
		return res.toString();
	}
}
