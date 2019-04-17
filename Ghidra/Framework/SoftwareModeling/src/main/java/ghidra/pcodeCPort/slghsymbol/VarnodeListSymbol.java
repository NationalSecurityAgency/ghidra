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
package ghidra.pcodeCPort.slghsymbol;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.*;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.pcodeCPort.translate.BadDataError;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

public class VarnodeListSymbol extends ValueSymbol {

	private VectorSTL<VarnodeSymbol> varnode_table = new VectorSTL<VarnodeSymbol>();
	private boolean tableisfilled;

	public VarnodeListSymbol(Location location) {
		super(location);
	} // For use with restoreXml

	@Override
	public symbol_type getType() {
		return symbol_type.varnodelist_symbol;
	}

	public VarnodeListSymbol(Location location, String nm, PatternValue pv,
			VectorSTL<SleighSymbol> vt) {
		super(location, nm, pv);
		for (int i = 0; i < vt.size(); ++i) {
			varnode_table.push_back((VarnodeSymbol) vt.get(i));
		}
		checkTableFill();
	}

	private void checkTableFill() {
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < varnode_table.size());
		for (int i = 0; i < varnode_table.size(); ++i) {
			if (varnode_table.get(i) == null) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public Constructor resolve(ParserWalker walker) {
		if (!tableisfilled) {
			int ind = (int) patval.getValue(walker);
			if ((ind < 0) || (ind >= varnode_table.size()) || (varnode_table.get(ind) == null)) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				PrintStream s = new PrintStream(baos);
				walker.getAddr().printRaw(s);
				throw new BadDataError(walker.getAddr().getShortcut() + baos.toString() +
					": No corresponding entry in varnode list");
			}
		}
		return null;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		int ind = (int) patval.getValue(pos);
		// The resolve routine has checked that -ind- must be a valid index
		VarnodeData fix = varnode_table.get(ind).getFixedVarnode();
		hand.space = fix.space;
		hand.offset_space = null; // Not a dynamic value
		hand.offset_offset = fix.offset;
		hand.size = fix.size;
	}

	@Override
	public int getSize() {
		for (int i = 0; i < varnode_table.size(); ++i) {
			VarnodeSymbol vnsym = varnode_table.get(i); // Assume all are same size
			if (vnsym != null) {
				return vnsym.getSize();
			}
		}
		throw new SleighError("No register attached to: " + getName(), getLocation());
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		int ind = (int) patval.getValue(pos);
		if (ind >= varnode_table.size()) {
			throw new SleighError("Value out of range for varnode table", getLocation());
		}
		s.append(varnode_table.get(ind).getName());
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<varlist_sym");
		saveSleighSymbolXmlHeader(s);
		s.append(">\n");
		patval.saveXml(s);
		for (int i = 0; i < varnode_table.size(); ++i) {
			if (varnode_table.get(i) == null) {
				s.append("<null/>\n");
			}
			else {
				s.append("<var id=\"0x");
				s.append(Long.toHexString(varnode_table.get(i).getId()));
				s.append("\"/>\n");
			}
		}
		s.append("</varlist_sym>\n");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<varlist_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {

		List<?> children = el.getChildren();
		Iterator<?> iter = children.iterator();
		Element child = (Element) iter.next();
		patval = (PatternValue) PatternExpression.restoreExpression(child, trans);
		patval.layClaim();
		while (iter.hasNext()) {
			Element subel = (Element) iter.next();
			if (subel.getName().equals("var")) {
				int id1 = XmlUtils.decodeUnknownInt(subel.getAttributeValue("id"));
				varnode_table.push_back((VarnodeSymbol) trans.findSymbol(id1));
			}
			else {
				varnode_table.push_back(null);
			}
		}
		checkTableFill();
	}

}
