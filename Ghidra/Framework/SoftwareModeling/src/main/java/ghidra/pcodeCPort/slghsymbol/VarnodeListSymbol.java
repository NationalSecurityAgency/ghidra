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
package ghidra.pcodeCPort.slghsymbol;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

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
