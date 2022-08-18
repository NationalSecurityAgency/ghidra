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
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

public class ValueMapSymbol extends ValueSymbol {
	private VectorSTL<Long> valuetable = new VectorSTL<Long>();
	private boolean tableisfilled;

	public ValueMapSymbol(Location location) {
		super(location);
	}

	public ValueMapSymbol(Location location, String nm, PatternValue pv, VectorSTL<Long> vt) {
		super(location, nm, pv);
		valuetable = new VectorSTL<Long>(vt);
		checkTableFill();
	}

	@Override
	public symbol_type getType() {
		return symbol_type.valuemap_symbol;
	}

	private void checkTableFill() {
		// Check if all possible entries in the table have been filled
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < valuetable.size());
		for (int i = 0; i < valuetable.size(); ++i) {
			if (valuetable.get(i) == 0xBADBEEF) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<valuemap_sym");
		saveSleighSymbolXmlHeader(s);
		s.append(">\n");
		patval.saveXml(s);
		for (int i = 0; i < valuetable.size(); ++i) {
			s.append("<valuetab val=\"").append(Long.toString(valuetable.get(i))).append("\"/>\n");
		}
		s.append("</valuemap_sym>\n");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<valuemap_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		List<?> list = el.getChildren();
		Iterator<?> iter = list.iterator();
		Element element = (Element) iter.next();
		patval = (PatternValue) PatternExpression.restoreExpression(element, trans);
		patval.layClaim();
		while (iter.hasNext()) {
			Element child = (Element) iter.next();
			long value = XmlUtils.decodeUnknownLong(child.getAttributeValue("val"));
			valuetable.push_back(value);
		}
		checkTableFill();

	}

}
