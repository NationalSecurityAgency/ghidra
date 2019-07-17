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
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.pcodeCPort.translate.BadDataError;
import ghidra.sleigh.grammar.Location;

public class NameSymbol extends ValueSymbol {

	private VectorSTL<String> nametable = new VectorSTL<>();
	private boolean tableisfilled;

	public NameSymbol(Location location) {
		super(location);
	} // For use with restoreXml

	public NameSymbol(Location location, String nm, PatternValue pv, VectorSTL<String> nt) {
		super(location, nm, pv);
		nametable = nt;
		checkTableFill();
	}

	private void checkTableFill() {
		// Check if all possible entries in the table have been filled
		long min = patval.minValue();
		long max = patval.maxValue();
		tableisfilled = (min >= 0) && (max < nametable.size());
		for (int i = 0; i < nametable.size(); ++i) {
			if (nametable.get(i) == null) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public Constructor resolve(ParserWalker pos) {
		if (!tableisfilled) {
			int ind = (int) patval.getValue(pos);
			if ((ind >= nametable.size()) || (ind < 0) || (nametable.get(ind).length() == 0)) {
				throw new BadDataError(
					"No corresponding entry in nametable <" + getName() + ">, index=" + ind);
			}
		}
		return null;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.name_symbol;
	}

	@Override
	public void print(PrintStream s, ParserWalker pos)

	{
		int ind = (int) patval.getValue(pos);
		// ind is already checked to be in range by the resolve routine
		s.print(nametable.get(ind));
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<name_sym");
		saveSleighSymbolXmlHeader(s);
		s.println(">");
		patval.saveXml(s);
		for (int i = 0; i < nametable.size(); ++i) {
			String name = nametable.get(i);
			if (name != null) {
				s.append("<nametab name=\"");
				s.append(name);
				s.println("\"/>");
			}
			else {
				s.println("<nametab/>");
			}
		}
		s.println("</name_sym>");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<name_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.println("/>");
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
			nametable.push_back(child.getAttributeValue("name"));
		}
		checkTableFill();
	}

}
