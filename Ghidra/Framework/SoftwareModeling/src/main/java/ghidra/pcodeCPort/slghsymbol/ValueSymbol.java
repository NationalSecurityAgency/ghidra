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

import ghidra.pcodeCPort.context.FixedHandle;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;
import java.util.List;

import org.jdom.Element;

public class ValueSymbol extends FamilySymbol {

	protected PatternValue patval;

	public ValueSymbol(Location location) {
		super(location);
		patval = null;
	} // For use with restoreXml

	public ValueSymbol(Location location, String nm, PatternValue pv) {
		super(location, nm);
		patval = pv;
		patval.layClaim();
	}

	@Override
	public PatternValue getPatternValue() {
		return patval;
	}

	@Override
	public PatternExpression getPatternExpression() {
		return patval;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.value_symbol;
	}

	@Override
	public void dispose() {
		if (patval != null) {
			PatternExpression.release(patval);
		}
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		hand.space = pos.getConstSpace();
		hand.offset_space = null;
		hand.offset_offset = patval.getValue(pos);
		hand.size = 0; // Cannot provide size
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		long val = patval.getValue(pos);
		if (val >= 0) {
			s.append("0x");
			s.append(Long.toHexString(val));
		}
		else {
			s.append("-0x");
			s.append(Long.toHexString(-val));
		}
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<value_sym");
		saveSleighSymbolXmlHeader(s);
		s.println(">");
		patval.saveXml(s);
		s.println("</value_sym>");
	}

	@Override
	public void saveXmlHeader(PrintStream s)

	{
		s.append("<value_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.println("/>");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		List<?> list = el.getChildren();
		Element child = (Element) list.get(0);
		patval = (PatternValue) PatternExpression.restoreExpression(child, trans);
		patval.layClaim();
	}

}
