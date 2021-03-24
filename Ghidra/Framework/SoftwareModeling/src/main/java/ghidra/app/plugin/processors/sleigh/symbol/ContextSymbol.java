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
/*
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A ValueSymbol that gets its semantic value from contiguous bits
 * in a VarnodeSymbol. This serves as an embedding of a ContextOp
 * into an actual Varnode and is probably only relevant at compile time
 */
public class ContextSymbol extends ValueSymbol {

	private VarnodeSymbol vn;
	private int low,high;			// Bit range of context value
	private boolean flow = true;	// indicates that context should follow flow
	
	public VarnodeSymbol getVarnode() { return vn; }
	
	/**
	 * Get starting bit of context value within its context register.
	 * @return the starting bit
	 */
	public int getLow() {
		return low;
	}

	/**
	 * Get ending bit of context value within its context register.
	 * @return the ending bit
	 */
	public int getHigh() {
		return high;
	}

	/**
	 * Get the starting bit of the context value within the "global" buffer, after
	 * the values have been packed.
	 * @return the starting bit
	 */
	public int getInternalLow() {
		return ((ContextField) patval).getStartBit();
	}

	/**
	 * Get the ending bit of the context value within the "global" buffer, after
	 * the values have been packed.
	 * @return the ending bit
	 */

	public int getInternalHigh() {
		return ((ContextField) patval).getEndBit();
	}
	public boolean followsFlow() { return flow; }
	
	@Override
    public void restoreXml(XmlPullParser parser,SleighLanguage sleigh) {
        XmlElement el = parser.start("context_sym");
		int id = SpecXmlUtils.decodeInt(el.getAttribute("varnode"));
		SymbolTable symtab = sleigh.getSymbolTable();
		vn = (VarnodeSymbol)symtab.findSymbol(id);
		low = SpecXmlUtils.decodeInt(el.getAttribute("low"));
		if (el.hasAttribute("flow")) {
			flow = SpecXmlUtils.decodeBoolean(el.getAttribute("flow"));
		}
		high = SpecXmlUtils.decodeInt(el.getAttribute("high"));
        patval = (PatternValue)PatternExpression.restoreExpression(parser,sleigh);
        parser.end(el);
	}
}
