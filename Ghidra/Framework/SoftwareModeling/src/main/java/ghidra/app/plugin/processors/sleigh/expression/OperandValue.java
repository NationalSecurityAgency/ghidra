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
package ghidra.app.plugin.processors.sleigh.expression;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.symbol.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * An Expression representing the value of a Constructor operand
 */
public class OperandValue extends PatternValue {
	private int index;
	private Constructor ct;

	@Override
	public int hashCode() {
		int result = 0;
		result += index;
		result *= 31;
		result += ct.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OperandValue)) {
			return false;
		}
		OperandValue that = (OperandValue) obj;
		if (this.index != that.index) {
			return false;
		}
		if (!this.ct.equals(that.ct)) {
			return false;
		}
		return true;
	}

	public OperandValue() {
	}

	public OperandValue(int i, Constructor c) {
		index = i;
		ct = c;
	}

	public int getIndex() {
		return index;
	}

	public Constructor getConstructor() {
		return ct;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.expression.PatternValue#minValue()
	 */
	@Override
	public long minValue() {
		throw new SleighException("Operand used in pattern expression");
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.expression.PatternValue#maxValue()
	 */
	@Override
	public long maxValue() {
		throw new SleighException("Operand used in pattern expression");
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.expression.PatternExpression#getValue(ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
	public long getValue(ParserWalker walker) throws MemoryAccessException {
		OperandSymbol sym = ct.getOperand(index);
		PatternExpression patexp = sym.getDefiningExpression();
		if (patexp == null) {
			TripleSymbol defSym = sym.getDefiningSymbol();
			if (defSym != null) {
				patexp = defSym.getPatternExpression();
			}
			if (patexp == null) {
				return 0;
			}
		}
		ConstructState tempstate = new ConstructState(null);
		ParserWalker newwalker = new ParserWalker(walker.getParserContext());
		newwalker.setOutOfBandState(ct, index, tempstate, walker);
		long res = patexp.getValue(newwalker);
		return res;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PatternExpression#restoreXml(org.jdom.Element)
	 */
	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.start("operand_exp");
		index = SpecXmlUtils.decodeInt(el.getAttribute("index"));
		int tabid = SpecXmlUtils.decodeInt(el.getAttribute("table"));
		int ctid = SpecXmlUtils.decodeInt(el.getAttribute("ct"));
		SubtableSymbol sym = (SubtableSymbol) lang.getSymbolTable().findSymbol(tabid);
		ct = sym.getConstructor(ctid);
		parser.end(el);
	}

	@Override
	public String toString() {
		OperandSymbol sym = ct.getOperand(index);
		StringBuilder sb = new StringBuilder();
		sb.append("[opval:" + sym.getName());
		PatternExpression patexp = sym.getDefiningExpression();
		if (patexp != null) {
			sb.append(" exp ");
		}
		else {
			TripleSymbol defSym = sym.getDefiningSymbol();
			if (defSym != null) {
				sb.append(" sym ");
				patexp = defSym.getPatternExpression();
			}
			else {
				sb.append("]");
				return sb.toString();
			}
		}
		sb.append(patexp);
		sb.append("]");
		return sb.toString();
	}
}
