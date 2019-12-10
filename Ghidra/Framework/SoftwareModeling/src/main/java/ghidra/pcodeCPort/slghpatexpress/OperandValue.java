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
package ghidra.pcodeCPort.slghpatexpress;

import java.io.PrintStream;

import org.jdom.Element;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.*;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghsymbol.*;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

public class OperandValue extends PatternValue {

	private int index; // This is the defining field of expression
	private Constructor ct; // cached pointer to constructor

	public OperandValue(Location location) {
		super(location);
	} // For use with restoreXml

	public OperandValue(Location location, int ind, Constructor c) {
		super(location);
		index = ind;
		ct = c;
	}

	public void changeIndex(int newind) {
		index = newind;
	}

	@Override
	public TokenPattern genMinPattern(VectorSTL<TokenPattern> ops) {
		if (index >= ops.size()) {
			return null;
		}
		return ops.get(index);
	}

	@Override
	public TokenPattern genPattern(long val) {
		// In general an operand cannot be interpreted as any sort
		// of static constraint in an equation, and if it is being
		// defined by the equation, it should be on the left hand side.
		// If the operand has a defining expression already, use
		// of the operand in the equation makes sense, its defining
		// expression would become a subexpression in the full
		// expression. However, since this can be accomplished
		// by explicitly copying the subexpression into the full
		// expression, we don't support operands as placeholders.
		throw new SleighError("Operand used in pattern expression", ct.location);
	}

	@Override
	public long minValue() {
		throw new SleighError("Operand used in pattern expression", ct.location);
	}

	@Override
	public long maxValue() {
		throw new SleighError("Operand used in pattern expression", ct.location);
	}

	// Get the value of an operand when it is used in
	// an expression.
	@Override
	public long getValue(ParserWalker pos) {
		OperandSymbol sym = ct.getOperand(index);
		PatternExpression patexp = sym.getDefiningExpression();
		if (patexp == null) {
			TripleSymbol defsym = sym.getDefiningSymbol();
			if (defsym != null) {
				patexp = defsym.getPatternExpression();
			}
			if (patexp == null) {
				return 0;
			}
		}
		ConstructState tempstate = new ConstructState();
		ParserWalker newwalker = new ParserWalker(pos.getParserContext());
		newwalker.setOutOfBandState(ct, index, tempstate, pos);
		long res = patexp.getValue(newwalker);
		return res;
	}

	@Override
	public long getSubValue(VectorSTL<Long> replace, MutableInt listpos) {
		OperandSymbol sym = ct.getOperand(index);
		return sym.getDefiningExpression().getSubValue(replace, listpos);
	}

	public boolean isConstructorRelative() {
		OperandSymbol sym = ct.getOperand(index);
		return (sym.getOffsetBase() == -1);
	}

	public String getName() {
		OperandSymbol sym = ct.getOperand(index);
		return sym.getName();
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<operand_exp");
		s.append(" index=\"");
		s.print(index);
		s.append("\"");
		s.append(" table=\"0x");
		int id = (ct == null ? 0 : ct.getParent().getId());
		s.append(Long.toHexString(id));
		s.append("\"");
		s.append(" ct=\"0x");
		long ctid = (ct == null ? 0 : ct.getId());
		s.append(Long.toHexString(ctid));
		s.append("\"/>\n"); // Save id of our constructor
	}

	@Override
	public void restoreXml(Element el, Translate trans) {
		index = XmlUtils.decodeUnknownInt(el.getAttributeValue("index"));
		long tabid = XmlUtils.decodeUnknownLong(el.getAttributeValue("table"));
		long ctid = XmlUtils.decodeUnknownLong(el.getAttributeValue("ct"));
		SleighBase sleigh = (SleighBase) trans;
		SubtableSymbol tab = (SubtableSymbol) (sleigh.findSymbol((int) tabid));
		ct = tab.getConstructor((int) ctid);
	}

}
