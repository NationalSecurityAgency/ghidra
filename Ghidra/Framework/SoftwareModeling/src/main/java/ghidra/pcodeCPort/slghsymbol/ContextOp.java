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
import ghidra.pcodeCPort.context.ParserWalkerChange;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.*;
import ghidra.pcodeCPort.utils.*;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;

import org.jdom.Element;

public class ContextOp extends ContextChange {
	public final Location location;

	private PatternExpression patexp; // Expression determining value
	private int num; // index of word containing context variable to set
	private int mask; // Mask off size of variable
	private int shift; // Number of bits to shift value into place

	public ContextOp(Location location) {
		this.location = location;
	} // For use with restoreXml

	@Override
	public void dispose() {
		PatternExpression.release(patexp);
	}

	public ContextOp(Location location, int startbit, int endbit, PatternExpression pe) {
		this.location = location;
		MutableInt n = new MutableInt();
		MutableInt s = new MutableInt();
		MutableInt m = new MutableInt();
		Utils.calc_maskword(location, startbit, endbit, n, s, m);
		num = n.get();
		shift = s.get();
		mask = m.get();
		patexp = pe;
		patexp.layClaim();
	}

	@Override
	public void apply(ParserWalkerChange pos) {
		int val = (int) patexp.getValue(pos); // Get our value based on context
		val <<= shift;
		pos.getParserContext().setContextWord(num, val, mask);
	}

	// Throw an exception if the PatternExpression is not valid
	@Override
	public void validate() {
		VectorSTL<PatternValue> values = new VectorSTL<PatternValue>();

		patexp.listValues(values); // Get all the expression tokens
		for (int i = 0; i < values.size(); ++i) {
			if (values.get(i) instanceof OperandValue) {
				OperandValue val = (OperandValue) (values.get(i));
				// Certain operands cannot be used in context expressions
				// because these are evaluated BEFORE the operand offset
				// has been recovered. If the offset is not relative to
				// the base constructor, then we throw an error
				if (!val.isConstructorRelative()) {
					throw new SleighError(val.getName() + ": cannot be used in context expression",
						val.location);
				}
			}
		}
	}

	@Override
	public void saveXml(PrintStream s) {
		s.append("<context_op");
		s.append(" i=\"");
		s.print(num);
		s.append("\"");
		s.append(" shift=\"");
		s.print(shift);
		s.append("\"");
		s.append(" mask=\"0x");
		s.append(Utils.toUnsignedIntHex(mask));
		s.append("\" >\n");
		patexp.saveXml(s);
		s.append("</context_op>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		num = XmlUtils.decodeUnknownInt(el.getAttributeValue("i"));
		shift = XmlUtils.decodeUnknownInt(el.getAttributeValue("shift"));
		mask = XmlUtils.decodeUnknownInt(el.getAttributeValue("mask"));
		Element child = (Element) el.getChildren().get(0);
		patexp = PatternExpression.restoreExpression(child, trans);
		patexp.layClaim();
	}

}
