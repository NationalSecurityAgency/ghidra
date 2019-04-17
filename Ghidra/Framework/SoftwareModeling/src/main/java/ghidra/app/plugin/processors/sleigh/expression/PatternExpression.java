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

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * An expression which results in a pattern for a specific InstructionContext
 */
public abstract class PatternExpression {
	public abstract long getValue(ParserWalker walker) throws MemoryAccessException;

	public abstract void restoreXml(XmlPullParser parser, SleighLanguage lang);

	public static PatternExpression restoreExpression(XmlPullParser parser, SleighLanguage lang) {
		XmlElement el = parser.peek();
		PatternExpression res;
		String nm = el.getName();
		if (nm.equals("tokenfield"))
			res = new TokenField();
		else if (nm.equals("contextfield"))
			res = new ContextField();
		else if (nm.equals("intb"))
			res = new ConstantValue();
		else if (nm.equals("operand_exp"))
			res = new OperandValue();
		else if (nm.equals("start_exp"))
			res = new StartInstructionValue();
		else if (nm.equals("end_exp"))
			res = new EndInstructionValue();
		else if (nm.equals("plus_exp"))
			res = new PlusExpression();
		else if (nm.equals("sub_exp"))
			res = new SubExpression();
		else if (nm.equals("mult_exp"))
			res = new MultExpression();
		else if (nm.equals("lshift_exp"))
			res = new LeftShiftExpression();
		else if (nm.equals("rshift_exp"))
			res = new RightShiftExpression();
		else if (nm.equals("and_exp"))
			res = new AndExpression();
		else if (nm.equals("or_exp"))
			res = new OrExpression();
		else if (nm.equals("xor_exp"))
			res = new XorExpression();
		else if (nm.equals("div_exp"))
			res = new DivExpression();
		else if (nm.equals("minus_exp"))
			res = new MinusExpression();
		else if (nm.equals("not_exp"))
			res = new NotExpression();
		else
			return null;

		res.restoreXml(parser, lang);
		return res;
	}

	@Override
	public abstract String toString();
}
