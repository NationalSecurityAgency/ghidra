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

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.slghpatexpress.*;
import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class ContextOp extends ContextChange {
	public final Location location;

	private PatternExpression patexp; // Expression determining value
	private int num; // index of word containing context variable to set
	private int mask; // Mask off size of variable
	private int shift; // Number of bits to shift value into place

	public ContextOp(Location location) {
		this.location = location;
	}

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
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONTEXT_OP);
		encoder.writeSignedInteger(ATTRIB_I, num);
		encoder.writeSignedInteger(ATTRIB_SHIFT, shift);
		encoder.writeUnsignedInteger(ATTRIB_MASK, Utils.unsignedInt(mask));
		patexp.encode(encoder);
		encoder.closeElement(ELEM_CONTEXT_OP);
	}

}
