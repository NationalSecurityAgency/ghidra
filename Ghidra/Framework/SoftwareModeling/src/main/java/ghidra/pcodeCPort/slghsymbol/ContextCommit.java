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

import ghidra.pcodeCPort.utils.MutableInt;
import ghidra.pcodeCPort.utils.Utils;
import ghidra.program.model.pcode.Encoder;

public class ContextCommit extends ContextChange {

	private TripleSymbol sym;
	private int num; // Index of word containing context commit
	private int mask; // mask of bits in word being committed
	private boolean flow; // Whether the context "flows" from the point of change

	public ContextCommit() {
	}

	@Override
	public void validate() {
	}

	public ContextCommit(TripleSymbol s, int sbit, int ebit, boolean fl) {
		sym = s;
		flow = fl;
		MutableInt n = new MutableInt();
		MutableInt zero = new MutableInt(0);
		MutableInt m = new MutableInt();
		Utils.calc_maskword(s.getLocation(), sbit, ebit, n, zero, m);
		num = n.get();
		mask = m.get();
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_COMMIT);
		encoder.writeUnsignedInteger(ATTRIB_ID, sym.getId());
		encoder.writeSignedInteger(ATTRIB_NUMBER, num);
		encoder.writeUnsignedInteger(ATTRIB_MASK, Utils.unsignedInt(mask));
		encoder.writeBool(ATTRIB_FLOW, flow);
		encoder.closeElement(ELEM_COMMIT);
	}

}
