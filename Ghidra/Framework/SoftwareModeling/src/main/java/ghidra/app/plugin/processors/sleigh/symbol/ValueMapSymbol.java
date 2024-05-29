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
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternValue;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

public class ValueMapSymbol extends ValueSymbol {
	private long[] valuetable;		// Map from natural encoding to attached values
	private boolean tableisfilled;

	public List<Long> getMap() {
		List<Long> result = new ArrayList<>();
		for (long v : valuetable) {
			result.add(v);
		}
		return Collections.unmodifiableList(result);
	}

	private void checkTableFill() {
		long min = getPatternValue().minValue();
		long max = getPatternValue().maxValue();
		tableisfilled = (min >= 0) && (max < valuetable.length);
		for (long element : valuetable) {
			if (element == 0xBADBEEF) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		if (!tableisfilled) {
			long ind = getPatternValue().getValue(walker);
			if ((ind >= valuetable.length) || (ind < 0) || (valuetable[(int) ind] == 0xBADBEEF)) {
				String errmsg =
					"No corresponding entry in valuetable <" + getName() + ">, index=" + ind;
				if (debug != null) {
					debug.append(errmsg + "\n");
				}
				throw new UnknownInstructionException(errmsg);
			}
		}
		return null;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		// Entry has already been tested for null by the resolve routine
		hand.space = walker.getConstSpace();
		hand.offset_space = null;	// Not a dynamic variable
		hand.offset_offset = valuetable[ind];
		hand.size = 0;				// Cannot provide size
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		// ind is already known to be a valid array index via resolve
		long val = valuetable[ind];
		String res;
		if (val >= 0) {
			res = "0x" + Long.toHexString(val);
		}
		else {
			res = "-0x" + Long.toHexString(-val);
		}
		return res;
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_VALUEMAP_SYM);
		patval = (PatternValue) PatternExpression.decodeExpression(decoder, sleigh);
		ArrayList<Long> values = new ArrayList<>();
		while (decoder.peekElement() == ELEM_VALUETAB.id()) {
			decoder.openElement();
			values.add(decoder.readSignedInteger(ATTRIB_VAL));
			decoder.closeElement(ELEM_VALUETAB.id());
		}
		valuetable = new long[values.size()];
		for (int i = 0; i < valuetable.length; ++i) {
			valuetable[i] = values.get(i);
		}
		checkTableFill();
		decoder.closeElement(ELEM_VALUEMAP_SYM.id());
	}
}
