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

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A constant value associated with an alwaysTrue pattern
 */
public class ConstantValue extends PatternValue {

	private long val;			// The constant value

	@Override
	public int hashCode() {
		return Long.hashCode(val);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof ConstantValue)) {
			return false;
		}
		ConstantValue that = (ConstantValue) obj;
		if (this.val != that.val) {
			return false;
		}
		return true;
	}

	public ConstantValue() {
		val = 0;
	}

	public ConstantValue(long b) {
		val = b;
	}

	@Override
	public long minValue() {
		return val;
	}

	@Override
	public long maxValue() {
		return val;
	}

	@Override
	public long getValue(ParserWalker walker) throws MemoryAccessException {
		return val;
	}

	public long getValue() {
		return val;
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
		int el = decoder.openElement(ELEM_INTB);
		val = decoder.readSignedInteger(ATTRIB_VAL);
		decoder.closeElement(el);
	}

	@Override
	public String toString() {
		return "0x" + Long.toHexString(val);
	}
}
