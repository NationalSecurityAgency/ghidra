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
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * The integer offset of the address following the current instruction
 */
public class EndInstructionValue extends PatternValue {
	private static final int HASH = "[inst_next]".hashCode();

	@Override
	public int hashCode() {
		return HASH;
	}

	@Override
	public boolean equals(Object obj) {
		return obj instanceof EndInstructionValue;
	}

	@Override
	public long minValue() {
		return 0;
	}

	@Override
	public long maxValue() {
		return 0;
	}

	@Override
	public long getValue(ParserWalker walker) throws MemoryAccessException {
		Address addr = walker.getNaddr();
		return addr.getAddressableWordOffset();
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
		int el = decoder.openElement(ELEM_END_EXP);
		decoder.closeElement(el);
		// Nothing to do
	}

	@Override
	public String toString() {
		return "[inst_next]";
	}
}
