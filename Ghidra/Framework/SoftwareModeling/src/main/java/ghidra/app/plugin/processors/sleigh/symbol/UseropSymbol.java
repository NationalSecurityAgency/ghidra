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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A user-defined pcode operation (PcodeOp)
 * This is implemented as a name and a unique id which is passed
 * as the first parameter to a PcodeOp with the opcode = "CALLOTHER".
 */
public class UseropSymbol extends Symbol {
	private int index;			// Unique id for this userop

	public int getIndex() {
		return index;
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_USEROP);
		index = (int) decoder.readSignedInteger(ATTRIB_INDEX);
		decoder.closeElement(ELEM_USEROP.id());
	}
}
