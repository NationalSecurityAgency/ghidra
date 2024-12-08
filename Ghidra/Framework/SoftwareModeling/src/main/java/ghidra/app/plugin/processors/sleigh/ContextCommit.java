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
package ghidra.app.plugin.processors.sleigh;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

public class ContextCommit implements ContextChange {

	private TripleSymbol sym;
	private int num;
	private int mask;

	public ContextCommit() {
		sym = null;
	}

	@Override
	public void apply(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException {
		walker.getParserContext().addCommit(walker.getState(), sym, num, mask);
		if (debug != null) {
			debug.dumpGlobalSet(walker.getParserContext(), walker.getState(), sym, num, mask,
				walker.getParserContext().getContextBytes()[num] & mask);
		}
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
		int el = decoder.openElement(ELEM_COMMIT);
		int id = (int) decoder.readUnsignedInteger(ATTRIB_ID);
		sym = (TripleSymbol) lang.getSymbolTable().findSymbol(id);
		num = (int) decoder.readSignedInteger(ATTRIB_NUMBER);
		mask = (int) decoder.readUnsignedInteger(ATTRIB_MASK);
		decoder.closeElement(el);
	}

}
