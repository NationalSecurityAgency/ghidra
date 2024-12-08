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

/**
 * A ValueSymbol whose printing aspect is determined by looking
 * up the context value of the symbol in a table of strings
 */
public class NameSymbol extends ValueSymbol {

	private String[] nametable;		// The table of strings
	private boolean tableisfilled;

	public List<String> getNameTable() {
		return Collections.unmodifiableList(Arrays.asList(nametable));
	}

	private void checkTableFill() {
		long min = getPatternValue().minValue();
		long max = getPatternValue().maxValue();
		tableisfilled = (min >= 0) && (max < nametable.length);
		for (int i = 0; i < nametable.length; ++i) {
			if (null == nametable[i]) {
				tableisfilled = false;
			}
		}
	}

	@Override
	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		if (!tableisfilled) {
			long ind = getPatternValue().getValue(walker);
			if ((ind >= nametable.length) || (ind < 0) || (nametable[(int) ind] == null)) {
				String errmsg =
					"No corresponding entry in nametable <" + getName() + ">, index=" + ind;
				if (debug != null) {
					debug.append(errmsg + "\n");
				}
				throw new UnknownInstructionException(errmsg);
			}
		}
		return null;
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		return nametable[ind];
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list)
			throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		String token = nametable[ind];
		for (int i = 0; i < token.length(); ++i) {
			list.add(Character.valueOf(token.charAt(i)));
		}
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_NAME_SYM);
		patval = (PatternValue) PatternExpression.decodeExpression(decoder, sleigh);
		ArrayList<String> names = new ArrayList<>();
		while (decoder.peekElement() == ELEM_NAMETAB.id()) {
			decoder.openElement();
			int attrib = decoder.getNextAttributeId();
			if (attrib == ATTRIB_NAME.id()) {
				names.add(decoder.readString());
			}
			else {
				names.add(null);
			}
			decoder.closeElement(ELEM_NAMETAB.id());
		}
		nametable = new String[names.size()];
		for (int i = 0; i < nametable.length; ++i) {
			nametable[i] = names.get(i);
		}
		checkTableFill();
		decoder.closeElement(ELEM_NAME_SYM.id());
	}
}
