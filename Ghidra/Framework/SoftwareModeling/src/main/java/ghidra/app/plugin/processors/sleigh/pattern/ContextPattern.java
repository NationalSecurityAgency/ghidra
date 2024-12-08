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
package ghidra.app.plugin.processors.sleigh.pattern;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;
import ghidra.util.StringUtilities;

/**
 * Pattern which depends only on the non-instruction stream bits
 * of the context
 */
public class ContextPattern extends DisjointPattern {

	private PatternBlock maskvalue;

	@Override
	public PatternBlock getBlock(boolean context) {
		return context ? maskvalue : null;
	}

	public ContextPattern() {
		maskvalue = null;
	}

	public ContextPattern(PatternBlock mv) {
		maskvalue = mv;
	}

	public PatternBlock getBlock() {
		return maskvalue;
	}

	@Override
	public Pattern simplifyClone() {
		return new ContextPattern((PatternBlock) maskvalue.clone());
	}

	@Override
	public void shiftInstruction(int sa) {
		// do nothing
	}

	@Override
	public Pattern doOr(Pattern b, int sa) {
		if (!(b instanceof ContextPattern)) {
			return b.doOr(this, -sa);
		}

		return new OrPattern((DisjointPattern) simplifyClone(),
			(DisjointPattern) b.simplifyClone());
	}

	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (!(b instanceof ContextPattern)) {
			return b.doAnd(this, -sa);
		}

		PatternBlock resblock = maskvalue.andBlock(((ContextPattern) b).maskvalue);
		return new ContextPattern(resblock);
	}

	@Override
	public boolean isMatch(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException {
		boolean match = maskvalue.isContextMatch(walker);
		debugPatternMatch(debug, walker, match);
		return match;
	}

	private void debugPatternMatch(SleighDebugLogger debug, ParserWalker walker, boolean match) {
		if (debug == null) {
			return;
		}
		debug.append("context pattern: ");
		if (alwaysTrue()) {
			debug.append("always-Matched\n");
		}
		else if (alwaysFalse()) {
			debug.append("always-Failed\n");
		}
		else {

			debug.addContextPattern(maskvalue);

			if (debug.isVerboseEnabled()) {
				debug.append("mask=");
				debug.append(maskvalue.maskvec, -1, 0);
				debug.append("\n");
				int startbit = maskvalue.offset * 8;
				int endbit = startbit + 31 + (32 * (maskvalue.maskvec.length - 1));
				String leader = "context(" + startbit + ".." + endbit + ")=";
				debug.append(StringUtilities.pad(leader, ' ', 22));
				for (int i = 0; i < maskvalue.maskvec.length; i++) {
					if (i != 0) {
						debug.append(".");
					}
					debug.append(
						walker.getParserContext().getContextBytes(maskvalue.offset + (i * 4), 4),
						-1, 0);
				}
				debug.append("\n");
				debug.append("          match-value=");
				debug.append(maskvalue.valvec, -1, 0);
				debug.append(" " + (match ? "Matched" : "Failed") + "\n");

				debug.dumpContextPattern(maskvalue.maskvec, maskvalue.valvec, maskvalue.offset,
					walker.getParserContext());
			}
		}
	}

	@Override
	public boolean alwaysTrue() {
		return maskvalue.alwaysTrue();
	}

	@Override
	public boolean alwaysFalse() {
		return maskvalue.alwaysFalse();
	}

	@Override
	public boolean alwaysInstructionTrue() {
		return true;
	}

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_CONTEXT_PAT);
		maskvalue = new PatternBlock(true);
		maskvalue.decode(decoder);
		decoder.closeElement(el);
	}

	@Override
	public String toString() {
		if (alwaysTrue()) {
			return "always";
		}
		if (alwaysFalse()) {
			return "never";
		}
		return "ctx:" + maskvalue;
	}
}
