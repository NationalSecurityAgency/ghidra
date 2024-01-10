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

/**
 * A pattern that has both an instruction part and non-instruction part
 */
public class CombinePattern extends DisjointPattern {

	private ContextPattern context;		// Context piece
	private InstructionPattern instr;	// Instruction piece

	@Override
	public PatternBlock getBlock(boolean cont) {
		return cont ? context.getBlock() : instr.getBlock();
	}

	public CombinePattern() {
		context = null;
		instr = null;
	}

	public CombinePattern(ContextPattern con, InstructionPattern in) {
		context = con;
		instr = in;
	}

	@Override
	public Pattern simplifyClone() {
		if (context.alwaysTrue()) {
			return instr.simplifyClone();
		}
		if (instr.alwaysTrue()) {
			return context.simplifyClone();
		}
		if (context.alwaysFalse() || instr.alwaysFalse()) {
			return new InstructionPattern(false);
		}

		return new CombinePattern((ContextPattern) context.simplifyClone(),
			(InstructionPattern) instr.simplifyClone());
	}

	@Override
	public void shiftInstruction(int sa) {
		instr.shiftInstruction(sa);
	}

	@Override
	public Pattern doOr(Pattern b, int sa) {
		if (b.numDisjoint() != 0) {
			return b.doOr(this, -sa);
		}

		DisjointPattern res1 = (DisjointPattern) simplifyClone();
		DisjointPattern res2 = (DisjointPattern) b.simplifyClone();
		if (sa < 0) {
			res1.shiftInstruction(-sa);
		}
		else {
			res2.shiftInstruction(sa);
		}
		OrPattern tmp = new OrPattern(res1, res2);
		return tmp;
	}

	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (b.numDisjoint() != 0) {
			return b.doAnd(this, -sa);
		}

		CombinePattern tmp;
		if (b instanceof CombinePattern) {
			ContextPattern c = (ContextPattern) context.doAnd(((CombinePattern) b).context, 0);
			InstructionPattern i = (InstructionPattern) instr.doAnd(((CombinePattern) b).instr, sa);
			tmp = new CombinePattern(c, i);
		}
		else {
			if (b instanceof InstructionPattern) {
				InstructionPattern i = (InstructionPattern) instr.doAnd(b, sa);
				tmp = new CombinePattern((ContextPattern) context.simplifyClone(), i);
			}
			else {		// Must be a ContextPattern
				ContextPattern c = (ContextPattern) context.doAnd(b, 0);
				InstructionPattern newpat = (InstructionPattern) instr.simplifyClone();
				if (sa < 0) {
					newpat.shiftInstruction(-sa);
				}
				tmp = new CombinePattern(c, newpat);
			}
		}
		return tmp;
	}

	@Override
	public boolean isMatch(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException {

		debugNextMatch(debug, true);
		boolean match = instr.isMatch(walker, debug);

		debugNextMatch(debug, false);
		if (match || debug != null) {
			match &= context.isMatch(walker, debug);
		}

		debugDone(debug, match);
		return match;
	}

	private void debugDone(SleighDebugLogger debug, boolean match) {
		if (debug != null) {
			debug.endPatternGroup(match);
			debug.dropIndent();
			debug.append(") " + (match ? "Matched" : "Failed") + "\n");
		}
	}

	private void debugNextMatch(SleighDebugLogger debug, boolean isFirst) {
		if (debug == null) {
			return;
		}
		if (isFirst) {
			debug.startPatternGroup(null);
			debug.append("(  ");
		}
		else {
			debug.dropIndent();
			debug.append(") -and- (\n");
		}
		debug.indent();
	}

	@Override
	public boolean alwaysTrue() {
		return (context.alwaysTrue() && instr.alwaysTrue());
	}

	@Override
	public boolean alwaysFalse() {
		return (context.alwaysFalse() || instr.alwaysFalse());
	}

	@Override
	public boolean alwaysInstructionTrue() {
		return instr.alwaysInstructionTrue();
	}

	@Override
	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_COMBINE_PAT);
		context = new ContextPattern();
		context.decode(decoder);
		instr = new InstructionPattern();
		instr.decode(decoder);
		decoder.closeElement(el);
	}

	@Override
	public String toString() {
		if (context.alwaysTrue()) {
			return instr.toString();
		}
		if (instr.alwaysTrue()) {
			return context.toString();
		}
		if (context.alwaysFalse() || instr.alwaysFalse()) {
			return "never";
		}
		return "cmb:(" + context + "," + instr + ")";
	}
}
