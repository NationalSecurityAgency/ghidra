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

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A pattern that has both an instruction part and non-instruction part
 */
public class CombinePattern extends DisjointPattern {

	private ContextPattern context;		// Context piece
	private InstructionPattern instr;	// Instruction piece

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.DisjointPattern#getBlock(boolean)
	 */
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

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#simplifyClone()
	 */
	@Override
	public Pattern simplifyClone() {
		if (context.alwaysTrue())
			return instr.simplifyClone();
		if (instr.alwaysTrue())
			return context.simplifyClone();
		if (context.alwaysFalse() || instr.alwaysFalse())
			return new InstructionPattern(false);

		return new CombinePattern((ContextPattern) context.simplifyClone(),
			(InstructionPattern) instr.simplifyClone());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#shiftInstruction(int)
	 */
	@Override
	public void shiftInstruction(int sa) {
		instr.shiftInstruction(sa);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doOr(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
	public Pattern doOr(Pattern b, int sa) {
		if (b.numDisjoint() != 0)
			return b.doOr(this, -sa);

		DisjointPattern res1 = (DisjointPattern) simplifyClone();
		DisjointPattern res2 = (DisjointPattern) b.simplifyClone();
		if (sa < 0)
			res1.shiftInstruction(-sa);
		else
			res2.shiftInstruction(sa);
		OrPattern tmp = new OrPattern(res1, res2);
		return tmp;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doAnd(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (b.numDisjoint() != 0)
			return b.doAnd(this, -sa);

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
				if (sa < 0)
					newpat.shiftInstruction(-sa);
				tmp = new CombinePattern(c, newpat);
			}
		}
		return tmp;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.pattern.Pattern#isMatch(ghidra.app.plugin.processors.sleigh.ParserWalker, ghidra.app.plugin.processors.sleigh.SleighDebugLogger)
	 */
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

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysTrue()
	 */
	@Override
	public boolean alwaysTrue() {
		return (context.alwaysTrue() && instr.alwaysTrue());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysFalse()
	 */
	@Override
	public boolean alwaysFalse() {
		return (context.alwaysFalse() || instr.alwaysFalse());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysInstructionTrue()
	 */
	@Override
	public boolean alwaysInstructionTrue() {
		return instr.alwaysInstructionTrue();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#restoreXml(org.jdom.Element)
	 */
	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("combine_pat");
		context = new ContextPattern();
		context.restoreXml(parser);
		instr = new InstructionPattern();
		instr.restoreXml(parser);
		parser.end(el);
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
