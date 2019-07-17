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
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.StringUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * Matches against the actual instruction bit stream
 */
public class InstructionPattern extends DisjointPattern {

	private PatternBlock maskvalue;

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.DisjointPattern#getBlock(boolean)
	 */
	@Override
	public PatternBlock getBlock(boolean context) {
		return context ? null : maskvalue;
	}

	public InstructionPattern() {
		maskvalue = null;
	}

	public InstructionPattern(PatternBlock mv) {
		maskvalue = mv;
	}

	public InstructionPattern(boolean tf) {
		maskvalue = new PatternBlock(tf);
	}

	public PatternBlock getBlock() {
		return maskvalue;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#simplifyClone()
	 */
	@Override
	public Pattern simplifyClone() {
		return new InstructionPattern((PatternBlock) maskvalue.clone());
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#shiftInstruction()
	 */
	@Override
	public void shiftInstruction(int sa) {
		maskvalue.shift(sa);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doOr(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
	public Pattern doOr(Pattern b, int sa) {
		if (b.numDisjoint() > 0)
			return b.doOr(this, -sa);

		if (b instanceof CombinePattern)
			return b.doOr(this, -sa);

		DisjointPattern res1, res2;
		res1 = (DisjointPattern) simplifyClone();
		res2 = (DisjointPattern) b.simplifyClone();
		if (sa < 0)
			res1.shiftInstruction(-sa);
		else
			res2.shiftInstruction(sa);
		return new OrPattern(res1, res2);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#doAnd(ghidra.app.plugin.processors.sleigh.Pattern, int)
	 */
	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (b.numDisjoint() > 0)
			return b.doAnd(this, -sa);
		if (b instanceof CombinePattern)
			return b.doAnd(this, -sa);
		if (b instanceof ContextPattern) {
			InstructionPattern newpat = (InstructionPattern) simplifyClone();
			if (sa < 0)
				newpat.shiftInstruction(-sa);
			return new CombinePattern((ContextPattern) b.simplifyClone(), newpat);
		}
		// b must be an InstructionPattern if it reaches here
		PatternBlock respattern;
		if (sa < 0) {
			PatternBlock a = (PatternBlock) maskvalue.clone();
			a.shift(-sa);
			respattern = a.andBlock(((InstructionPattern) b).maskvalue);
		}
		else {
			PatternBlock c = (PatternBlock) ((InstructionPattern) b).maskvalue.clone();
			c.shift(sa);
			respattern = maskvalue.andBlock(c);
		}
		return new InstructionPattern(respattern);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.pattern.Pattern#isMatch(ghidra.app.plugin.processors.sleigh.ParserWalker, ghidra.app.plugin.processors.sleigh.SleighDebugLogger)
	 */
	@Override
	public boolean isMatch(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException {
		boolean match = maskvalue.isInstructionMatch(walker);
		debugPatternMatch(debug, walker, match);
		return match;
	}

	private void debugPatternMatch(SleighDebugLogger debug, ParserWalker walker, boolean match) {
		if (debug == null) {
			return;
		}
		debug.append("byte pattern: ");
		if (alwaysTrue()) {
			debug.append("always-Matched\n");
		}
		else if (alwaysFalse()) {
			debug.append("always-Failed\n");
		}
		else {
			MemBuffer memBuf = walker.getParserContext().getMemBuffer();
			int offset = walker.getOffset(-1) + maskvalue.offset;
			int byteCnt = maskvalue.maskvec.length * 4;
			byte[] bytes = new byte[byteCnt];
			memBuf.getBytes(bytes, offset);

			if (match) {
				debug.addInstructionPattern(offset, maskvalue);
			}

			if (debug.isVerboseEnabled()) {
				debug.append("mask=");
				debug.append(maskvalue.maskvec, -1, 0);
				debug.append("\n");
				int endoffset = offset + bytes.length - 1;
				String leader = "bytes[" + offset + "-" + endoffset + "]=";
				debug.append(StringUtilities.pad(leader, ' ', 19));
				debug.append(bytes, -1, 0);
				debug.append("\n");
				debug.append("       match-value=");
				debug.append(maskvalue.valvec, -1, 0);
				debug.append(" " + (match ? "Matched" : "Failed") + "\n");
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysTrue()
	 */
	@Override
	public boolean alwaysTrue() {
		return maskvalue.alwaysTrue();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysFalse()
	 */
	@Override
	public boolean alwaysFalse() {
		return maskvalue.alwaysFalse();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#alwaysInstructionTrue()
	 */
	@Override
	public boolean alwaysInstructionTrue() {
		return maskvalue.alwaysTrue();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.Pattern#restoreXml(org.jdom.Element)
	 */
	@Override
	public void restoreXml(XmlPullParser parser) {
		XmlElement el = parser.start("instruct_pat");
		maskvalue = new PatternBlock(true);
		maskvalue.restoreXml(parser);
		parser.end(el);
	}

	@Override
	public String toString() {
		if (alwaysTrue()) {
			return "always";
		}
		if (alwaysFalse()) {
			return "never";
		}
		return "ins:" + maskvalue;
	}
}
