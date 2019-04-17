/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.pcodeCPort.slghpattern;

import ghidra.pcodeCPort.context.ParserWalker;

import java.io.PrintStream;
import java.util.List;

import org.jdom.Element;

public class CombinePattern extends DisjointPattern {

	private ContextPattern context; // Context piece
	private InstructionPattern instr; // Instruction piece

	@Override
	protected PatternBlock getBlock(boolean cont) {
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
	public void shiftInstruction(int sa) {
		instr.shiftInstruction(sa);
	}

	@Override
	public boolean alwaysInstructionTrue() {
		return instr.alwaysInstructionTrue();
	}

	@Override
	public void dispose() {
		if (context != null) {
			context.dispose();
		}
		if (instr != null) {
			instr.dispose();
		}
	}

	@Override
	public boolean isMatch(ParserWalker pos) {
		if (!instr.isMatch(pos)) {
			return false;
		}
		if (!context.isMatch(pos)) {
			return false;
		}
		return true;
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
	public Pattern doAnd(Pattern b, int sa) {
		CombinePattern tmp;

		if (b.numDisjoint() != 0) {
			return b.doAnd(this, -sa);
		}
		if (b instanceof CombinePattern) {
			CombinePattern b2 = (CombinePattern) b;
			ContextPattern c = (ContextPattern) context.doAnd(b2.context, 0);
			InstructionPattern i = (InstructionPattern) instr.doAnd(b2.instr, sa);
			tmp = new CombinePattern(c, i);
		}
		else {
			if (b instanceof InstructionPattern) {
				InstructionPattern b3 = (InstructionPattern) b;
				InstructionPattern i = (InstructionPattern) instr.doAnd(b3, sa);
				tmp = new CombinePattern((ContextPattern) context.simplifyClone(), i);
			}
			else { // Must be a ContextPattern
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
	public Pattern commonSubPattern(Pattern b, int sa) {
		Pattern tmp;

		if (b.numDisjoint() != 0) {
			return b.commonSubPattern(this, -sa);
		}

		if (b instanceof CombinePattern) {
			CombinePattern b2 = (CombinePattern) b;
			ContextPattern c = (ContextPattern) context.commonSubPattern(b2.context, 0);
			InstructionPattern i = (InstructionPattern) instr.commonSubPattern(b2.instr, sa);
			tmp = new CombinePattern(c, i);
		}
		else {
			if (b instanceof InstructionPattern) {
				InstructionPattern b3 = (InstructionPattern) b;
				tmp = instr.commonSubPattern(b3, sa);
			}
			else {
				// Must be a ContextPattern
				tmp = context.commonSubPattern(b, 0);
			}
		}
		return tmp;
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
		return new OrPattern(res1, res2);
	}

	// We should only have to think at "our" level
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
	public void saveXml(PrintStream s) {
		s.append("<combine_pat>\n");
		context.saveXml(s);
		instr.saveXml(s);
		s.append("</combine_pat>\n");
	}

	@Override
	public void restoreXml(Element el) {
		List<?> list = el.getChildren();
		Element child = (Element) list.get(0);
		context = new ContextPattern();
		context.restoreXml(child);
		child = (Element) list.get(1);
		instr = new InstructionPattern();
		instr.restoreXml(child);
	}

}
