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

public class InstructionPattern extends DisjointPattern {

	@Override
	public String toString() {
		return "InstructionPattern{" + maskvalue.toString() + "}";
	}

	private PatternBlock maskvalue;

	@Override
	protected PatternBlock getBlock(boolean context) {
		return context ? null : maskvalue;
	}

	public InstructionPattern() {
		maskvalue = null;
	} // For use with restoreXml

	public InstructionPattern(PatternBlock mv) {
		maskvalue = mv;
	}

	public InstructionPattern(boolean tf) {
		maskvalue = new PatternBlock(tf);
	}

	public PatternBlock getBlock() {
		return maskvalue;
	}

	@Override
	public void dispose() {
		if (maskvalue != null) {
			maskvalue.dispose();
		}
	}

	@Override
	public Pattern simplifyClone() {
		return new InstructionPattern(maskvalue.clone());
	}

	@Override
	public void shiftInstruction(int sa) {
		maskvalue.shift(sa);
	}

	@Override
	public boolean isMatch(ParserWalker pos) {
		return maskvalue.isInstructionMatch(pos, 0);
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
		return maskvalue.alwaysTrue();
	}

	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (b.numDisjoint() > 0) {
			return b.doAnd(this, -sa);
		}

		if (b instanceof CombinePattern) {
			return b.doAnd(this, -sa);
		}
		if (b instanceof ContextPattern) {
			ContextPattern b3 = (ContextPattern) b;
			InstructionPattern newpat = (InstructionPattern) simplifyClone();
			if (sa < 0) {
				newpat.shiftInstruction(-sa);
			}

			return new CombinePattern((ContextPattern) b3.simplifyClone(), newpat);
		}
		InstructionPattern b4 = (InstructionPattern) b;

		PatternBlock respattern;
		if (sa < 0) {
			PatternBlock a = maskvalue.clone();
			a.shift(-sa);
			respattern = a.intersect(b4.maskvalue);
			a.dispose();
		}
		else {
			PatternBlock c = b4.maskvalue.clone();
			c.shift(sa);
			respattern = maskvalue.intersect(c);
			c.dispose();
		}
		return new InstructionPattern(respattern);
	}

	@Override
	public Pattern commonSubPattern(Pattern b, int sa) {
		if (b.numDisjoint() > 0) {
			return b.commonSubPattern(this, -sa);
		}

		if (b instanceof CombinePattern) {
			return b.commonSubPattern(this, -sa);
		}
		if (b instanceof ContextPattern) {
			return new InstructionPattern(true);
		}
		InstructionPattern b4 = (InstructionPattern) b;

		PatternBlock respattern;
		if (sa < 0) {
			PatternBlock a = maskvalue.clone();
			a.shift(-sa);
			respattern = a.commonSubPattern(b4.maskvalue);
			a.dispose();
		}
		else {
			PatternBlock c = b4.maskvalue.clone();
			c.shift(sa);
			respattern = maskvalue.commonSubPattern(c);
			c.dispose();
		}
		return new InstructionPattern(respattern);
	}

	@Override
	public Pattern doOr(Pattern b, int sa) {
		if (b.numDisjoint() > 0) {
			return b.doOr(this, -sa);
		}

		if (b instanceof CombinePattern) {
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

	@Override
	public void saveXml(PrintStream s) {
		s.append("<instruct_pat>\n");
		maskvalue.saveXml(s);
		s.append("</instruct_pat>\n");
	}

	@Override
	public void restoreXml(Element el) {
		List<?> list = el.getChildren();
		Element child = (Element) list.get(0);
		maskvalue = new PatternBlock(true);
		maskvalue.restoreXml(child);
	}

}
