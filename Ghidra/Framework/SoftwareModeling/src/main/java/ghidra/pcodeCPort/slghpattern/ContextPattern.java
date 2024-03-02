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
package ghidra.pcodeCPort.slghpattern;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import ghidra.program.model.pcode.Encoder;

public class ContextPattern extends DisjointPattern {

	private PatternBlock maskvalue;

	@Override
	protected PatternBlock getBlock(boolean context) {
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
	public void dispose() {
		if (maskvalue != null) {
			maskvalue.dispose();
		}
	}

	@Override
	public Pattern simplifyClone() {
		return new ContextPattern(maskvalue.clone());
	}

	@Override
	public void shiftInstruction(int sa) {
	} // do nothing

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
	public Pattern doOr(Pattern b, int sa) {
		if (b instanceof ContextPattern) {
			ContextPattern b2 = (ContextPattern) b;
			return new OrPattern((DisjointPattern) simplifyClone(),
				(DisjointPattern) b2.simplifyClone());
		}
		return b.doOr(this, -sa);
	}

	@Override
	public Pattern doAnd(Pattern b, int sa) {
		if (b instanceof ContextPattern) {
			ContextPattern b2 = (ContextPattern) b;
			PatternBlock resblock = maskvalue.intersect(b2.maskvalue);
			return new ContextPattern(resblock);
		}
		return b.doAnd(this, -sa);

	}

	@Override
	public Pattern commonSubPattern(Pattern b, int sa) {
		if (b instanceof ContextPattern) {
			ContextPattern b2 = (ContextPattern) b;
			PatternBlock resblock = maskvalue.commonSubPattern(b2.maskvalue);
			return new ContextPattern(resblock);
		}
		return b.commonSubPattern(this, -sa);
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_CONTEXT_PAT);
		maskvalue.encode(encoder);
		encoder.closeElement(ELEM_CONTEXT_PAT);
	}

}
