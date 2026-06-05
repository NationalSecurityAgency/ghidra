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
package ghidra.pcode.emu.jit.op;

import java.util.List;

import org.apache.commons.collections4.iterators.ReverseListIterator;

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;

/**
 * The synthetic use-def node for concatenation.
 *
 * <p>
 * These are synthesized when memory/register access patterns cause multiple use-def variable nodes
 * to be "read" at the same time. E.g., consider {@code AL} and {@code AH} to be written and then
 * {@code AX} read.
 *
 * @param out the use-def variable node for the output
 * @param parts the inputs to be concatenated
 */
public record JitCatenateOp(JitOutVar out, List<JitVal> parts) implements JitDefOp, JitSyntheticOp {
	/**
	 * Compact constructor for validation
	 * 
	 * @param out the use-def variable node for the output
	 * @param parts the inputs to be concatenated
	 */
	public JitCatenateOp {
		if (parts.size() <= 1) {
			throw new IllegalArgumentException("Must have at least 2 parts");
		}
	}

	@Override
	public void link() {
		JitDefOp.super.link();
		for (int i = 0; i < parts.size(); i++) {
			parts.get(i).addUse(this, i);
		}
	}

	@Override
	public void unlink() {
		JitDefOp.super.unlink();
		for (int i = 0; i < parts.size(); i++) {
			parts.get(i).removeUse(this, i);
		}
	}

	/**
	 * Iterate over the parts from most to least significant
	 * 
	 * @param bigEndian the byte order off the machine
	 * @return an iterable over the parts
	 */
	public Iterable<JitVal> iterParts(boolean bigEndian) {
		if (bigEndian) {
			return parts;
		}
		return () -> new ReverseListIterator<>(parts);
	}

	@Override
	public List<JitVal> inputs() {
		return parts;
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		if (position > parts.size() || position < 0) {
			throw new AssertionError();
		}
		return partType();
	}

	/**
	 * We'd like every part to be an {@link JitTypeBehavior#INTEGER int}.
	 * 
	 * @return {@link JitTypeBehavior#INTEGER}
	 */
	public JitTypeBehavior partType() {
		return JitTypeBehavior.INTEGER;
	}

	@Override
	public JitTypeBehavior type() {
		return JitTypeBehavior.INTEGER;
	}
}
