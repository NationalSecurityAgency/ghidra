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

import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The synthetic use-def node for subpiece.
 * 
 * <p>
 * These are synthesized when memory/register access patterns cause only part of a use-def variable
 * node to be "read." E.g., consider {@code AX} to be written and then {@code AL} read. These are
 * different than {@link JitSubPieceOp} in that the latter have an actual {@link PcodeOp}
 * associated.
 * 
 * 
 * @param out the use-def variable node for the output
 * @param offset the offset, in bytes, to shift right
 * @param v the input use-def value node
 * @implNote Bits are shifted to the right by offset bytes. Then bits are truncated from the left to
 *           force it to match the out var's size.
 */
public record JitSynthSubPieceOp(JitOutVar out, int offset, JitVal v)
		implements JitDefOp, JitSyntheticOp {
	/**
	 * Compact constructor for validation.
	 * 
	 * @param out the use-def variable node for the output
	 * @param offset the offset, in bytes, to shift right
	 * @param v the input use-def value node
	 */
	public JitSynthSubPieceOp {
		if (offset < 0) {
			throw new IllegalArgumentException("Subpiece offset cannot be negative");
		}
		if (offset + out.size() > v.size()) {
			throw new IllegalArgumentException("Subpiece is outside input");
		}
		if (v.size() == out.size() && offset == 0) {
			throw new IllegalArgumentException("Subpiece is whole input");
		}
	}

	@Override
	public void link() {
		JitDefOp.super.link();
		v.addUse(this, 0);
	}

	@Override
	public void unlink() {
		JitDefOp.super.link();
		v.removeUse(this, 0);
	}

	@Override
	public List<JitVal> inputs() {
		return List.of(v);
	}

	/**
	 * We'd like the input to be an {@link JitTypeBehavior#INTEGER int}.
	 * 
	 * @return {@link JitTypeBehavior#INTEGER}
	 */
	public JitTypeBehavior vType() {
		return JitTypeBehavior.INTEGER;
	}

	@Override
	public JitTypeBehavior type() {
		return JitTypeBehavior.INTEGER;
	}

	@Override
	public JitTypeBehavior typeFor(int position) {
		return switch (position) {
			case 0 -> vType();
			default -> throw new AssertionError();
		};
	}

	/**
	 * Check if this piece abuts the given piece.
	 * 
	 * <p>
	 * To "abut," the pieces must take the same value as input, and then this piece's offset must be
	 * exactly the other's offset plus its size. Consider this diagram:
	 * 
	 * <pre>
	 * [this][right]
	 * </pre>
	 * 
	 * <p>
	 * We want this piece to be in the more-significant position immediately before the given piece.
	 * We thus compute {@code diff} the difference in offsets and check if that is equal to the size
	 * of the right piece. If it is, then we have:
	 *
	 * <pre>
	 * [offset=x+diff,size=s][offset=x,size=diff]
	 * </pre>
	 * 
	 * <p>
	 * And the "whole piece" is
	 * 
	 * <pre>
	 * [offset=x,size=s+diff]
	 * </pre>
	 * 
	 * @param right the piece to the right, i.e., less significant
	 * @return true if the two pieces can be expressed as one whole
	 */
	public boolean abuts(JitSynthSubPieceOp right) {
		int diff = this.offset() - right.offset();
		return right.out().size() == diff && this.v() == right.v();
	}
}
