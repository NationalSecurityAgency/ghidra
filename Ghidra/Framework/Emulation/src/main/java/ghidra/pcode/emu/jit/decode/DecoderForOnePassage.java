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
package ghidra.pcode.emu.jit.decode;

import java.util.*;
import java.util.stream.Stream;

import org.apache.commons.collections4.MapUtils;

import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.folding.*;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The decoder for a single passage
 * <p>
 * This is a sort of "mutable" passage or passage "builder" that is used while the passage is being
 * decoded. Once complete, this provides an immutable decoded {@link JitPassage}.
 */
@Internal
public class DecoderForOnePassage {
	public final JitPassageDecoder decoder;
	private final AddrCtx seed;
	private final int maxOps;
	private final int maxInstrs;
	private final int maxStrides;

	public final Map<PcodeOp, RIntBranch> internalBranches = new HashMap<>();
	// Sequenced, because this is also the seed queue
	final TieredBranchQueue externalBranches = new TieredBranchQueue();
	final Map<PcodeOp, PBranch> otherBranches = new HashMap<>();
	public final Map<AddrCtx, PcodeOp> firstOps = new HashMap<>();
	public final List<DecodedStride> strides = new ArrayList<>();
	public final Map<Operand, byte[]> folded = new HashMap<>();
	final Map<PcodeOp, List<PcodeOp>> inlines = new HashMap<>();

	private int opCount = 0;
	private int instructionCount = 0;

	static class TieredBranchQueue {
		final SequencedMap<PcodeOp, RExtBranch> direct = new LinkedHashMap<>();
		final SequencedMap<PcodeOp, RExtBranch> folded = new LinkedHashMap<>();

		void put(PcodeOp op, RExtBranch branch) {
			var which = switch (op.getOpcode()) {
				case PcodeOp.BRANCHIND, PcodeOp.CALLIND -> folded;
				default -> direct;
			};
			which.put(op, branch);
		}

		RExtBranch next() {
			var first = direct.pollFirstEntry();
			if (first != null) {
				return first.getValue();
			}
			first = folded.pollFirstEntry();
			if (first != null) {
				return first.getValue();
			}
			return null;
		}

		Collection<RExtBranch> remaining() {
			return Stream.concat(direct.values().stream(), folded.values().stream()).toList();
		}

		void clear() {
			direct.clear();
			folded.clear();
		}
	}

	/**
	 * Construct the decoder
	 * 
	 * @param decoder the thread's passage decoder
	 * @param seed the seed for this passage
	 * @param maxOps the maximum-ish number of p-code ops to emit
	 */
	DecoderForOnePassage(JitPassageDecoder decoder, AddrCtx seed, int maxOps) {
		this.decoder = decoder;
		this.seed = seed;
		this.maxOps = maxOps;
		JitConfiguration config = decoder.thread.getMachine().getConfiguration();
		this.maxInstrs = config.maxPassageInstructions();
		this.maxStrides = config.maxPassageStrides();
		EntryPcodeOp entryOp = new EntryPcodeOp(seed);
		externalBranches.put(entryOp, new RExtBranch(entryOp, seed,
			config.foldConstants() ? new FoldedState(decoder.thread.getLanguage()) : null,
			CtxReach.WITHOUT_CTXMOD));
	}

	/**
	 * Implements the actual decode loop
	 */
	void decodePassage() {
		while (opCount < maxOps && instructionCount < maxInstrs &&
			strides.size() < maxStrides) {
			RExtBranch next = externalBranches.next();
			if (next == null) {
				break;
			}
			AddrCtx start = next.to();

			if (decoder.thread.hasEntry(start)) {
				otherBranches.put(next.from(), next);
			}
			else if (!next.reach().canReachWithoutCtxMod()) {
				otherBranches.put(next.from(), next);
			}
			else {
				decodeStride(start, next.state());
				PcodeOp to = Objects.requireNonNull(firstOps.get(start));
				internalBranches.put(next.from(), next.toIntBranch(to));
			}
		}
	}

	/**
	 * Record that a direct branch was encountered.
	 * <p>
	 * If we've already decoded the target, we create an {@link IntBranch} record, and we're done.
	 * Otherwise, we queue up the {@link ExtBranch} record. If multiple direct branches target the
	 * same address, we still create separate entries. First, we note their {@link Branch#from()
	 * from} fields will be different. Also, we ensure once we've terminated (probably because of a
	 * quota), we must examine records still in the queue, but whose targets may have since been
	 * decoded, and convert them to {@link IntBranch} records.
	 * 
	 * @param eb the tentatively-external branch whose flow we may follow
	 */
	void flowTo(RExtBranch eb) {
		if (!eb.reach().canReachWithoutCtxMod()) {
			otherBranches.put(eb.from(), eb);
			return;
		}
		PcodeOp to = firstOps.get(eb.to());
		if (to != null) {
			internalBranches.put(eb.from(), eb.toIntBranch(to));
			return;
		}
		externalBranches.put(eb.from(), eb);
	}

	/**
	 * Decode a stride starting at the given address.
	 * 
	 * @param start the starting address and context
	 * @param state the constant-folding state at the given start
	 */
	private void decodeStride(AddrCtx start, FoldedState state) {
		DecodedStride stride = new DecoderForOneStride(decoder, this, start, state).decode();
		opCount += stride.ops().size();
		instructionCount += stride.instructions().size();
		strides.add(stride);
	}

	void revalidateFolded() {
		if (decoder.thread.getMachine().getConfiguration().foldConstants()) {
			new FoldRevalidator(this).revalidate();
		}
	}

	/**
	 * Sort out the result and create the decoded passage
	 * <p>
	 * The strides are sorted by their seeds (contextreg value then address), and their code
	 * concatenated together. The various types of branches are also all combined. (They can still
	 * be distinguished by type.) {@link ExtBranch} records are converted to {@link IntBranch}
	 * records where possible.
	 * 
	 * @return the passage
	 */
	JitPassage finish() {
		strides.sort(Comparator.comparing(DecodedStride::start));
		List<PcodeOp> code = strides.stream().flatMap(b -> b.ops().stream()).toList();
		List<Instruction> instructions =
			strides.stream().flatMap(b -> b.instructions().stream()).toList();
		Map<PcodeOp, PBranch> branches = otherBranches;
		branches.putAll(internalBranches);
		for (RExtBranch eb : externalBranches.remaining()) {
			if (!eb.reach().canReachWithoutCtxMod()) {
				branches.put(eb.from(), eb);
			}
			PcodeOp to = firstOps.get(eb.to());
			if (to != null) {
				branches.put(eb.from(), eb.toIntBranch(to));
			}
			else {
				branches.put(eb.from(), eb);
			}
		}
		return new JitPassage(decoder.thread.getLanguage(), seed, code, decoder.library,
			instructions, branches, MapUtils.invertMap(firstOps), folded);
	}

	/**
	 * Get the decoder-wrapped userop library
	 * 
	 * @return the library
	 */
	public PcodeUseropLibrary<MaskedBytes> library() {
		return decoder.library;
	}

	static boolean vnArrsEquivalent(Varnode[] a, Varnode[] b) {
		int n = a.length;
		if (n != b.length) {
			return false;
		}
		for (int i = 0; i < n; i++) {
			if (!vnsEquivalent(a[i], b[i])) {
				return false;
			}
		}
		return true;
	}

	static boolean vnsEquivalent(Varnode a, Varnode b) {
		if ((a == null) != (b == null)) {
			return false;
		}
		if (a == null) {
			return true;
		}
		return a.getOffset() == b.getOffset() && a.getSize() == b.getSize() &&
			a.getSpace() == b.getSpace();
	}

	/**
	 * Because {@link PcodeOp} does not override {@link Object#equals}, we define one here for our
	 * specific purposes.
	 * 
	 * @param a the first op
	 * @param b the second op
	 * @return true if the ops have the same opcode, output, and inputs
	 */
	static boolean opsEquivalent(PcodeOp a, PcodeOp b) {
		if ((a instanceof NopPcodeOp) != (b instanceof NopPcodeOp)) {
			return false;
		}
		if (a.getOpcode() != b.getOpcode()) {
			return false;
		}
		if (!vnsEquivalent(a.getOutput(), b.getOutput())) {
			return false;
		}
		if (!vnArrsEquivalent(a.getInputs(), b.getInputs())) {
			return false;
		}
		return true;
	}

	/**
	 * Check if the given op was replaced with the same program as before
	 * 
	 * @param op the inlined op
	 * @param revalidated the newly-observed replacement
	 * @return true if the replacement observed during decode is the same as the one given
	 */
	public boolean checkSameInline(PcodeOp op, List<PcodeOp> revalidated) {
		List<PcodeOp> original = inlines.get(op);
		int n = original.size();
		if (n != revalidated.size()) {
			return false;
		}
		for (int i = 0; i < n; i++) {
			PcodeOp oOp = original.get(i);
			PcodeOp rOp = revalidated.get(i);
			if (!opsEquivalent(oOp, rOp)) {
				return false;
			}
		}
		return true;
	}
}
