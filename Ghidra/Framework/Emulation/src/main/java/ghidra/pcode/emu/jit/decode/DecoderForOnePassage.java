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
import java.util.Map.Entry;

import org.apache.commons.collections4.MapUtils;

import ghidra.pcode.emu.jit.JitConfiguration;
import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The decoder for a single passage
 * 
 * <p>
 * This is a sort of "mutable" passage or passage "builder" that is used while the passage is being
 * decoded. Once complete, this provides an immutable (or at least it's supposed to be) decoded
 * {@link Passage}.
 */
class DecoderForOnePassage {
	private final JitPassageDecoder decoder;
	private final AddrCtx seed;
	private final int maxOps;
	private final int maxInstrs;
	private final int maxStrides;

	final Map<PcodeOp, RIntBranch> internalBranches = new HashMap<>();
	// Sequenced, because this is also the seed queue
	final SequencedMap<PcodeOp, RExtBranch> externalBranches = new LinkedHashMap<>();
	final Map<PcodeOp, PBranch> otherBranches = new HashMap<>();
	final Map<AddrCtx, PcodeOp> firstOps = new HashMap<>();
	final List<DecodedStride> strides = new ArrayList<>();

	private int opCount = 0;
	private int instructionCount = 0;

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
		externalBranches.put(entryOp, new RExtBranch(entryOp, seed, Reachability.WITHOUT_CTXMOD));
	}

	/**
	 * Implements the actual decode loop
	 */
	void decodePassage() {
		while (opCount < maxOps && instructionCount < maxInstrs &&
			strides.size() < maxStrides) {
			Entry<PcodeOp, RExtBranch> nextEnt = externalBranches.pollFirstEntry();
			if (nextEnt == null) {
				break;
			}
			RExtBranch next = nextEnt.getValue();
			AddrCtx start = next.to();

			if (decoder.thread.hasEntry(start)) {
				otherBranches.put(next.from(), next);
			}
			else if (!next.reach().canReachWithoutCtxMod()) {
				otherBranches.put(next.from(), next);
			}
			else {
				decodeStride(start);
				PcodeOp to = Objects.requireNonNull(firstOps.get(start));
				internalBranches.put(next.from(), next.toIntBranch(to));
			}
		}
	}

	/**
	 * Record that a direct branch was encountered.
	 * 
	 * <p>
	 * If we've already decoded the target, we create an {@link IntBranch} record, and we're done.
	 * Otherwise, we queue up an {@link ExtBranch} record. If multiple direct branches target the
	 * same address, we still create separate entries. First, we note their {@link Branch#from()
	 * from} fields will be different. Also, we ensure once we've terminated (probably because of a
	 * quota), we must examine records still in the queue, but whose targets may have since been
	 * decoded, and convert them to {@link IntBranch} records.
	 * 
	 * @param from the op representing or causing the control flow
	 * @param to the target of the branch
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
	 */
	private void decodeStride(AddrCtx start) {
		DecodedStride stride = new DecoderForOneStride(decoder, this, start).decode();
		opCount += stride.ops().size();
		instructionCount += stride.instructions().size();
		strides.add(stride);
	}

	/**
	 * Sort out the result and create the decoded passage
	 * 
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
		for (RExtBranch eb : externalBranches.values()) {
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
			instructions, branches, MapUtils.invertMap(firstOps));
	}

	/**
	 * Get the decoder-wrapped userop library
	 * 
	 * @return the library
	 */
	PcodeUseropLibrary<Object> library() {
		return decoder.library;
	}
}
