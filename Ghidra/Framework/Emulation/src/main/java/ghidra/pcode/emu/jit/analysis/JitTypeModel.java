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
package ghidra.pcode.emu.jit.analysis;

import java.util.*;
import java.util.Map.Entry;

import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.analysis.JitType.FloatJitType;
import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.emu.jit.var.JitVal.ValUse;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The type analysis for JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Type Assignment phase of the {@link JitCompiler} using a very basic "voting"
 * algorithm. The result is an assignment of type to each {@link JitVal}. To be clear, at this
 * phase, we're assigning types to variables (and constants) in the use-def graph, not varnodes.
 * Later we do another bit of "voting" to determine the type of each JVM local allocated to a
 * varnode. Perhaps we could be more direct, but in anticipation of future optimizations, we keep
 * this analysis at the per-variable level. This is partly an artifact of exploration before
 * deciding to allocate by varnode instead of by variable.
 * 
 * <h2>Types in P-code and the JVM</h2>
 * <p>
 * P-code (and Sleigh) is a relatively type free language. Aside from size, variables have no type;
 * they are just bit vectors. The operators are typed and cast the bits as required. This aligns
 * well with most machine architectures. Registers are just bit vectors, and the instructions
 * interpret them according to some type. In contrast, JVM variables have a type: {@code int},
 * {@code long}, {@code float}, {@code double}, or a reference. Conversions between JVM types must
 * be explicit, so we must attend to certain aspects of p-code types when consuming operands
 * allocated in JVM locals. There are three aspects to consider when translating p-code types to the
 * JVM: behavior, size, and signedness.
 * 
 * <h3>Behavior: Integer vs. Float</h3>
 * <p>
 * The JVM has two integral types {@code int} and {@code long} of 4 and 8 bytes respectively. P-code
 * has one integral type of no specified size. Or rather, it has as many integral types: 1-byte int,
 * 2-byte int, 3-byte int, and so on. We thus describe p-code operands as having a type
 * {@link JitTypeBehavior behavior}: <em>integral</em> or <em>floating-point</em>. Note there are
 * two ancillary behaviors <em>any</em> and <em>copy</em> to describe the operands of truly typeless
 * operators, like {@link JitCopyOp}.
 * 
 * <h3>Size</h3>
 * <p>
 * When paired with a varnode's size, we have enough information to start mapping p-code types to
 * JVM types. For float types, p-code only supports specific sizes defined by IEEE 754: 2-byte
 * half-precision, 4-byte single-precision, 8-byte double-precision, 10-byte extended-precision,
 * 16-byte quadruple-precision, and 32-byte octuple-precision. Some p-code types map precisely to
 * JVM counterparts: The 4- and 8-byte integer types map precisely to the JVM's {@code int} and
 * {@code long} types. Similarly, the 4- and 8-byte float types map precisely to {@code float} and
 * {@code double}. <b>TODO</b>: The JIT translator does not currently support integral types greater
 * than 8 bytes (64 bits) in size nor floating-point types other than 4 and 8 bytes (single and
 * double precision) in size.
 * 
 * <h3>Signedness</h3>
 * <p>
 * All floating-point types are signed, whether in p-code or in the JVM, so there's little to
 * consider in terms of mapping. Some p-code operators have signed operands, some have unsigned
 * operands, and others have no signedness at all. In contrast, no JVM bytecodes are strictly
 * unsigned. They are either signed or have no signedness. It was a choice of the Java language
 * designers that all variables would be signed, and this is consequence of that choice. In time,
 * "unsigned" operations were introduced in the form of static methods, e.g.,
 * {@link Integer#compareUnsigned(int, int)} and {@link Long#divideUnsigned(long, long)}. Note that
 * at the bit level, unsigned multiplication is the same as signed, and so no "unsigned multiply"
 * method was provided. This actually aligns well with p-code in that, for this aspect of
 * signedness, the variables are all the same. Instead the operations apply the type interpretation.
 * Thus, we need not consider signedness when allocating JVM locals.
 * 
 * <h2>Conversions and Casts</h2>
 * <p>
 * Conversions between JVM primitive types must be explicit in the emitted bytecode, even if the
 * intent is just to re-cast the bits. This is not the case for p-code. Conversions in p-code need
 * only be explicit when they mutate the actual bits. Consider the following p-code:
 * 
 * <pre>
 * $U00:4 = FLOAT_ADD r0, r1
 * r2     = INT_2COMP $U00:4
 * </pre>
 * 
 * <p>
 * The native translation to bytecode:
 * 
 * <pre>
 * FLOAD  1 # r0
 * FLOAD  2 # r1
 * FADD
 * FSTORE 3 # $U00:4
 * LDC    0
 * ILOAD  3 # $U00:4
 * ISUB
 * ISTORE 4 # r2
 * </pre>
 * 
 * <p>
 * Will cause an error when loading the class. This is because the local variable 3 must be one of
 * {@code int} or {@code float}, and the bytecode must declare which, so either the {@code FSTORE 3}
 * or the {@code ILOAD 3} will fail the JVM's type checker. To resolve this, we could assign the
 * type {@code float} to local variable 3, and change the erroneous {@code ILOAD 3} to:
 * 
 * <pre>
 * FLOAD  3
 * INVOKESTATIC {@link Float#floatToRawIntBits(float)}
 * </pre>
 * 
 * <p>
 * At this point, the bit-vector contents of {@code $U00:4} are on the stack, but for all the JVM
 * cares, they are now an {@code int}. We must assigned a JVM type to each local we allocate and
 * place bitwise type casts wherever the generated bytecodes would cause type disagreement. We would
 * like to assign JVM types in a way that reduces the number of {@code INVOKESTATIC} bytecodes
 * emitted. One could argue that we should instead seek to reduce the number of {@code INVOKESTATIC}
 * bytecodes actually executed, but I pray the JVM's JIT compiler can recognize calls to
 * {@link Float#floatToRawIntBits(float)} and similar and emit no native code for them, i.e., they
 * ought to have zero run-time cost.
 * 
 * <p>
 * Size conversions cause a similar need for explicit conversions, for two reasons: 1) Any
 * conversion between JVM {@code int} and {@code long} still requires specific bytecodes. Neither
 * platform supports implicit conversion between {@code float} and {@code double}. 2) We allocate
 * the smaller JVM integral type to accommodate each p-code integral type, so we must apply masks in
 * some cases to assure values to do not exceed their p-code varnode size. Luckily, p-code also
 * requires explicit conversions between sizes, e.g., using {@link PcodeOp#INT_ZEXT zext}. However,
 * we often have to perform temporary conversions in order to meet the type/size requirements of JVM
 * bytecodes.
 * 
 * <p>
 * Consider {@code r2 = INT_MULT r0, r1} where the registers are all 5 bytes. Thus, the registers
 * are allocated as JVM locals of type {@code long}. We load {@code r0} and {@code r1} onto the
 * stack, and then we emit an {@link Opcodes#LMUL}. Technically, the result is another JVM
 * {@code long}, which maps to an 8-byte p-code integer. Thus, we must apply a mask to "convert" the
 * result to a 5-byte p-code integer before storing the result in {@code r2}'s JVM local.
 * 
 * <h2>Type Assignment</h2>
 * <p>
 * Given that only behavior and size require any explicit conversions, we omit signedness from the
 * formal definition of p-code {@link JitType type}. It is just the behavior applied to a size,
 * e.g., {@link IntJitType#I3 int3}.
 * 
 * <p>
 * We use a fairly straightforward voting algorithm that examines how each variable definition is
 * used. The type of an operand is trivially determined by examining the behavior of each operand,
 * as specified by the p-code opcode; and the size of the input varnode, specified by the specific
 * p-code op instance. For example, the p-code op {@code $U00:4 = FLOAT_ADD r0, r1} has an output
 * operand of {@link FloatJitType#F4 float4}. Thus, it casts a vote that {@code $U00:4} should be
 * that type. However, the subsequent op {@code r2 = INT_2COMP $U00} casts a vote for
 * {@link IntJitType#I4 int4}. We prefer an {@code int} when tied, so we assign {@code $U00:4} the
 * type {@code int4}.
 * 
 * <p>
 * This become complicated in the face of typeless ops, namely {@link JitCopyOp copy} and
 * {@link JitPhiOp phi}. Again, we'd like to reduce the number of casts we have to emit in the
 * bytecode. Consider the op {@code r1 = COPY r0}. This should emit a load followed immediately by a
 * store, but The JVM will require both the source and destination locals to have the same type.
 * Otherwise, a cast is necessary. The votes regarding {@code r0} will thus need to incorporate the
 * votes regarding {@code r1} and vice versa.
 * 
 * <p>
 * Our algorithm is a straightforward queued traversal of the use-def graph until convergence.
 * First, we initialize a queue with all values (variables and constants) in the graph and
 * initialize all type assignments to {@link JitTypeBehavior#ANY any}. We then process each value in
 * the queue until it is empty. A value receives votes from its uses as required by each operand.
 * {@link JitTypeBehavior#INTEGER integer} and {@link JitTypeBehavior float} behaviors count as 1
 * vote for that behavior. The {@link JitTypeBehavior#ANY any} behavior contributes 0 votes. If the
 * behavior is {@link JitTypeBehavior#COPY copy}, then we know the use is either a {@link JitCopyOp
 * copy} or {@link JitPhiOp phi} op, so we fetch its output value. The op casts its vote for the
 * tentative type of that output value. Similar is done for the value's defining op, if applicable.
 * If it's a copy or phi, we start a sub contest where each input/option casts a vote for its
 * tentative type. The defining op's vote is cast according to the winner of the sub contest. Ties
 * favor {@link JitTypeBehavior#INTEGER integer}. The final winner is computed and the tentative
 * type assignment is updated. If there are no votes, the tentative assignment is
 * {@link JitTypeBehavior#ANY}.
 * 
 * <p>
 * When an update changes the tentative type assignment of a value, then all its neighbors are added
 * back to the queue. Neighbors are those values connected to this one via a copy or phi. When the
 * queue is empty, the tentative type assignments are made final. Any assignment that remains
 * {@link JitTypeBehavior#ANY any} is treated as if {@link JitTypeBehavior#INTEGER int}.
 * <b>TODO</b>: Prove that this algorithm always terminates.
 * 
 * @implNote We do all the bookkeeping in terms of {@link JitTypeBehavior} and wait to resolve the
 *           actual type until the final assignment.
 */
public class JitTypeModel {

	/**
	 * A contest to determine a type assignment
	 * 
	 * @param counts the initial count for each candidate (should just be empty)
	 */
	protected record Contest(Map<JitTypeBehavior, Integer> counts) {
		/**
		 * Start a new contest
		 */
		public Contest() {
			this(new HashMap<>());
		}

		/**
		 * Cast a vote for the given candidate
		 * 
		 * @param candidate the candidate type
		 * @param c the number of votes cast
		 */
		private void vote(JitTypeBehavior candidate, int c) {
			if (candidate == JitTypeBehavior.ANY || candidate == JitTypeBehavior.COPY) {
				return;
			}
			counts.compute(candidate, (k, v) -> v == null ? c : v + c);
		}

		/**
		 * Cast a vote for the given candidate
		 * 
		 * @param candidate the candidate type
		 */
		public void vote(JitTypeBehavior candidate) {
			vote(candidate, 1);
		}

		/**
		 * Compare the votes between two candidates, and select the winner
		 * 
		 * <p>
		 * The {@link #winner()} method seeks the "max" candidate, so the vote counts are compared
		 * in the usual fashion. We need to invert the comparison of the types, though.
		 * {@link JitTypeBehavior#INTEGER} has a lower ordinal than {@link JitTypeBehavior#FLOAT},
		 * but we want to ensure int is preferred, so we reverse that comparison.
		 * 
		 * @param ent1 the first candidate-vote entry
		 * @param ent2 the second candidate-vote entry
		 * @return -1 if the <em>second</em> wins, 1 if the <em>first</em> wins. 0 should never
		 *         result, unless we're comparing a candidate with itself.
		 */
		public static int compareCandidateEntries(Entry<JitTypeBehavior, Integer> ent1,
				Entry<JitTypeBehavior, Integer> ent2) {
			int c;
			c = Integer.compare(ent1.getValue(), ent2.getValue());
			if (c != 0) {
				return c;
			}
			c = JitTypeBehavior.compare(ent1.getKey(), ent2.getKey());
			if (c != 0) {
				return -c; // INT is preferred to FLOAT
			}
			return 0;
		}

		/**
		 * Compute the winner of the contest
		 * 
		 * @return the winner, or {@link JitTypeBehavior#ANY} if there are no entries
		 */
		public JitTypeBehavior winner() {
			return counts.entrySet()
					.stream()
					.max(Contest::compareCandidateEntries)
					.map(Entry::getKey)
					.orElse(JitTypeBehavior.ANY);
		}
	}

	private final JitDataFlowModel dfm;

	private final SequencedSet<JitVal> queue = new LinkedHashSet<>();
	private final Map<JitVal, JitTypeBehavior> assignments = new HashMap<>();

	/**
	 * Construct the type model
	 * 
	 * @param dfm the data flow model whose use-def graph to process
	 */
	public JitTypeModel(JitDataFlowModel dfm) {
		this.dfm = dfm;

		analyze();
	}

	/**
	 * Compute the new tentative assignment for the given value
	 * 
	 * <p>
	 * As discussed in the "voting" section of {@link JitTypeModel}, this tallies up the votes among
	 * the values's uses and defining op then selects the winner.
	 * 
	 * @param v the value
	 * @return the new assignment
	 */
	protected JitTypeBehavior computeNewAssignment(JitVal v) {
		Contest contest = new Contest();
		// Downstream votes
		for (ValUse use : v.uses()) {
			JitTypeBehavior type = use.type();
			if (type == JitTypeBehavior.COPY && use.op() instanceof JitDefOp def) {
				JitVal downstream = def.out();
				type = assignments.get(downstream);
			}
			contest.vote(type);
		}

		// Upstream votes
		if (v instanceof JitOutVar out) {
			JitTypeBehavior defType = JitTypeBehavior.ANY;
			JitDefOp def = out.definition();
			defType = def.type();
			if (defType == JitTypeBehavior.COPY) {
				Contest subContest = new Contest();
				for (JitVal upstream : def.inputs()) {
					subContest.vote(assignments.get(upstream));
				}
				defType = subContest.winner();
			}
			contest.vote(defType);
		}

		return contest.winner();
	}

	/**
	 * Re-add the given value's neighbors to the processing queue.
	 * 
	 * <p>
	 * Neighbors are any values connected to the given one via {@link JitCopyOp} or {@link JitPhiOp}
	 * &mdash; or any op with an operand requiring {@link JitTypeBehavior#COPY} if additional ones
	 * should appear in the future. This is necessary because those ops may change their vote now
	 * that this value's tentative type has changed. Note if the value is already in the queue, it
	 * need not be added again. Thus, the queue is a {@link SequencedSet}.
	 * 
	 * @param v the value whose neighbors to re-process
	 */
	protected void queueNeighbors(JitVal v) {
		for (ValUse use : v.uses()) {
			JitTypeBehavior type = use.type();
			if (type == JitTypeBehavior.COPY && use.op() instanceof JitDefOp def) {
				queue.add(def.out());
			}
		}

		if (v instanceof JitOutVar out) {
			JitDefOp def = out.definition();
			if (def.type() == JitTypeBehavior.COPY) {
				queue.addAll(def.inputs());
			}
		}
	}

	/**
	 * Perform the analysis
	 * 
	 * <p>
	 * This queues every value up to be processed at least once and then runs the algorithm to
	 * termination. Each value in the queue is removed and a voting contest run to update its type
	 * assignment. If the new assignment differs from its old assignment, its neighbors (if any) are
	 * re-added to the queue.
	 */
	protected void analyze() {
		Set<JitVal> vals = dfm.allValues();
		queue.addAll(vals);
		for (JitVal v : vals) {
			assignments.put(v, JitTypeBehavior.ANY);
		}

		while (!queue.isEmpty()) {
			JitVal v = queue.removeFirst();
			JitTypeBehavior type = computeNewAssignment(v);
			JitTypeBehavior old = assignments.put(v, type);
			if (old != type) {
				queueNeighbors(v);
			}
		}
	}

	/**
	 * Get the final type assignment for the given value
	 * 
	 * @param v the value
	 * @return the value's assigned type
	 */
	public JitType typeOf(JitVal v) {
		return assignments.get(v).type(v.size());
	}
}
