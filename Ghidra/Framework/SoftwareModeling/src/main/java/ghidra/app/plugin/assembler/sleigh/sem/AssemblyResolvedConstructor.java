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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.Predicate;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.processors.sleigh.ConstructState;
import ghidra.app.plugin.processors.sleigh.ContextOp;

/**
 * A {@link AssemblyResolution} indicating successful application of a constructor
 * 
 * This is almost analogous to {@link ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern
 * DisjointPattern}, in that is joins an instruction {@link AssemblyPatternBlock} with a corresponding
 * context {@link AssemblyPatternBlock}. However, this object is mutable, and it collects backfill records,
 * as well as forbidden patterns.
 * 
 * When the applied constructor is from the "instruction" subtable, this represents a fully-
 * constructed instruction with required context. All backfill records ought to be resolved and
 * applied before the final result is given to the user, i.e., passed into the
 * {@link AssemblySelector}. If at any time during the resolution or backfill process, the result
 * becomes confined to one of the forbidden patterns, it must be dropped, since the encoding will
 * actually invoke a more specific SLEIGH constructor.
 */
public class AssemblyResolvedConstructor extends AssemblyResolution {
	protected static final String INS = "ins:";
	protected static final String CTX = "ctx:";
	protected static final String SEP = ",";

	protected final AssemblyPatternBlock ins;
	protected final AssemblyPatternBlock ctx;

	protected final Set<AssemblyResolvedBackfill> backfills;
	protected final Set<AssemblyResolvedConstructor> forbids;

	@Override
	protected int computeHash() {
		int result = 0;
		result += ins.hashCode();
		result *= 31;
		result += ctx.hashCode();
		result *= 31;
		result += backfills.hashCode();
		result *= 31;
		result += forbids.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AssemblyResolvedConstructor)) {
			return false;
		}
		AssemblyResolvedConstructor that = (AssemblyResolvedConstructor) obj;
		if (!this.ins.equals(that.ins)) {
			return false;
		}
		if (!this.ctx.equals(that.ctx)) {
			return false;
		}
		if (!this.backfills.equals(that.backfills)) {
			return false;
		}
		if (!this.forbids.equals(that.forbids)) {
			return false;
		}
		return true;
	}

	/**
	 * @see AssemblyResolution#resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, List)
	 */
	AssemblyResolvedConstructor(String description,
			List<? extends AssemblyResolution> children, AssemblyPatternBlock ins,
			AssemblyPatternBlock ctx, Set<AssemblyResolvedBackfill> backfills,
			Set<AssemblyResolvedConstructor> forbids) {
		super(description, children);
		this.ins = ins;
		this.ctx = ctx;
		this.backfills = backfills == null ? Set.of() : backfills;
		this.forbids = forbids == null ? Set.of() : forbids;
	}

	/**
	 * Build a new successful SLEIGH constructor resolution from a string representation
	 * 
	 * This was used primarily in testing, to specify expected results.
	 * @param str the string representation: "{@code ins:[pattern],ctx:[pattern]}"
	 * @see ghidra.util.NumericUtilities#convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)
	 * NumericUtilities.convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)
	 * @param description a description of the resolution
	 * @param children any children involved in the resolution
	 * @return the decoded resolution
	 */
	public static AssemblyResolvedConstructor fromString(String str, String description,
			List<AssemblyResolution> children) {
		AssemblyPatternBlock ins = null;
		if (str.startsWith(INS)) {
			int end = str.indexOf(SEP);
			if (end == -1) {
				end = str.length();
			}
			ins = AssemblyPatternBlock.fromString(str.substring(INS.length(), end));
			str = str.substring(end);
			if (str.startsWith(SEP)) {
				str = str.substring(1);
			}
		}
		AssemblyPatternBlock ctx = null;
		if (str.startsWith(CTX)) {
			int end = str.length();
			ctx = AssemblyPatternBlock.fromString(str.substring(CTX.length(), end));
			str = str.substring(end);
		}
		if (str.length() != 0) {
			throw new IllegalArgumentException(str);
		}
		return AssemblyResolution.resolved(//
			ins == null ? AssemblyPatternBlock.nop() : ins,//
			ctx == null ? AssemblyPatternBlock.nop() : ctx,//
			description, children);
	}

	/**
	 * Shift the resolved instruction pattern to the right
	 * 
	 * This also shifts any backfill and forbidden pattern records.
	 * @param amt the number of bytes to shift.
	 * @return the result
	 */
	public AssemblyResolvedConstructor shift(int amt) {
		if (amt == 0) {
			return this;
		}
		AssemblyPatternBlock newIns = this.ins.shift(amt);

		// Also shift the attached backfills and forbidden patterns
		Set<AssemblyResolvedBackfill> newBackfills = new HashSet<>();
		for (AssemblyResolvedBackfill bf : this.backfills) {
			newBackfills.add(bf.shift(amt));
		}

		Set<AssemblyResolvedConstructor> newForbids = new HashSet<>();
		for (AssemblyResolvedConstructor f : this.forbids) {
			newForbids.add(f.shift(amt));
		}
		return new AssemblyResolvedConstructor(description, children, newIns, ctx,
			Collections.unmodifiableSet(newBackfills), Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Truncate (unshift) the resolved instruction pattern from the left
	 * 
	 * NOTE: This drops all backfill and forbidden pattern records, since this method is typically
	 *       used to read token fields rather than passed around for resolution.
	 * @param amt the number of bytes to remove from the left
	 * @return the result
	 */
	public AssemblyResolvedConstructor truncate(int amt) {
		if (amt == 0) {
			return this;
		}
		AssemblyPatternBlock newIns = this.ins.truncate(amt);

		return new AssemblyResolvedConstructor("Truncated: " + description, null, newIns, ctx, null,
			null);
	}

	/**
	 * Check if the current encoding is forbidden by one of the attached patterns
	 * 
	 * The pattern become forbidden if this encoding's known bits are an overset of any forbidden
	 * pattern's known bits.
	 * @return false if the pattern is forbidden (and thus in error), true if permitted
	 */
	public AssemblyResolution checkNotForbidden() {
		Set<AssemblyResolvedConstructor> newForbids = new HashSet<>();
		for (AssemblyResolvedConstructor f : this.forbids) {
			AssemblyResolvedConstructor check = this.combine(f);
			if (null == check) {
				continue;
			}
			newForbids.add(f);
			if (check.bitsEqual(this)) {
				// The result would be disassembled by a more-specific constructor.
				return AssemblyResolution.error("The result is forbidden by " + f, this);
			}
		}
		return new AssemblyResolvedConstructor(description, children, ins, ctx, backfills,
			Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Check if this and another resolution have equal encodings
	 * 
	 * This is like {@link #equals(Object)}, but it ignores backfills records and forbidden
	 * patterns.
	 * @param that the other resolution
	 * @return true if both have equal encodings
	 */
	protected boolean bitsEqual(AssemblyResolvedConstructor that) {
		return this.ins.equals(that.ins) && this.ctx.equals(that.ctx);
	}

	/**
	 * Combine the encodings and backfills of the given resolution into this one
	 * 
	 * This combines corresponding pattern blocks (assuming they agree), collects backfill
	 * records, and collects forbidden patterns.
	 * @param that the other resolution
	 * @return the result if successful, or null
	 */
	public AssemblyResolvedConstructor combine(AssemblyResolvedConstructor that) {
		// Not really a backfill, but I would like to re-use code
		return combineLessBackfill(that, null);
	}

	/**
	 * Combine a backfill result
	 * @param that the result from backfilling
	 * @param bf the resolved backfilled record
	 * @return the result if successful, or null
	 * 
	 * When a backfill is successful, the result should be combined with the owning resolution. In
	 * addition, for bookkeeping's sake, the resolved record should be removed from the list of
	 * backfills.
	 */
	protected AssemblyResolvedConstructor combineLessBackfill(AssemblyResolvedConstructor that,
			AssemblyResolvedBackfill bf) {
		AssemblyPatternBlock newIns = this.ins.combine(that.ins);
		if (newIns == null) {
			return null;
		}
		AssemblyPatternBlock newCtx = this.ctx.combine(that.ctx);
		if (newCtx == null) {
			return null;
		}
		Set<AssemblyResolvedBackfill> newBackfills = new HashSet<>(this.backfills);
		newBackfills.addAll(that.backfills);
		if (bf != null) {
			newBackfills.remove(bf);
		}
		Set<AssemblyResolvedConstructor> newForbids = new HashSet<>(this.forbids);
		newForbids.addAll(that.forbids);
		return new AssemblyResolvedConstructor(description, children, newIns, newCtx,
			Collections.unmodifiableSet(newBackfills), Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Combine the given backfill record into this resolution
	 * @param bf the backfill record
	 * @return the result
	 */
	public AssemblyResolvedConstructor combine(AssemblyResolvedBackfill bf) {
		Set<AssemblyResolvedBackfill> newBackfills = new HashSet<>(this.backfills);
		newBackfills.add(bf);
		return new AssemblyResolvedConstructor(description, children, ins, ctx,
			Collections.unmodifiableSet(newBackfills), forbids);
	}

	/**
	 * Create a new resolution from this one with the given forbidden patterns recorded
	 * @param more the additional forbidden patterns to record
	 * @return the new resolution
	 */
	public AssemblyResolvedConstructor withForbids(Set<AssemblyResolvedConstructor> more) {
		Set<AssemblyResolvedConstructor> combForbids = new HashSet<>(this.forbids);
		combForbids.addAll(more);
		return new AssemblyResolvedConstructor(description, children, ins, ctx, backfills,
			Collections.unmodifiableSet(more));
	}

	/**
	 * Create a copy of this resolution with a new description
	 * @param desc the new description
	 * @return the copy
	 */
	public AssemblyResolvedConstructor withDescription(String desc) {
		return new AssemblyResolvedConstructor(desc, children, ins, ctx, backfills, forbids);
	}

	/**
	 * Encode the given value into the context block as specified by an operation
	 * @param cop the context operation specifying the location of the value to encode
	 * @param val the masked value to encode
	 * @return the result
	 * 
	 * This is the forward (as in disassembly) direction of applying context operations. The
	 * pattern expression is evaluated, and the result is written as specified.
	 */
	public AssemblyResolvedConstructor writeContextOp(ContextOp cop, MaskedLong val) {
		AssemblyPatternBlock newCtx = this.ctx.writeContextOp(cop, val);
		return new AssemblyResolvedConstructor(description, children, ins, newCtx, backfills,
			forbids);
	}

	/**
	 * Decode the value from the context located where the given context operation would write
	 * 
	 * This is used to read the value from the left-hand-side "variable" of a context operation.
	 * It seems backward, because it is. When assembling, the right-hand-side expression of a
	 * context operation must be solved. This means the "variable" is known from the context(s) of
	 * the resolved children constructors. The value read is then used as the goal in solving the
	 * expression.
	 * @param cop the context operation whose "variable" to read.
	 * @return the masked result.
	 */
	public MaskedLong readContextOp(ContextOp cop) {
		return ctx.readContextOp(cop);
	}

	/**
	 * Duplicate this resolution, with additional description text appended
	 * @param append the text to append
	 * @return the duplicate
	 * NOTE: An additional separator {@code ": "} is inserted
	 */
	public AssemblyResolvedConstructor copyAppendDescription(String append) {
		AssemblyResolvedConstructor cp = new AssemblyResolvedConstructor(
			description + ": " + append, children, ins.copy(), ctx.copy(), backfills, forbids);
		return cp;
	}

	/**
	 * Set all bits read by a given context operation to unknown
	 * @param cop the context operation
	 * @return the result
	 * @see AssemblyPatternBlock#maskOut(ContextOp)
	 */
	public AssemblyResolvedConstructor maskOut(ContextOp cop) {
		AssemblyPatternBlock newCtx = this.ctx.maskOut(cop);
		return new AssemblyResolvedConstructor(description, children, ins, newCtx, backfills,
			forbids);
	}

	/**
	 * Apply as many backfill records as possible
	 * 
	 * Each backfill record is resolved in turn, if the record cannot be resolved, it remains
	 * listed. If the record can be resolved, but it conflicts, an error record is returned. Each
	 * time a record is resolved and combined successfully, all remaining records are tried again.
	 * The result is the combined resolved backfills, with only the unresolved backfill records
	 * listed.
	 * @param solver the solver, usually the same as the original attempt to solve.
	 * @param vals the values.
	 * @return the result, or an error.
	 */
	public AssemblyResolution backfill(RecursiveDescentSolver solver, Map<String, Long> vals) {
		if (!hasBackfills()) {
			return this;
		}

		AssemblyResolvedConstructor res = this;
		loop: while (true) {
			for (AssemblyResolvedBackfill bf : res.backfills) {
				AssemblyResolution ar = bf.solve(solver, vals, this);
				if (ar.isError()) {
					continue;
				}
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
				AssemblyResolvedConstructor check = res.combineLessBackfill(rc, bf);
				if (check == null) {
					return AssemblyResolution.error("Conflict: Backfill " + bf.description, res);
				}
				res = check;
				continue loop;
			}
			return res;
		}
	}

	@Override
	public String lineToString() {
		return dumpConstructorTree() + ":" + INS + ins + SEP + CTX + ctx + " (" + description + ")";
	}

	/**
	 * Check if this resolution has pending backfills to apply
	 * @return true if there are backfills
	 */
	public boolean hasBackfills() {
		return !backfills.isEmpty();
	}

	/**
	 * Check if this resolution includes forbidden patterns
	 * @return true if there are forbidden patterns
	 */
	private boolean hasForbids() {
		return !forbids.isEmpty();
	}

	/**
	 * Solve and apply context changes in reverse to forbidden patterns
	 * 
	 * To avoid circumstances where a context change during disassembly would invoke a more
	 * specific subconstructor than was used to assembly the instruction, we must solve the
	 * forbidden patterns in tandem with the overall resolution. If the context of any forbidden
	 * pattern cannot be solved, we simply drop the forbidden pattern -- the lack of a solution
	 * implies there is no way the context change could produce the forbidden pattern.
	 * @param sem the constructor whose context changes to solve
	 * @param vals any defined symbols
	 * @param opvals the operand values
	 * @return the result
	 * @see AssemblyConstructorSemantic#solveContextChanges(AssemblyResolvedConstructor, Map, Map)
	 */
	public AssemblyResolvedConstructor solveContextChangesForForbids(
			AssemblyConstructorSemantic sem, Map<String, Long> vals, Map<Integer, Object> opvals) {
		if (!hasForbids()) {
			return this;
		}
		Set<AssemblyResolvedConstructor> newForbids = new HashSet<>();
		for (AssemblyResolvedConstructor f : this.forbids) {
			AssemblyResolution t = sem.solveContextChanges(f, vals, opvals);
			if (!(t instanceof AssemblyResolvedConstructor)) {
				// Can't be solved, so it can be dropped
				continue;
			}
			newForbids.add((AssemblyResolvedConstructor) t);
		}
		return new AssemblyResolvedConstructor(description, children, ins, ctx, backfills,
			Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Get the length of the instruction encoding
	 * 
	 * This is used to ensure each operand is encoded at the correct offset
	 * @return the length of the instruction block
	 * 
	 * NOTE: this DOES include the offset
	 * NOTE: this DOES include pending backfills
	 */
	public int getInstructionLength() {
		int inslen = ins.length();
		for (AssemblyResolvedBackfill bf : backfills) {
			inslen = Math.max(inslen, bf.getInstructionLength());
		}
		return inslen;
	}

	/**
	 * Get the length of the instruction encoding, excluding trailing undefined bytes
	 * @return the length of the defined bytes in the instruction block
	 * 
	 * NOTE: this DOES include the offset
	 * NOTE: this DOES NOT include pending backfills
	 */
	public int getDefinedInstructionLength() {
		byte[] imsk = ins.getMask();
		int i;
		for (i = imsk.length - 1; i >= 0; i--) {
			if (imsk[i] != 0) {
				break;
			}
		}
		return ins.getOffset() + i + 1;
	}

	/**
	 * Get the instruction block
	 * @return the instruction block
	 */
	public AssemblyPatternBlock getInstruction() {
		return ins;
	}

	/**
	 * Get the context block
	 * @return the context block
	 */
	public AssemblyPatternBlock getContext() {
		return ctx;
	}

	/**
	 * Decode a portion of the instruction block
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the read masked value
	 * @see AssemblyPatternBlock#readBytes(int, int)
	 */
	public MaskedLong readInstruction(int start, int len) {
		return ins.readBytes(start, len);
	}

	/**
	 * Decode a portion of the context block
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the read masked value
	 * @see AssemblyPatternBlock#readBytes(int, int)
	 */
	public MaskedLong readContext(int start, int len) {
		return ctx.readBytes(start, len);
	}

	@Override
	public boolean isError() {
		return false;
	}

	@Override
	public boolean isBackfill() {
		return false;
	}

	@Override
	public boolean hasChildren() {
		return super.hasChildren() || hasBackfills() || hasForbids();
	}

	@Override
	protected String childrenToString(String indent) {
		StringBuilder sb = new StringBuilder();
		if (super.hasChildren()) {
			sb.append(super.childrenToString(indent) + "\n");
		}
		for (AssemblyResolvedBackfill bf : backfills) {
			sb.append(indent);
			sb.append("backfill: " + bf + "\n");
		}
		for (AssemblyResolvedConstructor f : forbids) {
			sb.append(indent);
			sb.append("forbidden: " + f + "\n");
		}
		return sb.substring(0, sb.length() - 1);
	}

	protected static final Pattern pat = Pattern.compile("line(\\d*)");

	/**
	 * Used for testing and diagnostics: list the constructor line numbers used to resolve this
	 * encoding
	 * 
	 * This includes braces to describe the tree structure
	 * @see ConstructState#dumpConstructorTree()
	 * @return the constructor tree
	 */
	public String dumpConstructorTree() {
		StringBuilder sb = new StringBuilder();
		// TODO: HACK, but diagnostic
		Matcher mat = pat.matcher(description);
		if (mat.find()) {
			sb.append(mat.group(1));
		}
		else {
			return null;
		}

		if (children == null) {
			return sb.toString();
		}

		List<String> subs = new ArrayList<>();
		for (AssemblyResolution c : children) {
			if (c instanceof AssemblyResolvedConstructor) {
				AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) c;
				String s = rc.dumpConstructorTree();
				if (s != null) {
					subs.add(s);
				}
			}
		}

		if (subs.isEmpty()) {
			return sb.toString();
		}
		sb.append('[');
		sb.append(StringUtils.join(subs, ","));
		sb.append(']');
		return sb.toString();
	}

	/**
	 * Count the number of bits specified in the resolution patterns
	 * 
	 * Totals the specificity of the instruction and context pattern blocks.
	 * @return the number of bits in the resulting patterns
	 * @see AssemblyPatternBlock#getSpecificity()
	 */
	public int getSpecificity() {
		return ins.getSpecificity() + ctx.getSpecificity();
	}

	/**
	 * Get an iterable over all the possible fillings of the instruction pattern given a context
	 * 
	 * This is meant to be used idiomatically, as in an enhanced for loop:
	 * 
	 * <pre>
	 * {@code
	 * for (byte[] ins : rcon.possibleInsVals(ctx)) {
	 *     System.out.println(format(ins));
	 * }
	 * }
	 * </pre>
	 * 
	 * This is similar to calling
	 * {@link #getInstruction()}.{@link AssemblyPatternBlock#possibleVals()}, <em>but</em> with
	 * forbidden patterns removed. A context is required so that only those forbidden patterns
	 * matching the given context are actually removed. This method should always be preferred to
	 * the sequence mentioned above, since {@link AssemblyPatternBlock#possibleVals()} on its own
	 * may yield bytes that do not produce the desired instruction. 
	 * 
	 * NOTE: The implementation is based on {@link AssemblyPatternBlock#possibleVals()}, so be
	 * aware that a single array is reused for each iterate. You should not retain a pointer to the
	 * array, but rather make a copy.
	 * 
	 * @param forCtx the context at the assembly address
	 * @return the iterable
	 */
	public Iterable<byte[]> possibleInsVals(AssemblyPatternBlock forCtx) {
		Predicate<byte[]> removeForbidden = (byte[] val) -> {
			for (AssemblyResolvedConstructor f : forbids) {
				// If the forbidden length is larger than us, we can ignore it
				if (f.getDefinedInstructionLength() > val.length) {
					continue;
				}
				// Check if the context matches, if not, we can let it pass
				if (null == f.getContext().combine(forCtx)) {
					continue;
				}
				// If the context matches, now check the instruction
				AssemblyPatternBlock i = f.getInstruction();
				AssemblyPatternBlock vi =
					AssemblyPatternBlock.fromBytes(ins.length() - val.length, val);
				if (null == i.combine(vi)) {
					continue;
				}
				return false;
			}
			return true;
		};
		return new Iterable<byte[]>() {
			@Override
			public Iterator<byte[]> iterator() {
				return IteratorUtils.filteredIterator(ins.possibleVals().iterator(),
					removeForbidden);
			}
		};
	}
}
