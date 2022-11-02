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
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.Predicate;
import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.symbol.OperandSymbol;
import ghidra.app.plugin.processors.sleigh.symbol.SubtableSymbol;

/**
 * A {@link AssemblyResolution} indicating successful application of a constructor
 * 
 * <p>
 * This is almost analogous to {@link ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern
 * DisjointPattern}, in that is joins an instruction {@link AssemblyPatternBlock} with a
 * corresponding context {@link AssemblyPatternBlock}. However, this object is mutable, and it
 * collects backfill records, as well as forbidden patterns.
 * 
 * <p>
 * When the applied constructor is from the "instruction" subtable, this represents a fully-
 * constructed instruction with required context. All backfill records ought to be resolved and
 * applied before the final result is given to the user, i.e., passed into the
 * {@link AssemblySelector}. If at any time during the resolution or backfill process, the result
 * becomes confined to one of the forbidden patterns, it must be dropped, since the encoding will
 * actually invoke a more specific SLEIGH constructor.
 */
public class AssemblyResolvedPatterns extends AssemblyResolution {
	protected static final String INS = "ins:";
	protected static final String CTX = "ctx:";
	protected static final String SEP = ",";

	protected final Constructor cons;
	protected final AssemblyPatternBlock ins;
	protected final AssemblyPatternBlock ctx;

	protected final Set<AssemblyResolvedBackfill> backfills;
	protected final Set<AssemblyResolvedPatterns> forbids;

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
		if (!(obj instanceof AssemblyResolvedPatterns)) {
			return false;
		}
		AssemblyResolvedPatterns that = (AssemblyResolvedPatterns) obj;
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
	 * @see AssemblyResolution#resolved(AssemblyPatternBlock, AssemblyPatternBlock, String, Constructor, List, AssemblyResolution)
	 */
	AssemblyResolvedPatterns(String description, Constructor cons,
			List<? extends AssemblyResolution> children, AssemblyResolution right,
			AssemblyPatternBlock ins, AssemblyPatternBlock ctx,
			Set<AssemblyResolvedBackfill> backfills, Set<AssemblyResolvedPatterns> forbids) {
		super(description, children, right);
		this.cons = cons;
		this.ins = ins;
		this.ctx = ctx;
		this.backfills = backfills == null ? Set.of() : backfills;
		this.forbids = forbids == null ? Set.of() : forbids;
	}

	/**
	 * Build a new successful SLEIGH constructor resolution from a string representation
	 * 
	 * <p>
	 * This was used primarily in testing, to specify expected results.
	 * 
	 * @param str the string representation: "{@code ins:[pattern],ctx:[pattern]}"
	 * @see ghidra.util.NumericUtilities#convertHexStringToMaskedValue(AtomicLong, AtomicLong,
	 *      String, int, int, String) NumericUtilities.convertHexStringToMaskedValue(AtomicLong,
	 *      AtomicLong, String, int, int, String)
	 * @param description a description of the resolution
	 * @param children any children involved in the resolution
	 * @return the decoded resolution
	 */
	public static AssemblyResolvedPatterns fromString(String str, String description,
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
			description, null, children, null);
	}

	@Override
	public AssemblyResolvedPatterns shift(int amt) {
		if (amt == 0) {
			return this;
		}
		AssemblyPatternBlock newIns = this.ins.shift(amt);

		// Also shift the attached backfills and forbidden patterns
		Set<AssemblyResolvedBackfill> newBackfills = new HashSet<>();
		for (AssemblyResolvedBackfill bf : this.backfills) {
			newBackfills.add(bf.shift(amt));
		}

		Set<AssemblyResolvedPatterns> newForbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : this.forbids) {
			newForbids.add(f.shift(amt));
		}
		return new AssemblyResolvedPatterns(description, cons, children, right, newIns, ctx,
			Collections.unmodifiableSet(newBackfills), Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Truncate (unshift) the resolved instruction pattern from the left
	 * 
	 * <b>NOTE:</b> This drops all backfill and forbidden pattern records, since this method is
	 * typically used to read token fields rather than passed around for resolution.
	 * 
	 * @param amt the number of bytes to remove from the left
	 * @return the result
	 */
	public AssemblyResolvedPatterns truncate(int amt) {
		if (amt == 0) {
			return this;
		}
		AssemblyPatternBlock newIns = this.ins.truncate(amt);

		return new AssemblyResolvedPatterns("Truncated: " + description, cons, null, right,
			newIns, ctx,
			null, null);
	}

	/**
	 * Check if the current encoding is forbidden by one of the attached patterns
	 * 
	 * <p>
	 * The pattern becomes forbidden if this encoding's known bits are an overset of any forbidden
	 * pattern's known bits.
	 * 
	 * @return false if the pattern is forbidden (and thus in error), true if permitted
	 */
	public AssemblyResolution checkNotForbidden() {
		Set<AssemblyResolvedPatterns> newForbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : this.forbids) {
			AssemblyResolvedPatterns check = this.combine(f);
			if (null == check) {
				continue;
			}
			newForbids.add(f);
			if (check.bitsEqual(this)) {
				// The result would be disassembled by a more-specific constructor.
				return AssemblyResolution.error("The result is forbidden by " + f, this);
			}
		}
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx,
			backfills, Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Check if this and another resolution have equal encodings
	 * 
	 * <p>
	 * This is like {@link #equals(Object)}, but it ignores backfill records and forbidden patterns.
	 * 
	 * @param that the other resolution
	 * @return true if both have equal encodings
	 */
	protected boolean bitsEqual(AssemblyResolvedPatterns that) {
		return this.ins.equals(that.ins) && this.ctx.equals(that.ctx);
	}

	/**
	 * Combine the encodings and backfills of the given resolution into this one
	 * 
	 * <p>
	 * This combines corresponding pattern blocks (assuming they agree), collects backfill records,
	 * and collects forbidden patterns.
	 * 
	 * @param that the other resolution
	 * @return the result if successful, or null
	 */
	public AssemblyResolvedPatterns combine(AssemblyResolvedPatterns that) {
		// Not really a backfill, but I would like to re-use code
		return combineLessBackfill(that, null);
	}

	/**
	 * Combine a backfill result
	 * 
	 * <p>
	 * When a backfill is successful, the result should be combined with the owning resolution. In
	 * addition, for bookkeeping's sake, the resolved record should be removed from the list of
	 * backfills.
	 * 
	 * @param that the result from backfilling
	 * @param bf the resolved backfilled record
	 * @return the result if successful, or null
	 */
	protected AssemblyResolvedPatterns combineLessBackfill(AssemblyResolvedPatterns that,
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
		Set<AssemblyResolvedPatterns> newForbids = new HashSet<>(this.forbids);
		newForbids.addAll(that.forbids);
		return new AssemblyResolvedPatterns(description, cons, children, right, newIns, newCtx,
			Collections.unmodifiableSet(newBackfills), Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Combine the given backfill record into this resolution
	 * 
	 * @param bf the backfill record
	 * @return the result
	 */
	public AssemblyResolvedPatterns combine(AssemblyResolvedBackfill bf) {
		Set<AssemblyResolvedBackfill> newBackfills = new HashSet<>(this.backfills);
		newBackfills.add(bf);
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx,
			Collections.unmodifiableSet(newBackfills), forbids);
	}

	/**
	 * Create a new resolution from this one with the given forbidden patterns recorded
	 * 
	 * @param more the additional forbidden patterns to record
	 * @return the new resolution
	 */
	public AssemblyResolvedPatterns withForbids(Set<AssemblyResolvedPatterns> more) {
		Set<AssemblyResolvedPatterns> combForbids = new HashSet<>(this.forbids);
		combForbids.addAll(more);
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx,
			backfills, Collections.unmodifiableSet(more));
	}

	/**
	 * Create a copy of this resolution with a new description
	 * 
	 * @param desc the new description
	 * @return the copy
	 */
	public AssemblyResolvedPatterns withDescription(String desc) {
		return new AssemblyResolvedPatterns(desc, cons, children, right, ins, ctx, backfills,
			forbids);
	}

	/**
	 * Create a copy of this resolution with a replaced constructor
	 * 
	 * @param cons the new constructor
	 * @return the copy
	 */
	public AssemblyResolvedPatterns withConstructor(Constructor cons) {
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx,
			backfills,
			forbids);
	}

	/**
	 * Encode the given value into the context block as specified by an operation
	 * 
	 * @param cop the context operation specifying the location of the value to encode
	 * @param val the masked value to encode
	 * @return the result
	 * 
	 *         This is the forward (as in disassembly) direction of applying context operations. The
	 *         pattern expression is evaluated, and the result is written as specified.
	 */
	public AssemblyResolvedPatterns writeContextOp(ContextOp cop, MaskedLong val) {
		AssemblyPatternBlock newCtx = this.ctx.writeContextOp(cop, val);
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, newCtx,
			backfills, forbids);
	}

	/**
	 * Decode the value from the context located where the given context operation would write
	 * 
	 * <p>
	 * This is used to read the value from the left-hand-side "variable" of a context operation. It
	 * seems backward, because it is. When assembling, the right-hand-side expression of a context
	 * operation must be solved. This means the "variable" is known from the context(s) of the
	 * resolved children constructors. The value read is then used as the goal in solving the
	 * expression.
	 * 
	 * @param cop the context operation whose "variable" to read.
	 * @return the masked result.
	 */
	public MaskedLong readContextOp(ContextOp cop) {
		return ctx.readContextOp(cop);
	}

	/**
	 * Duplicate this resolution, with additional description text appended
	 * 
	 * @param append the text to append
	 * @return the duplicate NOTE: An additional separator {@code ": "} is inserted
	 */
	public AssemblyResolvedPatterns copyAppendDescription(String append) {
		AssemblyResolvedPatterns cp = new AssemblyResolvedPatterns(
			description + ": " + append, cons, children, right, ins.copy(), ctx.copy(), backfills,
			forbids);
		return cp;
	}

	@Override
	public AssemblyResolvedPatterns withRight(AssemblyResolution right) {
		AssemblyResolvedPatterns cp = new AssemblyResolvedPatterns(description, cons,
			children, right, ins.copy(), ctx.copy(), backfills, forbids);
		return cp;
	}

	public AssemblyResolvedPatterns nopLeftSibling() {
		return new AssemblyResolvedPatterns("nop-left", null, null, this, ins.copy(),
			ctx.copy(), backfills, forbids);
	}

	@Override
	public AssemblyResolvedPatterns parent(String description, int opCount) {
		List<AssemblyResolution> allRight = getAllRight();
		AssemblyResolvedPatterns cp = new AssemblyResolvedPatterns(description, cons,
			allRight.subList(0, opCount), allRight.get(opCount), ins, ctx, backfills, forbids);
		return cp;
	}

	/**
	 * Set all bits read by a given context operation to unknown
	 * 
	 * @param cop the context operation
	 * @return the result
	 * @see AssemblyPatternBlock#maskOut(ContextOp)
	 */
	public AssemblyResolvedPatterns maskOut(ContextOp cop) {
		AssemblyPatternBlock newCtx = this.ctx.maskOut(cop);
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, newCtx,
			backfills, forbids);
	}

	/**
	 * Apply as many backfill records as possible
	 * 
	 * <p>
	 * Each backfill record is resolved in turn, if the record cannot be resolved, it remains
	 * listed. If the record can be resolved, but it conflicts, an error record is returned. Each
	 * time a record is resolved and combined successfully, all remaining records are tried again.
	 * The result is the combined resolved backfills, with only the unresolved backfill records
	 * listed.
	 * 
	 * @param solver the solver, usually the same as the original attempt to solve.
	 * @param vals the values.
	 * @return the result, or an error.
	 */
	public AssemblyResolution backfill(RecursiveDescentSolver solver, Map<String, Long> vals) {
		if (!hasBackfills()) {
			return this;
		}

		AssemblyResolvedPatterns res = this;
		loop: while (true) {
			for (AssemblyResolvedBackfill bf : res.backfills) {
				AssemblyResolution ar = bf.solve(solver, vals, this);
				if (ar.isError()) {
					continue;
				}
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
				AssemblyResolvedPatterns check = res.combineLessBackfill(rc, bf);
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
	 * 
	 * @return true if there are backfills
	 */
	public boolean hasBackfills() {
		return !backfills.isEmpty();
	}

	/**
	 * Check if this resolution includes forbidden patterns
	 * 
	 * @return true if there are forbidden patterns
	 */
	private boolean hasForbids() {
		return !forbids.isEmpty();
	}

	/**
	 * Solve and apply context changes in reverse to forbidden patterns
	 * 
	 * <p>
	 * To avoid circumstances where a context change during disassembly would invoke a more specific
	 * sub-constructor than was used to assembly the instruction, we must solve the forbidden
	 * patterns in tandem with the overall resolution. If the context of any forbidden pattern
	 * cannot be solved, we simply drop the forbidden pattern -- the lack of a solution implies
	 * there is no way the context change could produce the forbidden pattern.
	 * 
	 * @param sem the constructor whose context changes to solve
	 * @param vals any defined symbols
	 * @return the result
	 * @see AssemblyConstructorSemantic#solveContextChanges(AssemblyResolvedPatterns, Map)
	 */
	public AssemblyResolvedPatterns solveContextChangesForForbids(
			AssemblyConstructorSemantic sem, Map<String, Long> vals) {
		if (!hasForbids()) {
			return this;
		}
		Set<AssemblyResolvedPatterns> newForbids = new HashSet<>();
		for (AssemblyResolvedPatterns f : this.forbids) {
			AssemblyResolution t = sem.solveContextChanges(f, vals);
			if (!(t instanceof AssemblyResolvedPatterns)) {
				// Can't be solved, so it can be dropped
				continue;
			}
			newForbids.add((AssemblyResolvedPatterns) t);
		}
		return new AssemblyResolvedPatterns(description, cons, children, right, ins, ctx,
			backfills, Collections.unmodifiableSet(newForbids));
	}

	/**
	 * Get the length of the instruction encoding
	 * 
	 * <p>
	 * This is used to ensure each operand is encoded at the correct offset
	 * 
	 * <p>
	 * <b>NOTE:</b> this DOES include the offset<br>
	 * <b>NOTE:</b> this DOES include pending backfills
	 * 
	 * @return the length of the instruction block
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
	 * 
	 * <p>
	 * <b>NOTE:</b> this DOES include the offset<br>
	 * <b>NOTE:</b> this DOES NOT include pending backfills
	 * 
	 * @return the length of the defined bytes in the instruction block
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
	 * 
	 * @return the instruction block
	 */
	public AssemblyPatternBlock getInstruction() {
		return ins;
	}

	/**
	 * Get the context block
	 * 
	 * @return the context block
	 */
	public AssemblyPatternBlock getContext() {
		return ctx;
	}

	/**
	 * Decode a portion of the instruction block
	 * 
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
	 * 
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
		for (AssemblyResolvedPatterns f : forbids) {
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
	 * <p>
	 * This includes braces to describe the tree structure
	 * 
	 * @see ConstructState#dumpConstructorTree()
	 * @return the constructor tree
	 */
	public String dumpConstructorTree() {
		StringBuilder sb = new StringBuilder();
		if (cons == null) {
			return null;
		}
		sb.append(cons.getSourceFile() + ":" + cons.getLineno());

		if (children == null) {
			return sb.toString();
		}

		List<String> subs = new ArrayList<>();
		for (AssemblyResolution c : children) {
			if (c instanceof AssemblyResolvedPatterns) {
				AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) c;
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
	 * <p>
	 * Totals the specificity of the instruction and context pattern blocks.
	 * 
	 * @return the number of bits in the resulting patterns
	 * @see AssemblyPatternBlock#getSpecificity()
	 */
	public int getSpecificity() {
		return ins.getSpecificity() + ctx.getSpecificity();
	}

	/**
	 * Get an iterable over all the possible fillings of the instruction pattern given a context
	 * 
	 * <p>
	 * This is meant to be used idiomatically, as in an enhanced for loop:
	 * 
	 * <pre>
	 * for (byte[] ins : rcon.possibleInsVals(ctx)) {
	 * 	System.out.println(format(ins));
	 * }
	 * </pre>
	 * 
	 * <p>
	 * This is similar to calling
	 * {@link #getInstruction()}.{@link AssemblyPatternBlock#possibleVals()}, <em>but</em> with
	 * forbidden patterns removed. A context is required so that only those forbidden patterns
	 * matching the given context are actually removed. This method should always be preferred to
	 * the sequence mentioned above, since {@link AssemblyPatternBlock#possibleVals()} on its own
	 * may yield bytes that do not produce the desired instruction.
	 * 
	 * <p>
	 * <b>NOTE:</b> The implementation is based on {@link AssemblyPatternBlock#possibleVals()}, so
	 * be aware that a single array is reused for each iterate. You should not retain a pointer to
	 * the array, but rather make a copy.
	 * 
	 * @param forCtx the context at the assembly address
	 * @return the iterable
	 */
	public Iterable<byte[]> possibleInsVals(AssemblyPatternBlock forCtx) {
		AssemblyPatternBlock ctxCompat = ctx.combine(forCtx);
		if (ctxCompat == null) {
			return List.of();
		}
		Predicate<byte[]> removeForbidden = (byte[] val) -> {
			for (AssemblyResolvedPatterns f : forbids) {
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

	protected static int getOpIndex(String piece) {
		if (piece.charAt(0) != '\n') {
			return -1;
		}
		return piece.charAt(1) - 'A';
	}

	/**
	 * If the construct state is a {@code ^instruction} or other purely-recursive constructor, get
	 * its single child.
	 * 
	 * @param state the parent state
	 * @return the child state if recursive, or null
	 */
	protected static ConstructState getPureRecursion(ConstructState state) {
		// NB. There can be other operands, but only one can be printed
		// Furthermore, nothing else can be printed, whether an operand or not
		List<String> pieces = state.getConstructor().getPrintPieces();
		if (pieces.size() != 1) {
			return null;
		}
		int opIdx = getOpIndex(pieces.get(0));
		if (opIdx < 0) {
			return null;
		}
		ConstructState sub = state.getSubState(opIdx);
		if (sub == null || sub.getConstructor() == null ||
			sub.getConstructor().getParent() != state.getConstructor().getParent()) {
			// not recursive
			return null;
		}
		return sub;
	}

	public boolean equivalentConstructState(ConstructState state) {
		ConstructState rec = getPureRecursion(state);
		if (rec != null) {
			if (state.getConstructor() == cons) {
				assert children.size() == 1;
				AssemblyResolvedPatterns recRes = (AssemblyResolvedPatterns) children.get(0);
				return recRes.equivalentConstructState(rec);
			}
			return equivalentConstructState(rec);
		}
		if (state.getConstructor() != cons) {
			return false;
		}
		int opCount = cons.getNumOperands();
		for (int opIdx = 0; opIdx < opCount; opIdx++) {
			OperandSymbol opSym = cons.getOperand(opIdx);
			Set<Integer> printed =
				Arrays.stream(cons.getOpsPrintOrder()).boxed().collect(Collectors.toSet());
			if (!(opSym.getDefiningSymbol() instanceof SubtableSymbol)) {
				AssemblyTreeResolver.DBG.println("Operand " + opSym + " is not a sub-table");
				continue;
			}
			if (!printed.contains(opIdx)) {
				AssemblyTreeResolver.DBG.println("Operand " + opSym + " is hidden");
				continue;
			}
			AssemblyResolvedPatterns child = (AssemblyResolvedPatterns) children.get(opIdx);
			ConstructState subState = state.getSubState(opIdx);
			if (!child.equivalentConstructState(subState)) {
				return false;
			}
		}
		return true;
	}
}
