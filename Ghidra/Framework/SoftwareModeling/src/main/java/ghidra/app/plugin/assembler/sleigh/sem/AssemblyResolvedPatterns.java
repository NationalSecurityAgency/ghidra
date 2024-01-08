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

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.RecursiveDescentSolver;
import ghidra.app.plugin.processors.sleigh.*;

public interface AssemblyResolvedPatterns extends AssemblyResolution {

	/**
	 * Get the instruction block
	 * 
	 * @return the instruction block
	 */
	AssemblyPatternBlock getInstruction();

	/**
	 * Get the context block
	 * 
	 * @return the context block
	 */
	AssemblyPatternBlock getContext();

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
	int getInstructionLength();

	/**
	 * Get the length of the instruction encoding, excluding trailing undefined bytes
	 * 
	 * <p>
	 * <b>NOTE:</b> this DOES include the offset<br>
	 * <b>NOTE:</b> this DOES NOT include pending backfills
	 * 
	 * @return the length of the defined bytes in the instruction block
	 */
	int getDefinedInstructionLength();

	/**
	 * Get the backfill records for this resolution, if any
	 * 
	 * @return the backfills
	 */
	Collection<AssemblyResolvedBackfill> getBackfills();

	/**
	 * Check if this resolution has pending backfills to apply
	 * 
	 * @return true if there are backfills
	 */
	boolean hasBackfills();

	/**
	 * Get the forbidden patterns for this resolution
	 * 
	 * <p>
	 * These represent patterns included in the current resolution that would actually get matched
	 * by a more specific constructor somewhere in the resolved tree, and thus are subtracted.
	 * 
	 * @return the forbidden patterns
	 */
	Collection<AssemblyResolvedPatterns> getForbids();

	/**
	 * Decode a portion of the instruction block
	 * 
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the read masked value
	 * @see AssemblyPatternBlock#readBytes(int, int)
	 */
	MaskedLong readInstruction(int byteStart, int size);

	/**
	 * Decode a portion of the context block
	 * 
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the read masked value
	 * @see AssemblyPatternBlock#readBytes(int, int)
	 */
	MaskedLong readContext(int start, int len);

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
	MaskedLong readContextOp(ContextOp cop);

	/**
	 * Check if this and another resolution have equal encodings
	 * 
	 * <p>
	 * This is like {@link #equals(Object)}, but it ignores backfill records and forbidden patterns.
	 * 
	 * @param that the other resolution
	 * @return true if both have equal encodings
	 */
	boolean bitsEqual(AssemblyResolvedPatterns that);

	/**
	 * Check if this assembled construct state is the same as the given dis-assembled construct
	 * state.
	 */
	boolean equivalentConstructState(ConstructState state);

	@Override
	AssemblyResolvedPatterns shift(int shamt);

	/**
	 * Create a copy of this resolution with a new description
	 * 
	 * @param desc the new description
	 * @return the copy
	 */
	AssemblyResolvedPatterns withDescription(String description);

	/**
	 * Create a copy of this resolution with a sibling to the right
	 * 
	 * <p>
	 * The right sibling is a mechanism for collecting children of a parent yet to be created. See
	 * {@link #parent(String, int)}.
	 * 
	 * @param right the right sibling
	 * @return the new resolution
	 */
	AssemblyResolvedPatterns withRight(AssemblyResolution right);

	/**
	 * Create a copy of this resolution with a replaced constructor
	 * 
	 * @param cons the new constructor
	 * @return the copy
	 */
	AssemblyResolvedPatterns withConstructor(Constructor cons);

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
	AssemblyResolvedPatterns combine(AssemblyResolvedPatterns pat);

	/**
	 * Combine the given backfill record into this resolution
	 * 
	 * @param bf the backfill record
	 * @return the result
	 */
	AssemblyResolvedPatterns combine(AssemblyResolvedBackfill bf);

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
	AssemblyResolvedPatterns combineLessBackfill(AssemblyResolvedPatterns that,
			AssemblyResolvedBackfill bf);

	@Override
	AssemblyResolvedPatterns parent(String description, int opCount);

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
	AssemblyResolution backfill(RecursiveDescentSolver solver, Map<String, Long> vals);

	/**
	 * Check if the current encoding is forbidden by one of the attached patterns
	 * 
	 * <p>
	 * The pattern becomes forbidden if this encoding's known bits are an overset of any forbidden
	 * pattern's known bits.
	 * 
	 * @return false if the pattern is forbidden (and thus in error), true if permitted
	 */
	AssemblyResolution checkNotForbidden();

	/**
	 * Generate a new nop right this resolution to its right.
	 * 
	 * <p>
	 * Alternatively phrased: append a nop to the left of this list of siblings, returning the new
	 * head.
	 * 
	 * @return the nop resolution
	 */
	AssemblyResolvedPatterns nopLeftSibling();

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
	AssemblyResolvedPatterns solveContextChangesForForbids(AssemblyConstructorSemantic sem,
			Map<String, Long> vals);

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
	Iterable<byte[]> possibleInsVals(AssemblyPatternBlock forCtx);

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
	String dumpConstructorTree();

	/**
	 * Truncate (unshift) the resolved instruction pattern from the left
	 * 
	 * <b>NOTE:</b> This drops all backfill and forbidden pattern records, since this method is
	 * typically used to read token fields rather than passed around for resolution.
	 * 
	 * @param amt the number of bytes to remove from the left
	 * @return the result
	 */
	AssemblyResolvedPatterns truncate(int shamt);

	/**
	 * Create a new resolution from this one with the given forbidden patterns recorded
	 * 
	 * @param more the additional forbidden patterns to record
	 * @return the new resolution
	 */
	AssemblyResolvedPatterns withForbids(Set<AssemblyResolvedPatterns> more);

	/**
	 * Set all bits read by a given context operation to unknown
	 * 
	 * @param cop the context operation
	 * @return the result
	 * @see AssemblyPatternBlock#maskOut(ContextOp)
	 */
	AssemblyResolvedPatterns maskOut(ContextOp cop);

	/**
	 * Encode the given value into the context block as specified by an operation
	 * 
	 * <p>
	 * This is the forward (as in disassembly) direction of applying context operations. The pattern
	 * expression is evaluated, and the result is written as specified.
	 * 
	 * @param cop the context operation specifying the location of the value to encode
	 * @param val the masked value to encode
	 * @return the result
	 */
	AssemblyResolvedPatterns writeContextOp(ContextOp cop, MaskedLong val);
}
