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
package ghidra.app.plugin.assembler;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.assembler.sleigh.util.SleighUtil;

/**
 * Provides a mechanism for pruning and selecting binary assembled instructions from the results
 * of parsing textual assembly instructions. There are two opportunities: After parsing, but before
 * semantic resolution, and after resolution. In the first opportunity, filtering is optional ---
 * the user may discard any or all parse trees. The second is required, since only one instruction
 * may be placed at the desired address --- the user must select one instruction among the many
 * results, and if a mask is present, decide on a value for the omitted bits.
 * 
 * Extensions of this class are also suitable for collecting diagnostic information about attempted
 * assemblies. For example, an implementation may employ the syntax errors in order to produce
 * code completion suggestions in a GUI.
 */
public class AssemblySelector {
	protected Set<AssemblyParseResult> syntaxErrors = new TreeSet<>();
	protected Set<AssemblyResolvedError> semanticErrors = new TreeSet<>();

	/**
	 * A comparator on instruction length (shortest first), then bits lexicographically
	 */
	protected Comparator<AssemblyResolvedConstructor> compareBySizeThenBits = (a, b) -> {
		int result;
		result = a.getInstructionLength() - b.getInstructionLength();
		if (result != 0) {
			return result;
		}

		result =
			SleighUtil.compareArrays(a.getInstruction().getVals(), b.getInstruction().getVals());
		if (result != 0) {
			return result;
		}
		return 0;
	};

	/**
	 * Filter a collection of parse trees.
	 * 
	 * Generally, the assembly resolver considers every possible parsing of an assembly
	 * instruction. If, for some reason, the user wishes to ignore certain trees (perhaps for
	 * efficiency, or perhaps because a certain form of instruction is desired), entire parse
	 * trees may be pruned here.
	 * 
	 * It's possible that no trees pass the filter. In this case, this method ought to throw an
	 * {@link AssemblySyntaxException}. Another option is to pass the erroneous result on for semantic
	 * analysis, in which case, the error is simply copied into an erroneous semantic result.
	 * Depending on preferences, this may simplify the overall filtering and error-handling logic.
	 * 
	 * By default, no filtering is applied. If all the trees produce syntax errors, an exception is
	 * thrown.
	 * 
	 * @param parse the collection of parse results (errors and trees).
	 * @return the filtered collection, optionally in-place.
	 * @throws AssemblySyntaxException if the selector wishes to forward one or more syntax errors
	 */
	public Collection<AssemblyParseResult> filterParse(Collection<AssemblyParseResult> parse)
			throws AssemblySyntaxException {
		boolean gotOne = false;
		for (AssemblyParseResult pr : parse) {
			if (pr.isError()) {
				syntaxErrors.add(pr);
			}
			else {
				gotOne = true;
			}
		}
		if (!gotOne) {
			throw new AssemblySyntaxException(syntaxErrors);
		}
		return parse;
	}

	/**
	 * Select an instruction from the possible results.
	 * 
	 * Must select precisely one resolved constructor from the results given back by the assembly
	 * resolver. Precisely one. That means the mask of the returned result must consist of all 1s.
	 * Also, if no selection is suitable, an exception must be thrown.
	 * 
	 * By default, this method selects the shortest instruction that is compatible with the given
	 * context and takes 0 for bits that fall outside the mask. If all possible resolutions produce
	 * errors, an exception is thrown.
	 * 
	 * @param rr the collection of resolved constructors
	 * @param ctx the applicable context.
	 * @return a single resolved constructor with a full instruction mask.
	 * @throws AssemblySemanticException 
	 */
	public AssemblyResolvedConstructor select(AssemblyResolutionResults rr,
			AssemblyPatternBlock ctx) throws AssemblySemanticException {
		List<AssemblyResolvedConstructor> sorted = new ArrayList<>();
		// Select only non-erroneous results whose contexts are compatible.
		for (AssemblyResolution ar : rr) {
			if (ar.isError()) {
				semanticErrors.add((AssemblyResolvedError) ar);
				continue;
			}
			AssemblyResolvedConstructor rc = (AssemblyResolvedConstructor) ar;
			sorted.add(rc);
		}
		if (sorted.isEmpty()) {
			throw new AssemblySemanticException(semanticErrors);
		}
		// Sort them
		sorted.sort(compareBySizeThenBits);

		// Pick just the first
		AssemblyResolvedConstructor res = sorted.get(0);
		// Just set the mask to ffs (effectively choosing 0 for the omitted bits)
		return AssemblyResolution.resolved(res.getInstruction().fillMask(), res.getContext(),
			"Selected", null);
	}
}
