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
// This script illustrates one way to work with the WildSleighAssembler by searching for the first
// 10 instances of each encoding of a single predefined x86_64 instruction with a wildcard.
//
// This script assembles the instruction "XOR R13D,`Q1/R1(2|3)D`" where the second operand is a
// wildcard which we have constrained to be either R12D or R13D. Using the metadata from assembly
// we find all the unique encodings after discounting wildcard specific bits and search for each of
// these unique encodings in the binary. For performance / example reasons we only find the first
// 10 search results for each starting from currentAddress. For each result, we print the address
// of the hit and the value of the wildcard at that location.
//
// See documentation within the script for more detail on APIs. See "Help > Contents > Ghidra
// Functionality > Wildcard Assembler" for assembly wildcard syntax.
//
// See the "WildSleighAssemblerInfo" script for a simpler use of the WildSleighAssembler.
// @category Examples

import java.util.*;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.asm.wild.*;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class FindInstructionWithWildcard extends GhidraScript {

	@Override
	public void run() throws Exception {

		var instruction = askString("Instruction to search", """
				Instruction to search for with wildcard (example is for x86_64, adjust if you are \
				using a different architecture): \
				XOR R13D,`Q1/R1(2|3)D`""");
		var allValidResults = getAllResolvedPatterns(instruction);

		var encodings = getMapOfUniqueInstructionEncodings(allValidResults);

		searchMemoryForEncodings(encodings, allValidResults);
	}

	/**
	 * Use a {@link WildSleighAssembler} to assemble the given {@code wildcardedInstruction}
	 * 
	 * @param wildcardedInstruction
	 * @return All {@link WildAssemblyResolvedPatterns} produced from the given input (e.g. All
	 *         VALID results of assembling the given input)
	 */
	private List<WildAssemblyResolvedPatterns> getAllResolvedPatterns(
			String wildcardedInstruction) {
		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();

		SleighLanguage currentLanguage = (SleighLanguage) currentProgram.getLanguage();

		// Create a WildSleighAssembler that we'll use to assemble our wildcard-included
		// instruction
		WildSleighAssemblerBuilder assemblerBuilder =
			new WildSleighAssemblerBuilder(currentLanguage);
		WildSleighAssembler assembler =
			assemblerBuilder.getAssembler(new AssemblySelector(), currentProgram);

		// Parse a single line of assembly which includes a wildcard.
		Collection<AssemblyParseResult> parses = assembler.parseLine(wildcardedInstruction);

		// Remove all the AssemblyParseResults that represent parse errors
		List<AssemblyParseResult> allResults = parses.stream()
				.filter(p -> !p.isError())
				.toList();

		// Try to resolve each AssemblyParseResult at address 0 and collect all the results which
		// are valid
		Address addr0 = currentLanguage.getAddressFactory().getDefaultAddressSpace().getAddress(0);

		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = assembler.resolveTree(r, addr0);

			allValidResults.addAll(getValidResults(results));
		}
		return allValidResults;
	}

	/**
	 * Reduce the given {@code WildAssemblyResolvedPatterns} to a map keyed by unique instruction
	 * encodings WITHOUT specific wildcard values. Each key in this map corresponds to a set of
	 * {@code WildOperandInfo} options for the corresponding encoding.
	 * 
	 * @param allValidResolvedPatterns
	 * @return
	 */
	private Map<AssemblyPatternBlock, Set<WildOperandInfo>> getMapOfUniqueInstructionEncodings(
			List<WildAssemblyResolvedPatterns> allValidResolvedPatterns) {

		// Bail out early if we were not able to find any results (should only happen if the hard
		// coded instruction in this example script is changed)
		if (allValidResolvedPatterns.isEmpty()) {
			println("No assembly results for given assembly with wildcard!");
			return Map.of();
		}

		// 'allValidResolvedPatterns' has one entry for each encoding/wildcard value pair. We're
		// going to reduce that down to a map where each:
		// * Key is a single encoding of an instruction WITHOUT the wildcard operand bits specified
		// * Value is a set of WildOperandInfo instances containing each valid wildcard completion
		Map<AssemblyPatternBlock, Set<WildOperandInfo>> encodings =
			new HashMap<AssemblyPatternBlock, Set<WildOperandInfo>>();
		for (WildAssemblyResolvedPatterns x : allValidResolvedPatterns) {
			var y = new ReducedWildcardAssemblyResolvedPattern(x);
			var existing = encodings.get(y.maskedInstruction);
			if (existing == null) {
				existing = new HashSet<WildOperandInfo>();
			}
			existing.addAll(y.parent.getOperandInfo());
			encodings.put(y.maskedInstruction, existing);
		}
		return encodings;
	}

	/**
	 * This is a helper class which creates and holds an {@code AssemblyPatternBlock} for a given
	 * {@code WildAssemblyResolvedPatterns}. This created {@code AssemblyPatternBlock} does NOT have
	 * any bits specified that are part of a wildcarded operand. This is in contrast to the original
	 * {@code WildAssemblyResolvedPatterns} where those bits are specified to have the values that
	 * correspond to the {@code WildOperandInfo} values found in the
	 * {@code WildAssemblyResolvedPatterns}.
	 */
	static class ReducedWildcardAssemblyResolvedPattern {
		/**
		 * The original WildAssemblyResolvedPatterns that this is based on
		 */
		WildAssemblyResolvedPatterns parent;
		/**
		 * The portion of the instruction that is NOT any wildcarded operand
		 */
		AssemblyPatternBlock maskedInstruction;

		ReducedWildcardAssemblyResolvedPattern(WildAssemblyResolvedPatterns input) {
			parent = input;

			// Remove all the bits which correspond to wildcarded opcodes from the instruction save
			// the result as maskedInstruction
			var reducedInstruction = input.getInstruction();
			for (WildOperandInfo info : input.getOperandInfo()) {
				reducedInstruction = reducedInstruction.maskOut(info.location());
			}
			maskedInstruction = reducedInstruction;
		}

		/**
		 * Returns true of the given value shares the same {@code maskedInstruction} and wildcard(s)
		 * as this instance.
		 * 
		 * @param other Value to compare against
		 * @return True if both values share the same maskedInstruction and wildcard(s)
		 */
		boolean sameBaseEncoding(ReducedWildcardAssemblyResolvedPattern other) {
			if (!this.maskedInstruction.equals(other.maskedInstruction)) {
				return false;
			}

			// Loop over each WildOperandInfo in this to ensure that there is a matching one in
			// other which shares the same wildcard (name) and location. Remember that there might
			// be more than one wildcard in an instruction with the same name so we can't assume
			// there's not a match if a matching name doesn't have the same location.
			for (WildOperandInfo info : this.parent.getOperandInfo()) {
				var foundMatch = false;

				// Check all of other's WildOperandInfo
				for (WildOperandInfo otherInfo : other.parent.getOperandInfo()) {
					// Check if we have matching wildcards (names), expressions, and locations.
					// We're *NOT* checking choice here, as we expect those to be different.
					if (info.wildcard().equals(otherInfo.wildcard()) &&
						info.expression().equals(otherInfo.expression()) &&
						info.location().equals(otherInfo.location())) {
						foundMatch = true;
						break;
					}
				}

				if (!foundMatch) {
					// We were unable to find a wildcard that matched so we declare that these
					// encodings don't have the same base encoding
					return false;
				}
			}
			return true;
		}
	}

	/**
	 * Searches for at most 10 matches for each given encoding, starting at {@code currentAddress}
	 * and prints results to the console.
	 * <p>
	 * This searches encoding by encoding, restarting back at the start of memory for each.
	 * <p>
	 * Does not currently print wildcard information about the search results, but this could be
	 * added.
	 * 
	 * @param encodings Map of encodings to that encoding's possible WildOperandInfo values.
	 * @throws MemoryAccessException If we find bytes but can't read them
	 */
	private void searchMemoryForEncodings(
			Map<AssemblyPatternBlock, Set<WildOperandInfo>> encodings,
			List<WildAssemblyResolvedPatterns> allValidResolvedPatterns)
			throws MemoryAccessException {

		Memory memory = currentProgram.getMemory();

		for (var encoding : encodings.keySet()) {
			println("Searching for encoding: " + encoding.toString());

			// Start/restart back at currentAddress for each new encoding search
			var searchFromAddress = currentAddress;
			var matchCount = 0;

			// Stop if we run out of addresses or don't have a currentAddress
			while (searchFromAddress != null) {

				var matchAddress =
					memory.findBytes(searchFromAddress, encoding.getVals(), encoding.getMask(),
						getReusePreviousChoices(), monitor);
				if (matchAddress == null) {
					// No match found, go to next encoding
					break;
				}

				// Get the specific bytes found at this address and print match info
				var foundBytes = new byte[encoding.length()];
				memory.getBytes(matchAddress, foundBytes);
				printSearchHitInfo(matchAddress, foundBytes, allValidResolvedPatterns);

				// Continue to the next result (unless we've had 10 matches already)
				searchFromAddress = matchAddress.next();
				matchCount += 1;
				if (matchCount > 10) {
					println("Stopping after 10 matches!");
					break;
				}
			}
		}
	}

	/**
	 * Print information about a specific search hit to the console
	 * <p>
	 * NOTE: This is certainly not the highest performance way to do this, but it is reasonably
	 * simple and shows what is possible.
	 * 
	 * @param matchAddress The address where our search hit occurred
	 * @param matchData The bytes found at matchAddress. Must include the entire matching
	 *            instruction!
	 * @param allValidResolvedPatterns All resolved patterns which were searched from (used to find
	 *            wildcard information)
	 */
	private void printSearchHitInfo(Address matchAddress, byte[] matchData,
			List<WildAssemblyResolvedPatterns> allValidResolvedPatterns) {

		println("Hit at address: " + matchAddress.toString());

		// Check all the resolutions we were searching for and find the one which matches the found
		// bytes and use that resolution to determine what the wildcard values are for the given
		// hit.
		//
		// It'd likely be much faster to deduplicate similar WildAssemblyResolvedPatterns based on
		// their instruction with wildcards masked out (similar to what is done in
		// ReducedWildcardAssemblyResolvedPattern) and create a lookup table for wildcard values but
		// that's beyond this basic example script.
		for (WildAssemblyResolvedPatterns resolved : allValidResolvedPatterns) {
			var resolvedInstruction = resolved.getInstruction();
			if (resolvedInstruction.length() > matchData.length) {
				// It can't be this resolution because we were not given enough bytes of
				// matchData
				continue;
			}

			// Mask out the matchData with the mask of our candidate resolvedInstruction and
			// see if
			// the results match. If they do, then this is the WildAssemblyResolvedPatterns
			var matchMasked = resolvedInstruction.getMaskedValue(matchData);
			if (matchMasked.equals(resolvedInstruction)) {
				for (WildOperandInfo info : resolved.getOperandInfo()) {
					println("Wildcard `" + info.wildcard() + "` = " + info.choice().toString());
				}
				return;
			}
			println("Failed to find search hit info");
		}

	}

	/**
	 * Return all items from {@code results} which are instances of
	 * {@link WildAssemblyResolvedPatterns}
	 * 
	 * @param results The results to return {@link WildAssemblyResolvePatterns} from
	 * @return All {@link WildAssemblyResolvedPatterns} which were found in the input
	 */
	private List<WildAssemblyResolvedPatterns> getValidResults(AssemblyResolutionResults results) {
		var out = new ArrayList<WildAssemblyResolvedPatterns>();
		for (AssemblyResolution result : results) {
			if (result instanceof WildAssemblyResolvedPatterns resolvedPatterns) {
				out.add(resolvedPatterns);
			}
		}
		return out;
	}

}
