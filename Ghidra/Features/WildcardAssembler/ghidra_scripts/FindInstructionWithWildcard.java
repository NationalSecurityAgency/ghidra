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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.asm.wild.WildOperandInfo;
import ghidra.asm.wild.WildSleighAssembler;
import ghidra.asm.wild.WildSleighAssemblerBuilder;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;

public class FindInstructionWithWildcard extends GhidraScript {

	public void run() throws Exception {

		// The wildcard here specifies that the second operand of this instruction is
		// either "R12D" or "R13D". The instruction and/or wildcard here can be modified
		// to an instruction found in your x86_64 binary, or patch your binary to have
		// the bytes "0x45 0x31 0xed" somewhere.
		var allValidResults = getAllResolvedPatterns("XOR R13D,`Q1/R1(2|3)D`");

		var encodings = getMapOfUniqueInstructionEncodings(allValidResults);

		searchMemoryForEncodings(encodings, allValidResults);
	}

	/**
	 * Use an x86_64 WildSleighAssembler to assemble the given {@code wildcardedInstruction}
	 * 
	 * @param wildcardedInstruction
	 * @return All WildAssemblyResolvedPatterns produced from the given input (e.g. All VALID
	 *         results of assembling the given input)
	 */
	private ArrayList<WildAssemblyResolvedPatterns> getAllResolvedPatterns(
			String wildcardedInstruction) {
		var allValidResults = new ArrayList<WildAssemblyResolvedPatterns>();

		// Get our current program or build a new program if our current binary isn't x86_64
		Program baseProgram = currentProgram;
		if (!baseProgram.getLanguageCompilerSpecPair().languageID.getIdAsString()
				.equals("x86:LE:64:default")) {
			println(
				"WARNING: Current program is not 'x86:LE:64:default' so using a builder instead!");

			ProgramBuilder baseProgramBuilder;
			try {
				baseProgramBuilder = new ProgramBuilder("x86_64_test", "x86:LE:64:default");
			}
			catch (Exception e) {
				println(
					"Couldn't create ProgramBuilder with hardcoded languageName! Something is very wrong!");
				e.printStackTrace();
				return allValidResults;
			}

			baseProgram = baseProgramBuilder.getProgram();
		}

		SleighLanguage x8664Language = (SleighLanguage) baseProgram.getLanguage();

		// Create a WildSleighAssembler that we'll use to assemble our wildcard-included instruction
		WildSleighAssemblerBuilder builderX8664 = new WildSleighAssemblerBuilder(x8664Language);
		WildSleighAssembler asmX8664 =
			builderX8664.getAssembler(new AssemblySelector(), baseProgram);

		// Parse a single line of assembly which includes a wildcard.
		Collection<AssemblyParseResult> parses = asmX8664.parseLine(wildcardedInstruction);

		// Remove all the AssemblyParseResults that represent parse errors
		AssemblyParseResult[] allResults = parses.stream()
				.filter(p -> !p.isError())
				.toArray(AssemblyParseResult[]::new);

		// Try to resolve each AssemblyParseResult at address 0 and collect all the
		// results which are valid
		Address addr0 = x8664Language.getAddressFactory().getDefaultAddressSpace().getAddress(0);

		for (AssemblyParseResult r : allResults) {
			AssemblyResolutionResults results = asmX8664.resolveTree(r, addr0);

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
	private HashMap<AssemblyPatternBlock, HashSet<WildOperandInfo>> getMapOfUniqueInstructionEncodings(
			ArrayList<WildAssemblyResolvedPatterns> allValidResolvedPatterns) {

		// Bail out early if we were not able to find any results (should only happen if the hard
		// coded instruction in this example script is changed)
		if (allValidResolvedPatterns.size() < 1) {
			println("No assembly results for given assembly with wildcard!");
			return new HashMap<AssemblyPatternBlock, HashSet<WildOperandInfo>>();
		}

		// 'allValidResolvedPatterns' has one entry for each encoding/wildcard value pair. We're
		// going to reduce that down to a map where each:
		// * Key is a single encoding of an instruction WITHOUT the wildcard operand
		// bits specified
		// * Value is a set of WildOperandInfo instances containing each valid wildcard
		// completion
		var encodings = new HashMap<AssemblyPatternBlock, HashSet<WildOperandInfo>>();
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
	class ReducedWildcardAssemblyResolvedPattern {
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

			// Remove all the bits which correspond to wildcarded opcodes from the instruction and
			// save the result as maskedInstruction
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
		 * @param other
		 *            Value to compare against
		 * @return True if both values share the same maskedInstruction and wildcard(s)
		 */
		boolean sameBaseEncoding(ReducedWildcardAssemblyResolvedPattern other) {
			if (this.maskedInstruction.compareTo(other.maskedInstruction) != 0) {
				return false;
			}

			for (WildOperandInfo info : this.parent.getOperandInfo()) {
				var foundMatch = false;
				for (WildOperandInfo otherInfo : other.parent.getOperandInfo()) {
					if (info.wildcard().equals(otherInfo.wildcard())) {
						if (!info.equals(otherInfo)) {
							return false;
						}
						foundMatch = true;
						break;
					}
				}
				if (!foundMatch) {
					return false;
				}
			}
			return true;
		}
	}

	/**
	 * Searches for at most 10 matches for each given encoding, starting at {@code currentAddress}
	 * and prints results to the console.
	 * 
	 * This searches encoding by encoding, restarting back at the start of memory for each.
	 * 
	 * Does not currently print wildcard information about the search results, but this could be
	 * added.
	 * 
	 * @param encodings
	 *            HashMap of encodings to that encoding's possible WildOperandInfo values.
	 * @throws MemoryAccessException
	 *             If we find bytes but can't read them
	 */
	private void searchMemoryForEncodings(
			HashMap<AssemblyPatternBlock, HashSet<WildOperandInfo>> encodings,
			ArrayList<WildAssemblyResolvedPatterns> allValidResolvedPatterns)
			throws MemoryAccessException {

		Memory memory = currentProgram.getMemory();

		for (var entry : encodings.entrySet()) {
			var encoding = entry.getKey();
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
	 * 
	 * NOTE: This is certainly not the highest performance way to do this, but it is reasonably
	 * simple and shows what is possible.
	 * 
	 * @param matchAddress
	 *            The address where our search hit occurred
	 * @param matchData
	 *            The bytes found at matchAddress. Must include the entire matching instruction!
	 * @param allValidResolvedPatterns
	 *            All resolved patterns which were searched from (used to find wildcard information)
	 */
	private void printSearchHitInfo(Address matchAddress, byte[] matchData,
			ArrayList<WildAssemblyResolvedPatterns> allValidResolvedPatterns) {

		println("Hit at address: " + matchAddress.toString());

		// Search over all the resolutions we were searching for and find the one which matches and
		// use it determine what the wildcard values are for the given hit.
		//
		// It'd likely be much faster the deduplicate similar WildAssemblyResolvedPatterns based on
		// their instruction with wildcards masked out (similar to what is done in
		// ReducedWildcardAssemblyResolvedPattern) and create a lookup table for wildcard values but
		// that's beyond this basic example script.
		for (WildAssemblyResolvedPatterns resolved : allValidResolvedPatterns) {
			var resolvedInstruction = resolved.getInstruction();
			if (resolvedInstruction.length() > matchData.length) {
				// It can't be this resolution because we were not given enough bytes of matchData
				continue;
			}

			// Mask out the matchData with the mask of our candidate resolvedInstruction and see if
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
	 * {@code WildAssemblyResolvedPatterns}
	 * 
	 * @param results
	 * @return
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
