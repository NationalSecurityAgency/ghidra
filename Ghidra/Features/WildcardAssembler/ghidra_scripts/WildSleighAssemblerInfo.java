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
// Prints information about the results of assembling an instruction using the WildSleighAssembler
// when that instruction has one or more wildcards in it.
//
// This script uses currentProgram and currentAddress to determine architecture and location.
//
// Notice that this script doesn't only output the assembled bytes of an instruction, but also more
// specific information about each wildcard in the input instruction.
//
// See the "FindInstructionWithWildcard" script for another example of using the WildSleighAssembler
// @category Examples

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolution;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.asm.wild.*;
import ghidra.asm.wild.sem.WildAssemblyResolvedPatterns;

public class WildSleighAssemblerInfo extends GhidraScript {

	List<String> sampleInstructions = List.of(
		"MOV EAX,`Q1`",
		"MOV RDI,qword ptr [`Q1` + -0x30]",
		"Custom");

	@Override
	public void run() throws Exception {

		String instruction = askChoice("Instruction to assemble", "Assemble this instruction:",
			sampleInstructions, "Custom");

		if (instruction.equals("Custom")) {
			instruction = askString("Instruction",
				"Instruction to assemble and print information about.",
				"MOV RDI,qword ptr [`Q1` + -0x30]");
		}
		var assemblyResolutions = getAllAssemblyResolutions(instruction);
		printAssemblyParseResults(assemblyResolutions);
	}

	/**
	 * Use a {@link WildSleighAssembler} to assemble the given {@code wildcardedInstruction}
	 * 
	 * @param wildcardedInstruction String of the instruction to assemble, possibly including a
	 *            wildcard
	 * @return All AssemblyParseResult produced from the given input
	 */
	private List<AssemblyResolution> getAllAssemblyResolutions(
			String wildcardedInstruction) {

		SleighLanguage language = (SleighLanguage) currentProgram.getLanguage();

		// Make sure that if one of the example instructions was chosen the current binary has the
		// correct architecture.
		if (sampleInstructions.contains(wildcardedInstruction) &&
			!language.getLanguageID().toString().equals("x86:LE:64:default")) {
			popup("""
					The current program is not a \"x86:LE:64:default\" binary that the example was \
					designed for. This script will continue and try anyway, but the results might \
					not be as expected. Retry with a custom instruction in your architecture!""");
		}

		// Create a WildSleighAssembler that we'll use to assemble our wildcard-included instruction
		WildSleighAssemblerBuilder assemblerBuilder = new WildSleighAssemblerBuilder(language);
		WildSleighAssembler assembler =
			assemblerBuilder.getAssembler(new AssemblySelector(), currentProgram);

		// Parse a single line of assembly which includes a wildcard.
		Collection<AssemblyParseResult> parses = assembler.parseLine(wildcardedInstruction);

		long errorCount = parses.stream().filter(p -> p.isError()).count();
		println("Removing " + errorCount + " of " + parses.size() +
			" AssemblyParseResults which are errored parses");

		return parses
				.stream()
				// Remove all the AssemblyParseResults that represent parse errors
				.filter(p -> !p.isError())
				// Resolve each parseTree at the current address and collect all AssemblyResolutions
				// into a single flat collection using flatMap
				.flatMap(p -> assembler.resolveTree(p, currentAddress).stream())
				.collect(Collectors.toList());
	}

	/**
	 * Print information about the {@link WildAssemblyResolvedPatterns} in the given list.
	 * 
	 * @param resolutionResults
	 */
	private void printAssemblyParseResults(List<AssemblyResolution> resolutionResults) {
		var errorCount = 0;

		for (AssemblyResolution r : resolutionResults) {
			if (monitor.isCancelled()) {
				break;
			}
			if (r instanceof WildAssemblyResolvedPatterns resolution) {
				printWildAssemblyResolvedPatterns(resolution);
			}
			else {
				errorCount += 1;
			}
		}

		if (errorCount > 0) {
			println("Additionally, " + errorCount +
				" non-WildAssemblyResolvedPatterns were not printed");

		}
	}

	/**
	 * Print information about a single {@link WildAssemblyResolvedPatterns}, including information
	 * about each of its wildcards.
	 * 
	 * @param x The value to print information about.
	 */
	private void printWildAssemblyResolvedPatterns(WildAssemblyResolvedPatterns x) {
		println("Instruction bits (including wildcard values): " + x.getInstruction());
		for (WildOperandInfo info : x.getOperandInfo()) {
			String out =
				"\tThe wildcard " + info.wildcard() + " is found in bits " + info.location();
			if (info.choice() == null) {
				out += " with a value which can be computed with the expression: " +
					info.expression();
			}
			else {
				out += " with the value: " + info.choice() +
					" which can be computed with the expression: " + info.expression();
			}
			println(out);
		}
	}

}
