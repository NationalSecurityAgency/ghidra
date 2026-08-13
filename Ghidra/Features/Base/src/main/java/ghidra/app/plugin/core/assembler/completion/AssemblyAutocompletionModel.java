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
package ghidra.app.plugin.core.assembler.completion;

import java.util.*;

import docking.widgets.autocomplete.AutocompletionModel;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult;
import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.HTMLUtilities;

public class AssemblyAutocompletionModel implements AutocompletionModel<AssemblyCompletion> {

	protected Assembler assembler;
	protected Address address;
	protected Instruction existing;
	protected boolean exhaustUndefined;

	/**
	 * Set the assembler to use
	 * 
	 * @param assembler the assembler
	 */
	public void setAssembler(Assembler assembler) {
		this.assembler = Objects.requireNonNull(assembler);
	}

	/**
	 * {@return the assembler used by this model}
	 */
	public Assembler getAssembler() {
		return assembler;
	}

	/**
	 * Set the address of the assembly instruction
	 * <p>
	 * Note this will reset the existing instruction to null to prevent its accidental re-use. See
	 * {@link #setExisting(Instruction)}.
	 * 
	 * @param address the address
	 */
	public void setAddress(Address address) {
		this.address = Objects.requireNonNull(address);
		this.existing = null;
	}

	/**
	 * Set the "existing" instruction used for ordering proposed instructions by "most similar"
	 * 
	 * @see #computePreference(AssemblyResolvedPatterns)
	 * @param existing the existing instruction
	 */
	public void setExisting(Instruction existing) {
		this.existing = existing;
	}

	/**
	 * Construct the HTML display for a given suggestion
	 *
	 * <p>
	 * This is an extension point.
	 * 
	 * <p>
	 * Currently, this just shows the current prefix in bold, and the text that would be inserted as
	 * normal weight.
	 * 
	 * @param prefix the text currently in the fields
	 * @param suggestion the text suggested by the assembly syntax analyzer
	 * @param bufferleft the portion of the prefix that is also part of the suggestion
	 * @return a formatted string that hints to the effect of selecting this suggestion
	 */
	protected String formatSuggestion(String prefix, String suggestion, String bufferleft) {
		String extra = suggestion.substring(bufferleft.length());
		String before = prefix.substring(0, prefix.length() - bufferleft.length());
		return String.format("<html><b>%s%s</b>%s</html>", HTMLUtilities.escapeHTML(before),
			HTMLUtilities.escapeHTML(bufferleft), HTMLUtilities.escapeHTML(extra));
	}

	/**
	 * Provides an ordering for assembled instructions appearing in the list
	 * 
	 * <p>
	 * The items with the highest preference are positioned at the top of the list
	 * 
	 * <p>
	 * This is an extension point.
	 * 
	 * <p>
	 * Currently, a proposed instruction having the same constructor tree as the existing one is the
	 * most preferred. Second, are instructions having a similar tree as the existing one --
	 * "similar" is not yet well defined, but at the moment, it means their constructor tree strings
	 * have a long common prefix. Third, instructions having the same encoded length as the existing
	 * one are preferred. Last, the shortest instructions are preferred.
	 * 
	 * @param rc a resolved instruction
	 * @return a preference
	 */
	protected int computePreference(AssemblyResolvedPatterns rc) {
		if (existing == null) {
			return 0;
		}
		String myTree = rc.dumpConstructorTree();
		String exTree =
			((SleighInstructionPrototype) existing.getPrototype()).dumpConstructorTree();
		for (int i = 0; i < myTree.length(); i++) {
			if (!myTree.startsWith(exTree.substring(0, i))) {
				return rc.getInstructionLength() == existing.getLength() ? 5000 : i;
			}
		}
		return 10000;
	}

	/**
	 * Get the context for filtering completed instructions in the auto-completer
	 * 
	 * @return the context
	 */
	protected AssemblyPatternBlock getContext() {
		return assembler.getContextAt(address).fillMask();
	}

	protected void collectSuggestionsFromErrors(Set<AssemblyCompletion> result, String text) {
		Collection<AssemblyParseResult> parses = assembler.parseLine(text);
		for (AssemblyParseResult parse : parses) {
			if (parse.isError()) {
				AssemblyParseErrorResult err = (AssemblyParseErrorResult) parse;
				String buffer = err.getBuffer();
				for (String s : err.getSuggestions()) {
					if (s.startsWith(buffer)) {
						result.add(new SuggestionAssemblyCompletion(s.substring(buffer.length()),
							formatSuggestion(text, s, buffer)));
					}
				}
			}
		}
	}

	protected void collectSuggestionsFromAccepted(Set<AssemblyCompletion> result, String text) {
		final AssemblyPatternBlock ctx = Objects.requireNonNull(getContext());
		Program program = assembler.getProgram();
		Language language = assembler.getLanguage();
		Register ctxReg = language.getContextBaseRegister();
		RegisterValue ctxVal = ctx.toRegisterValue(ctxReg);
		Collection<AssemblyParseResult> parses = assembler.parseLine(text);
		for (AssemblyParseResult parse : parses) {
			if (!parse.isError()) {
				AssemblyResolutionResults sems = assembler.resolveTree(parse, address, ctx);
				for (AssemblyResolution ar : sems) {
					if (ar.isError()) {
						//result.add(new AssemblyError("", ar.toString()));
						continue;
					}
					AssemblyResolvedPatterns rc = (AssemblyResolvedPatterns) ar;
					for (byte[] ins : rc.possibleInsVals(ctx)) {
						InstructionAssemblyCompletion ai = new InstructionAssemblyCompletion(
							program, language, address, text, Arrays.copyOf(ins, ins.length),
							ctxVal, computePreference(rc));
						result.add(ai);
						if (!exhaustUndefined) {
							break;
						}
					}
				}
			}
		}
	}

	@Override
	public Collection<AssemblyCompletion> computeCompletions(String text) {
		Set<AssemblyCompletion> result = new TreeSet<>();

		collectSuggestionsFromErrors(result, text);
		collectSuggestionsFromAccepted(result, text);

		if (result.isEmpty()) {
			result.add(new ErrorAssemblyCompletion("", "Invalid instruction and/or prefix"));
		}
		return result;
	}

}
