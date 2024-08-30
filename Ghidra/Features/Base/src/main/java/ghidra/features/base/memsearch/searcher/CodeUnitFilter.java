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
package ghidra.features.base.memsearch.searcher;

import java.util.function.Predicate;

import ghidra.program.model.listing.*;

/**
 * Search filter that can test a search result and determine if that result starts at or inside
 * a code unit that matches one of the selected types.
 */
public class CodeUnitFilter implements Predicate<MemoryMatch> {

	private boolean includeInstructions;
	private boolean includeUndefinedData;
	private boolean includeDefinedData;
	private boolean includeAll;
	private Listing listing;

	/**
	 * Constructor
	 * @param program the program to get code units from for testing its type
	 * @param includeInstructions if true, accept matches that are in an instruction
	 * @param includeDefinedData if true, accept matches that are in defined data
	 * @param includeUndefinedData if true, accept matches that are in undefined data
	 */
	public CodeUnitFilter(Program program, boolean includeInstructions, boolean includeDefinedData,
			boolean includeUndefinedData) {
		this.listing = program.getListing();
		this.includeInstructions = includeInstructions;
		this.includeDefinedData = includeDefinedData;
		this.includeUndefinedData = includeUndefinedData;
		this.includeAll = includeInstructions && includeDefinedData && includeUndefinedData;
	}

	@Override
	public boolean test(MemoryMatch match) {
		if (includeAll) {
			return true;
		}
		CodeUnit codeUnit = listing.getCodeUnitContaining(match.getAddress());
		if (codeUnit instanceof Instruction) {
			return includeInstructions;
		}
		else if (codeUnit instanceof Data) {
			Data data = (Data) codeUnit;
			if (data.isDefined()) {
				return includeDefinedData;
			}
			return includeUndefinedData;
		}
		return false;
	}

}
