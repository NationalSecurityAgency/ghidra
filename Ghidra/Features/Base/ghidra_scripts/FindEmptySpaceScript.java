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
//searches for pre-defined patterns and free space in code images

import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.plugin.core.searchmem.RegExSearchData;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.search.memory.*;

public class FindEmptySpaceScript extends GhidraScript implements Ingredient {

	@Override
	public void run() throws Exception {
		IngredientDescription[] ingredients = getIngredientDescriptions();
		for (IngredientDescription ingredient : ingredients) {
			state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
				ingredient.getDefaultValue());
		}
		if (!state.displayParameterGatherer("Empty Area Finder Options")) {
			return;
		}

		String emptyArea = (String) state.getEnvironmentVar("EmptyAreaData");
		Integer threshold = (Integer) state.getEnvironmentVar("Threshold");
		Integer align = (Integer) state.getEnvironmentVar("Alignment");
		String stem = (String) state.getEnvironmentVar("NameStem");

		findEmptyAreas(emptyArea, threshold, align, stem);
	}

	protected void findEmptyAreas(String emptyArea, Integer threshold, Integer align, String stem)
			throws Exception {
		String emptyAreaPlusThreshold = emptyArea + "{" + threshold + ",}";
		if (align < currentProgram.getLanguage().getInstructionAlignment()) {
			align = currentProgram.getLanguage().getInstructionAlignment();
			println(
				"  Adjusting alignment to minimum instruction alignment for this processor; new alignment is " +
					align + " bytes");
		}
		else if ((align % currentProgram.getLanguage().getInstructionAlignment()) != 0) {
			align = align + (align % currentProgram.getLanguage().getInstructionAlignment());
			println(
				"  Adjusting alignment to match processor instruction alignment; new alignment is " +
					align + " bytes");
		}

		println("  Searching initialized memory for " + emptyAreaPlusThreshold +
			"; minimum size = " + threshold + " bytes ; alignment = " + align +
			" bytes; search limited to first 1000 matches");

		AddressSetView addrs = currentProgram.getMemory().getLoadedAndInitializedAddressSet();

		SearchInfo searchInfo = new SearchInfo(new RegExSearchData(emptyAreaPlusThreshold), 1000,
			false, true, align, true, null);
		RegExMemSearcherAlgorithm searcher =
			new RegExMemSearcherAlgorithm(searchInfo, addrs, currentProgram, true);

		ListAccumulator<MemSearchResult> accumulator = new ListAccumulator<>();
		searcher.search(accumulator, monitor);
		List<MemSearchResult> results = accumulator.asList();
		List<Address> addresses =
			results.stream().map(r -> r.getAddress()).collect(Collectors.toList());

		int numMatches = 0;
		long maxLen = 0;
		if (results.isEmpty()) {
			println("  FAILURE: Could not find any empty areas with regexp = " +
				emptyAreaPlusThreshold + "and alignment = " + align + " bytes");
			return;
		}

		//put matches into an address set, thereby coalescing ranges
		AddressSet addrSet = new AddressSet();
		for (MemSearchResult result : results) {
			Address match = result.getAddress();
			int len = result.getLength();
			addrSet.addRange(match, match.addNoWrap(len));
		}

		//iterate over the set items that matched
		for (AddressRange range : addrSet) {
			long len = range.getLength();
			addLabelAndExportSym(range.getMinAddress(), len, stem, "emptyArea", "size = " + len +
				" bytes (alignment = " + align + " bytes; min size = " + threshold + " bytes)");
			numMatches++;
			if (len > maxLen) {
				maxLen = len;
			}
		}

		println("  Found " + numMatches +
			" empty areas meeting size and alignment requirements; maximum length found = " +
			maxLen + " bytes");

	}

	protected void addLabelAndExportSym(Address matchAddr, long len, String stem, String tag,
			String optComment) {
		String label = stem + "_" + matchAddr + "_" + len;
		label = label.replaceAll(":", "_");
		String comment = "{@exportsym " + tag + " " + optComment + "}";
		CodeUnit cd = currentProgram.getListing().getCodeUnitAt(matchAddr);
		if (cd == null) {
			return;
		}
		AddLabelCmd lcmd = new AddLabelCmd(matchAddr, label, false, SourceType.USER_DEFINED);
		lcmd.applyTo(currentProgram);
		String commentThere = cd.getComment(CodeUnit.EOL_COMMENT);
		if (commentThere != null) {
			comment = commentThere + "\n" + comment;
		}
		cd.setComment(CodeUnit.EOL_COMMENT, comment);
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {

		IngredientDescription[] retVal = new IngredientDescription[] {
			new IngredientDescription("EmptyAreaData", "Regular Expression Data Pattern",
				GatherParamPanel.STRING, "\\xff"),
			new IngredientDescription("Threshold", "Minimum Size (decimal bytes)",
				GatherParamPanel.INTEGER, ""),
			new IngredientDescription("Alignment", "Alignment (decimal bytes)",
				GatherParamPanel.INTEGER, ""),
			new IngredientDescription("NameStem", "Optional Label Stem", GatherParamPanel.STRING,
				"EMPTY") };
		return retVal;
	}

}
