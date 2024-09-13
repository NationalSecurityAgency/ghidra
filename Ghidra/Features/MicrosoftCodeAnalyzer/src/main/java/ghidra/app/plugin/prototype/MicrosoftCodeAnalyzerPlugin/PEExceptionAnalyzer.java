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
package ghidra.app.plugin.prototype.MicrosoftCodeAnalyzerPlugin;

import java.util.List;

import ghidra.app.cmd.data.exceptionhandling.CreateEHFuncInfoBackgroundCmd;
import ghidra.app.cmd.data.exceptionhandling.EHFunctionInfoModel;
import ghidra.app.services.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.bytesource.ProgramByteSource;
import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.matcher.RegExByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.*;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer that finds Windows PE Visual Studio exception handling data structures and creates data using the 
 * exception handling data types. Data flows can be followed to find other data and functions. If
 * the data appears valid, labels, references, and functions can be created based on the data.
 */
public class PEExceptionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Windows x86 PE Exception Handling";
	private static final String DESCRIPTION =
		"Marks up exception handling data structures within a Visual Studio windows PE program.";

	// MATCH_LIMIT is the maximum number of matches allowed when searching for FuncInfo magic numbers.
	private static final int MATCH_LIMIT = Integer.MAX_VALUE; // May need to change this limit later.
	// MAX_MAP_ENTRY_COUNT is the maximum expected value for a count of map entries.
	private static final int MAX_MAP_ENTRY_COUNT = 16000;

	/**
	 * Creates an analyzer for determining PE exception handling data.
	 */
	public PEExceptionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PEUtil.isVisualStudioOrClangPe(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Get the memory blocks to search for exception handling structures.
		List<MemoryBlock> ehBlocks =
			ProgramMemoryUtil.getMemoryBlocksStartingWithName(program, set, ".rdata", monitor);
		if (ehBlocks.isEmpty()) {
			ehBlocks =
				ProgramMemoryUtil.getMemoryBlocksStartingWithName(program, set, ".text", monitor);
		}

		// search for FuncInfo data type's magic number pattern.
		String lePattern =
			"[\\x20,\\x21,\\x22]\\x05\\x93[\\x19,\\x39,\\x59,\\x79,\\x99,\\xb9,\\xd9,\\xf9]";
		String bePattern =
			"[\\x19,\\x39,\\x59,\\x79,\\x99,\\xb9,\\xd9,\\xf9]\\x93\\x05[\\x20,\\x21,\\x22]";

		String pattern = program.getLanguage().isBigEndian() ? bePattern : lePattern;
		int alignment = 4;

		SearchSettings settings = new SearchSettings().withAlignment(alignment);
		settings = settings.withIncludeInstructions(false); 	// only search data

		ByteMatcher matcher = new RegExByteMatcher(pattern, settings);
		AddressableByteSource byteSource = new ProgramByteSource(program);
		Memory memory = program.getMemory();
		AddressSet addresses = memory.getLoadedAndInitializedAddressSet().intersect(set);

		// Only want to search exception handling memory blocks.
		addresses = getAddressSet(ehBlocks).intersect(addresses);

		MemorySearcher searcher = new MemorySearcher(byteSource, matcher, addresses, MATCH_LIMIT);

		ListAccumulator<MemoryMatch> accumulator = new ListAccumulator<>();
		searcher.findAll(accumulator, monitor);
		List<MemoryMatch> results = accumulator.asList();

		// Establish the options to use when creating the exception handling data.
		// For now these are fixed. Later these may need to come from analysis options.
		DataValidationOptions validationOptions = new DataValidationOptions();
		DataApplyOptions applyOptions = new DataApplyOptions();

		monitor.setMaximum(results.size());

		// Attempt to create data at each address if it appears to be valid for the data type.
		int count = 0;
		for (MemoryMatch match : results) {

			monitor.setProgress(count++);
			if (monitor.isCancelled()) {
				return false;
			}

			Address address = match.getAddress();
			if (address.getOffset() % alignment != 0) {
				continue; // Skip non-aligned addresses.
			}
			// Validate the possible FuncInfo before trying to create it.
			EHFunctionInfoModel model =
				new EHFunctionInfoModel(program, address, validationOptions);
			try {
				model.validate();
				model.validateCounts(MAX_MAP_ENTRY_COUNT);
				model.validateLocationsInSameBlock();

				// Create FuncInfo data at the address of the magic number, if the data appears valid.
				// This can also create associated exception handling data based on the options.
				Command<Program> cmd =
					new CreateEHFuncInfoBackgroundCmd(address, validationOptions, applyOptions);
				cmd.applyTo(program);
			}
			catch (InvalidDataTypeException e) {
				// Doesn't appear valid so just move on to the next one.
				// This doesn't log an error because we are trying to find valid exception
				// handling structures and apply them.
			}
		}

		return true;
	}

	private AddressSet getAddressSet(List<MemoryBlock> blocks) {
		AddressSet addressSet = new AddressSet();
		for (MemoryBlock memoryBlock : blocks) {
			addressSet.add(memoryBlock.getStart(), memoryBlock.getEnd());
		}
		return addressSet;
	}
}
