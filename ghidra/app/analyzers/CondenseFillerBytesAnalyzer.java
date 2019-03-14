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
package ghidra.app.analyzers;

import java.util.*;
import java.util.Map.Entry;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.AlignmentDataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramUtilities;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class CondenseFillerBytesAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Condense Filler Bytes";
	private static final String DESCRIPTION =
		"This analyzer finds filler bytes between functions and collapses them";
	private static final String DEFAULT_FILL_VALUE = "Auto";
	private static final int MIN_BYTES = 1;
	private int minBytes = MIN_BYTES;
	String fillerValue = DEFAULT_FILL_VALUE;

	public CondenseFillerBytesAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
		setPrototype();
	}

	/**
	 * This function tries to determine the fill value used by the current program.
	 * The byte value occurring most is the winner.
	 * 
	 * @return filler value
	 * @throws Exception
	 */
	String determineFillerValue(Listing listing) {

		FunctionIterator iterator = listing.getFunctions(true);
		HashMap<String, Integer> patterns = new HashMap<>();

		while (iterator.hasNext()) {

			// Get undefined byte immediately following function
			Function function = iterator.next();
			Address maxAddress = function.getBody().getMaxAddress();
			Data undefinedData = listing.getUndefinedDataAt(maxAddress.next());
			if (undefinedData == null) {
				// No undefined filler bytes found, keep going to next function
				continue;
			}

			// Add filler to hash
			String pattern = ProgramUtilities.getByteCodeString(undefinedData);
			if ("??".equals(pattern)) {
				continue;
			}

			if (patterns.containsKey(pattern)) {
				int value = patterns.get(pattern);
				patterns.put(pattern, value + 1);
			}
			else {
				patterns.put(pattern, 1);
			}
		}

		if (patterns.isEmpty()) {
			return null;
		}

		// Decide that filler value is the one with the greatest count				
		String filler = getMostFrequentFillValue(patterns);

		return filler;
	}

	private String getMostFrequentFillValue(HashMap<String, Integer> fillValuesHash) {

		if (fillValuesHash.isEmpty()) {
			throw new AssertException("Must have filler bytes!");
		}

		// Determine val with highest count		
		Set<Entry<String, Integer>> entries = fillValuesHash.entrySet();
		Entry<String, Integer> max = entries.iterator().next(); // start with a non-null
		for (Entry<String, Integer> entry : entries) {
			int current = entry.getValue();
			if (current > max.getValue()) {
				max = entry;
			}
		}

		return max.getKey();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		String filler = "0x" + fillerValue;

		if (fillerValue.equalsIgnoreCase(DEFAULT_FILL_VALUE)) {
			String fillerBytes = determineFillerValue(listing);
			if (fillerBytes == null) {
				return false;
			}

			filler = "0x" + fillerBytes;
		}

		// Create array of minBytes length initialized to fillerByte    	    	    	
		byte[] testBytes = new byte[minBytes];
		byte fillerByte = Integer.decode(filler).byteValue();
		Arrays.fill(testBytes, fillerByte);

		byte[] programBytes = new byte[minBytes];

		FunctionIterator iterator = listing.getFunctions(true);
		while (iterator.hasNext() && !monitor.isCancelled()) {

			// Get undefined byte immediately following function
			Function functioin = iterator.next();
			Address fillerAddress = functioin.getBody().getMaxAddress().next();
			Data undefined = listing.getUndefinedDataAt(fillerAddress);
			if (undefined == null) {
				// No undefined filler bytes found, keep going to next function
				continue;
			}

			String undefinedRepresentation = undefined.getDefaultValueRepresentation();

			if (!getBytes(program.getMemory(), fillerAddress, programBytes)) {
				continue;
			}

			if (!Arrays.equals(programBytes, testBytes)) {
				// the bytes we found do not match the chosen filler type--ignore
				continue;
			}

			// Determine actual length of filler bytes
			int fillerLength = countUndefineds(program, fillerAddress, undefinedRepresentation);

			replaceFillerBytes(listing, fillerAddress, fillerLength);
		}

		return true;
	}

	private boolean getBytes(Memory memory, Address fillerAddress, byte[] programBytes) {
		try {
			memory.getBytes(fillerAddress, programBytes);
			return true;
		}
		catch (MemoryAccessException e) {
			return false;
		}
	}

	private int countUndefineds(Program p, Address address, String undefinedString) {

		int undefinedCount = 1;
		Listing listing = p.getListing();
		AddressSet allAddressAfter = new AddressSet(p, address, p.getMaxAddress());
		AddressIterator iterator = allAddressAfter.getAddresses(address.next(), true);
		while (iterator.hasNext()) {
			Address next = iterator.next();
			Data undefined = listing.getUndefinedDataAt(next);
			if (undefined == null) {
				break;
			}

			String currentString = undefined.getDefaultValueRepresentation();
			if (!undefinedString.equalsIgnoreCase(currentString)) {
				break;
			}
			++undefinedCount;
		}
		return undefinedCount;
	}

	private void replaceFillerBytes(Listing listing, Address fillerAddress, int fillerLength) {
		// Replace filler bytes with Alignment type
		try {
			listing.createData(fillerAddress, new AlignmentDataType(), fillerLength);
		}
		catch (CodeUnitInsertionException e) {
			// shouldn't happen if we have true filler bytes
			Msg.error(this,
				"Unable to condense filler bytes (bad filler value?) at " + fillerAddress, e);
			return;
		}
		catch (DataTypeConflictException e) {
			// shouldn't happen if we have true filler bytes
			Msg.error(this,
				"Unable to condense filler bytes (bad filler value?) at " + fillerAddress, e);
			return;
		}
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption("Minimum number of sequential bytes", minBytes, null,
			"Enter the minimum number of sequential bytes to collapse");
		options.registerOption("Filler Value", fillerValue, null,
			"Enter filler byte to search for and collapse (Examples:  0, 00, 90, cc).  " +
				"\"Auto\" will make the program determine the value (by greatest count).");
		optionsChanged(options, program);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		fillerValue = options.getString("Filler Value", fillerValue);
		minBytes = options.getInt("Minimum number of sequential bytes", minBytes);
	}
}
