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

import java.util.*;

import ghidra.app.cmd.data.CreateTypeDescriptorBackgroundCmd;
import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.*;
import ghidra.app.services.*;
import ghidra.app.util.datatype.microsoft.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Finds Run-Time Type Information (RTTI) data structures within a Windows program. It creates data
 * where the RTTI structures are found and annotates them using symbols and comments.
 */
public class RttiAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Windows x86 PE RTTI Analyzer";
	private static final String DESCRIPTION =
		"Finds and creates RTTI metadata structures and associated vf tables.";

	// TODO If we want the RTTI analyzer to find all type descriptors regardless of whether
	//      they are used for RTTI, then change the CLASS_PREFIX_CHARS to ".". Need to be
	//      careful that changing to this doesn't cause problems to RTTI analysis.
	private static final String CLASS_PREFIX_CHARS = ".?A";

	private DataValidationOptions validationOptions;
	private DataApplyOptions applyOptions;

	/**
	 * Constructs an RttiAnalyzer.
	 */
	public RttiAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
		// Set priority of RTTI analyzer to run after Demangler so can see if better 
		// plate comment or label already exists from Demangler.
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
		setDefaultEnablement(true);
		validationOptions = new DataValidationOptions();
		applyOptions = new DataApplyOptions();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PEUtil.isVisualStudioOrClangPe(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Address commonVfTableAddress = RttiUtil.findTypeInfoVftableAddress(program, monitor);

		if (commonVfTableAddress == null) {
			return true;
		}
		
		RttiUtil.createTypeInfoVftableSymbol(program,commonVfTableAddress);
		
		Set<Address> possibleTypeAddresses = locatePotentialRTTI0Entries(program, set, monitor);
		if (possibleTypeAddresses == null) {
			return true;
		}

		// We now have a list of potential rtti0 addresses.
		processRtti0(possibleTypeAddresses, program, monitor);

		return true;
	}

	/**
	 * locate any potential RTTI0 based on pointers to the type_info vftable
	 * @param program proram to locate within
	 * @param set restricted set to locate within
	 * @param monitor monitor for canceling
	 * @return set of potential RTTI0 entries
	 * @throws CancelledException
	 */
	private Set<Address> locatePotentialRTTI0Entries(Program program, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		Address commonVfTableAddress = RttiUtil.findTypeInfoVftableAddress(program, monitor);
		if (commonVfTableAddress == null) {
			return null;
		}

		// use the type_info vftable address to find a list of potential RTTI0 addresses
		int alignment = program.getDefaultPointerSize();
		List<MemoryBlock> dataBlocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(
				program, program.getMemory(), ".data", TaskMonitor.DUMMY);
		Set<Address> possibleTypeAddresses = ProgramMemoryUtil.findDirectReferences(program,
				dataBlocks, alignment, commonVfTableAddress, monitor);
		return possibleTypeAddresses;
	}

	private void processRtti0(Collection<Address> possibleRtti0Addresses, Program program,
			TaskMonitor monitor) throws CancelledException {

		monitor.setMaximum(possibleRtti0Addresses.size());
		monitor.setMessage("Creating RTTI Data...");

		ArrayList<Address> rtti0Locations = new ArrayList<>();
		int count = 0;
		for (Address rtti0Address : possibleRtti0Addresses) {
			monitor.checkCanceled();
			monitor.setProgress(count++);

			// Validate
			TypeDescriptorModel typeModel =
				new TypeDescriptorModel(program, rtti0Address, validationOptions);
			try {
				// Check that name matches the expected format.
				String typeName = typeModel.getTypeName(); // can be null.
				if (typeName == null || !typeName.startsWith(CLASS_PREFIX_CHARS)) {
					continue; // Invalid so don't create.
				}
			}
			catch (InvalidDataTypeException e) {
				continue; // Invalid so don't create.
			}

			// Create the TypeDescriptor (RTTI 0) regardless of the other RTTI structures.
			CreateTypeDescriptorBackgroundCmd typeDescCmd = new CreateTypeDescriptorBackgroundCmd(
				rtti0Address, validationOptions, applyOptions);
			typeDescCmd.applyTo(program, monitor);

			rtti0Locations.add(rtti0Address);
		}

		// Create any valid RTTI4s for this TypeDescriptor
		processRtti4sForRtti0(program, rtti0Locations, monitor);
	}

	private void processRtti4sForRtti0(Program program, List<Address> rtti0Locations,
			TaskMonitor monitor) throws CancelledException {

		List<MemoryBlock> dataBlocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", monitor);

		dataBlocks.addAll(ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".data", monitor));

		dataBlocks.addAll(ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".text", monitor));

		List<Address> rtti4Addresses =
			getRtti4Addresses(program, dataBlocks, rtti0Locations, validationOptions, monitor);

		// create all found RTTI4 tables at once
		if (rtti4Addresses.size() > 0) {
			CreateRtti4BackgroundCmd cmd = new CreateRtti4BackgroundCmd(rtti4Addresses, dataBlocks,
				validationOptions, applyOptions);
			cmd.applyTo(program, monitor);
		}
	}

	/**
	 * Gets the base addresses of all the RTTI 4 structures that appear to be associated with
	 * the RTTI 0 at the indicated base address.
	 * @param program the program containing the RTTI 0 data structure.
	 * @param rtti4Blocks the memory blocks to be searched for RTTI4 structures.
	 * @param rtti0Locations the base addresses of the RTTI 0 structure in the program
	 * @param validationOptions options indicating how validation is performed for data structures
	 * @param monitor the task monitor for canceling a task
	 * @return the RTTI 4 base addresses associated with the RTTI 0
	 * @throws CancelledException if the user cancels this task.
	 */
	private static List<Address> getRtti4Addresses(Program program, List<MemoryBlock> rtti4Blocks,
			List<Address> rtti0Locations, DataValidationOptions validationOptions,
			TaskMonitor monitor) throws CancelledException {

		monitor.checkCanceled();

		List<Address> addresses =
			getRefsToRtti0(program, rtti4Blocks, rtti0Locations, validationOptions, monitor);

		return addresses;
	}

	/** For each of the RTTI0 locations found locate the associated RTTI4 structure referring to it.
	 * 
	 * @param program program to be searched
	 * @param dataBlocks dataBlocks to search
	 * @param rtti0Locations list of known rtti0 locations
	 * @param validationOptions options for validation of found RTTI4 entries
	 * @param monitor to cancel
	 * @return list of found RTTI4 references to known RTTI0 locations
	 * @throws CancelledException if canceled
	 */
	private static List<Address> getRefsToRtti0(Program program, List<MemoryBlock> dataBlocks,
			List<Address> rtti0Locations, DataValidationOptions validationOptions,
			TaskMonitor monitor) throws CancelledException {

		List<Address> addresses = new ArrayList<>(); // the RTTI 4 addresses

		int rtti0PointerOffset = Rtti4Model.getRtti0PointerComponentOffset();

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("RTTI0 references");

		for (Address rtti0Address : rtti0Locations) {
			byte[] bytes;
			if (MSDataTypeUtils.is64Bit(program)) {
				// 64-bit programs will have the addresses as offsets from the image base (BOS)
				bytes = ProgramMemoryUtil.getImageBaseOffsets32Bytes(program, 4, rtti0Address);

				addByteSearchPattern(searcher, validationOptions, addresses, rtti0PointerOffset,
					rtti0Address, bytes);
			}
			else {
				// 32-bit could have direct address in memory
				bytes = ProgramMemoryUtil.getDirectAddressBytes(program, rtti0Address);

				addByteSearchPattern(searcher, validationOptions, addresses, rtti0PointerOffset,
					rtti0Address, bytes);
			}
		}

		AddressSet searchSet = new AddressSet();
		for (MemoryBlock block : dataBlocks) {
			searchSet.add(block.getStart(), block.getEnd());
		}

		searcher.search(program, searchSet, monitor);

		return addresses;
	}

	/**
	 * Add a search pattern, to the searcher, for the set of bytes representing an address
	 * 
	 * @param searcher pattern searcher
	 * @param validationOptions RTTI4 validation options
	 * @param addresses list of found valid RTTI4 locations accumulated during actual search
	 * @param rtti0PointerOffset offset of pointer in RTTI4 entry to RTTI0
	 * @param rtti0Address RTTI0 address corresponding to pattern of bytes
	 * @param bytes pattern of bytes in memory corresponding to address
	 */
	private static void addByteSearchPattern(MemoryBytePatternSearcher searcher,
			DataValidationOptions validationOptions, List<Address> addresses,
			int rtti0PointerOffset, Address rtti0Address, byte[] bytes) {

		// no pattern bytes.
		if (bytes == null) {
			return;
		}

		// Each time a match for this byte pattern validate as an RTTI4 and add to list
		GenericMatchAction<Address> action = new GenericMatchAction<>(rtti0Address) {
			@Override
			public void apply(Program prog, Address addr, Match match) {
				Address possibleRtti4Address;
				try {
					possibleRtti4Address = addr.subtractNoWrap(rtti0PointerOffset);
				}
				catch (AddressOverflowException e) {
					return; // Couldn't get an Rtti4 address.
				}

				Rtti4Model rtti4Model =
					new Rtti4Model(prog, possibleRtti4Address, validationOptions);
				try {
					rtti4Model.validate();
				}
				catch (InvalidDataTypeException e) {
					return; // Only process valid RTTI 4 data.
				}

				// Check that the RTTI 0 is referred to both directly from the RTTI 4 and indirectly 
				// through the RTTI 3.
				boolean refersToRtti0 = rtti4Model.refersToRtti0(getMatchValue());
				if (!refersToRtti0) {
					return; // Only process valid RTTI 4 data.
				}

				// add to list of RTTI4 locations to be processed later
				addresses.add(possibleRtti4Address);
			}
		};

		// create a Pattern of the bytes and the MatchAction to perform upon a match
		GenericByteSequencePattern<Address> genericByteMatchPattern =
			new GenericByteSequencePattern<>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);
	}
}
