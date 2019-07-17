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
import ghidra.app.cmd.data.rtti.CreateRtti4BackgroundCmd;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.services.*;
import ghidra.app.util.datatype.microsoft.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.lang.UndefinedValueException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds Run-Time Type Information (RTTI) data structures within a Windows program. It creates data
 * where the RTTI structures are found and annotates them using symbols and comments.
 */
public class RttiAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Windows x86 PE RTTI Analyzer";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the RTTI metadata structures and their associated vf tables.";

	// TODO If we want the RTTI analyzer to find all type descriptors regardless of whether
	//      they are used for RTTI, then change the CLASS_PREFIX_CHARS to ".". Need to be
	//      careful that changing to this doesn't cause problems to RTTI analysis.
	private static final String CLASS_PREFIX_CHARS = ".?A";
	public static final String TYPE_INFO_STRING = ".?AVtype_info@@";

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
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before());
		setDefaultEnablement(true);
		validationOptions = new DataValidationOptions();
		applyOptions = new DataApplyOptions();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PEUtil.canAnalyze(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		List<MemoryBlock> dataBlocks =
			ProgramMemoryUtil.getMemoryBlocksStartingWithName(program, set, ".data", monitor);
		List<Address> typeInfoAddresses =
			ProgramMemoryUtil.findString(TYPE_INFO_STRING, program, dataBlocks, set, monitor);

		int typeInfoCount = typeInfoAddresses.size();
		if (typeInfoCount != 1) {
			if (typeInfoCount == 0) {
				log.appendMsg(this.getName(), "Couldn't find type info structure.");
				return true;
			}
			log.appendMsg(this.getName(),
				"Found " + typeInfoCount + " type info structures when expecting only 1.");
			return false;
		}

		// Found exactly 1 type info string, so use it to find RTTI structures.
		Address typeInfoStringAddress = typeInfoAddresses.get(0);
		Address typeInfoRtti0Address =
			TypeDescriptorModel.getBaseAddress(program, typeInfoStringAddress);
		if (typeInfoRtti0Address == null) {
			log.appendMsg(this.getName(), "Couldn't find RTTI type info structure.");
			return true;
		}

		// Get the address of the vf table data in common for all RTTI 0.
		TypeDescriptorModel typeDescriptorModel =
			new TypeDescriptorModel(program, typeInfoRtti0Address, validationOptions);
		try {
			Address commonVfTableAddress = typeDescriptorModel.getVFTableAddress();
			if (commonVfTableAddress == null) {
				log.appendMsg(this.getName(),
					"Couldn't get vf table address for RTTI 0 @ " + typeInfoRtti0Address + ". ");
				return false;
			}

			int alignment = program.getDefaultPointerSize();
			Set<Address> possibleTypeAddresses = ProgramMemoryUtil.findDirectReferences(program,
				dataBlocks, alignment, commonVfTableAddress, monitor);

			// We now have a list of potential rtti0 addresses.
			processRtti0(possibleTypeAddresses, program, monitor);

			return true;
		}
		catch (InvalidDataTypeException | UndefinedValueException e) {
			log.appendMsg(this.getName(), "Couldn't get vf table address for RTTI 0 @ " +
				typeInfoRtti0Address + ". " + e.getMessage());
			return false;
		}
	}

	private void processRtti0(Collection<Address> possibleRtti0Addresses, Program program,
			TaskMonitor monitor) throws CancelledException {

		monitor.setMaximum(possibleRtti0Addresses.size());
		monitor.setMessage("Creating RTTI Data...");

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

			// Create any valid RTTI4s for this TypeDescriptor
			processRtti4sForRtti0(program, rtti0Address, monitor);
		}
	}

	private void processRtti4sForRtti0(Program program, Address rtti0Address, TaskMonitor monitor)
			throws CancelledException {

		List<MemoryBlock> rDataBlocks = ProgramMemoryUtil.getMemoryBlocksStartingWithName(program,
			program.getMemory(), ".rdata", monitor);

		List<Address> rtti4Addresses =
			getRtti4Addresses(program, rDataBlocks, rtti0Address, validationOptions, monitor);

		for (Address rtti4Address : rtti4Addresses) {

			monitor.checkCanceled();

			CreateRtti4BackgroundCmd cmd =
				new CreateRtti4BackgroundCmd(rtti4Address, rDataBlocks, validationOptions,
					applyOptions);
			cmd.applyTo(program, monitor);
		}
	}

	/**
	 * Gets the base addresses of all the RTTI 4 structures that appear to be associated with
	 * the RTTI 0 at the indicated base address.
	 * @param program the program containing the RTTI 0 data structure.
	 * @param rtti4Blocks the memory blocks to be searched for RTTI4 structures.
	 * @param rtti0Address the base address of the RTTI 0 structure in the program
	 * @param validationOptions options indicating how validation is performed for data structures
	 * @param monitor the task monitor for cancelling a task
	 * @return the RTTI 4 base addresses associated with the RTTI 0
	 * @throws CancelledException if the user cancels this task.
	 */
	private static List<Address> getRtti4Addresses(Program program, List<MemoryBlock> rtti4Blocks,
			Address rtti0Address, DataValidationOptions validationOptions, TaskMonitor monitor)
			throws CancelledException {

		monitor.checkCanceled();

		List<Address> addresses = new ArrayList<>(); // the RTTI 4 addresses
		int rtti0PointerOffset = Rtti4Model.getRtti0PointerComponentOffset();
		Set<Address> refsToRtti0 = getRefsToRtti0(program, rtti4Blocks, rtti0Address);

		// for each RTTI 0 now see if we can get RTTI4s that refer to it.
		for (Address refAddress : refsToRtti0) {

			monitor.checkCanceled();

			Address possibleRtti4Address;
			try {
				possibleRtti4Address = refAddress.subtractNoWrap(rtti0PointerOffset);
			}
			catch (AddressOverflowException e) {
				continue; // Couldn't get an Rtti4 address.
			}

			Rtti4Model rtti4Model =
				new Rtti4Model(program, possibleRtti4Address, validationOptions);
			try {
				rtti4Model.validate();
			}
			catch (InvalidDataTypeException e) {
				continue; // Only process valid RTTI 4 data.
			}

			// Check that the RTTI 0 is referred to both directly from the RTTI 4 and indirectly 
			// through the RTTI 3.
			boolean refersToRtti0 = rtti4Model.refersToRtti0(rtti0Address);
			if (!refersToRtti0) {
				continue; // Only process valid RTTI 4 data.
			}

			addresses.add(possibleRtti4Address);
		}
		return addresses;
	}

	private static Set<Address> getRefsToRtti0(Program program, List<MemoryBlock> dataBlocks,
			Address rtti0Address) throws CancelledException {
		Set<Address> refsToRtti0;
		if (MSDataTypeUtils.is64Bit(program)) {
			refsToRtti0 = ProgramMemoryUtil.findImageBaseOffsets32(program, 4, rtti0Address,
				TaskMonitor.DUMMY);
		}
		else {
			refsToRtti0 = ProgramMemoryUtil.findDirectReferences(program, dataBlocks,
				program.getDefaultPointerSize(), rtti0Address, TaskMonitor.DUMMY);
		}
		return refsToRtti0;
	}
}
