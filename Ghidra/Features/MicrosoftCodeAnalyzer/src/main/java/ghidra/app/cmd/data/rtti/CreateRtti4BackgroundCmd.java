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
package ghidra.app.cmd.data.rtti;

import java.util.*;

import ghidra.app.cmd.data.*;
import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This command will create multiple RTTI4 data types all at one time. 
 * If there are any existing instructions in the areas to be made into data, the command will fail only on that RTTI4 entry.
 * Any data in the area will be replaced with the new dataType.
 */
public class CreateRtti4BackgroundCmd extends AbstractCreateDataBackgroundCmd<Rtti4Model> {

	private static final String RTTI_4_NAME = "RTTI Complete Object Locator";
	private List<MemoryBlock> vfTableBlocks;
	private List<Address> rtti4Locations;

	/**
	 * Constructs a command for applying an RTTI4 dataType at an address.
	 * @param address the address where the data should be created using the data type.
	 * @param vfTableBlocks a list of the only memory blocks to be searched for vf tables.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	public CreateRtti4BackgroundCmd(Address address, List<MemoryBlock> vfTableBlocks,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {

		super(Rtti4Model.DATA_TYPE_NAME, address, 1, validationOptions, applyOptions);
		this.vfTableBlocks = vfTableBlocks;
		rtti4Locations = new ArrayList<Address>();
		rtti4Locations.add(address);
	}

	public CreateRtti4BackgroundCmd(List<Address> addresses, List<MemoryBlock> vfTableBlocks,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {

		super(Rtti4Model.DATA_TYPE_NAME, addresses.get(0), 1, validationOptions, applyOptions);
		this.rtti4Locations = addresses;
		this.vfTableBlocks = vfTableBlocks;
	}

	@Override
	protected boolean doApplyTo(Program program, TaskMonitor taskMonitor)
			throws CancelledException {

		// process each potential RTTI4 entry, keeping track of good RTTI4 tables
		List<Address> goodRtti4Locations = new ArrayList<Address>();
		boolean succeeded = false;
		for (Address addr : rtti4Locations) {
			setDataAddress(addr);
			succeeded |= super.doApplyTo(program, taskMonitor);
			goodRtti4Locations.add(addr);
		}

		// if any succeeded and should create associated data, make the vftables all at one time
		if (succeeded && applyOptions.shouldFollowData()) {
			createAssociatedVfTables(program, goodRtti4Locations, taskMonitor);
		}

		return succeeded;
	}

	@Override
	protected Rtti4Model createModel(Program program) {
		if (model == null || program != model.getProgram() ||
			!getDataAddress().equals(model.getAddress())) {
			model = new Rtti4Model(program, getDataAddress(), validationOptions);
		}
		return model;
	}

	@Override
	protected boolean createAssociatedData() throws CancelledException {

		monitor.checkCanceled();

		boolean createRtti0Success;
		try {
			createRtti0Success = createRtti0();
		}
		catch (InvalidDataTypeException e) {
			createRtti0Success = false;
			// log message and continue with other mark-up.
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
		}

		boolean createRtti3Success;
		try {
			createRtti3Success = createRtti3();
		}
		catch (InvalidDataTypeException e) {
			createRtti3Success = false;
			// log message and continue with other markup.
			handleErrorMessage(model.getProgram(), model.getAddress(), e.getMessage());
		}

		return createRtti0Success && createRtti3Success;
	}

	private boolean createRtti0() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateTypeDescriptorBackgroundCmd cmd =
			new CreateTypeDescriptorBackgroundCmd(model.getRtti0Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createRtti3() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		CreateRtti3BackgroundCmd cmd =
			new CreateRtti3BackgroundCmd(model.getRtti3Model(), applyOptions);
		return cmd.applyTo(model.getProgram(), monitor);
	}

	private boolean createAssociatedVfTables(Program program, List<Address> goodRtti4Locations,
			TaskMonitor taskMonitor) throws CancelledException {

		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("RTTI4 Vftables");

		HashMap<Address, VfTableModel> foundVFtables = new HashMap<>();

		for (Address rtti4Address : goodRtti4Locations) {

			byte[] bytes = ProgramMemoryUtil.getDirectAddressBytes(program, rtti4Address);

			addByteSearchPattern(searcher, foundVFtables, rtti4Address, bytes);
		}

		AddressSet searchSet = new AddressSet();
		for (MemoryBlock block : vfTableBlocks) {
			searchSet.add(block.getStart(), block.getEnd());
		}

		searcher.search(program, searchSet, monitor);

		// did the search, now process the results
		boolean didSome = false;
		for (Address rtti4Address : goodRtti4Locations) {
			monitor.checkCanceled();

			VfTableModel vfTableModel = foundVFtables.get(rtti4Address);
			if (vfTableModel == null) {
				String message =
					"No vfTable found for " + Rtti4Model.DATA_TYPE_NAME + " @ " + rtti4Address;
				handleErrorMessage(program, rtti4Address, message);
				continue;
			}

			CreateVfTableBackgroundCmd cmd =
				new CreateVfTableBackgroundCmd(vfTableModel, applyOptions);
			didSome |= cmd.applyTo(program, monitor);
		}

		return didSome;
	}

	/**
	 * Add a search pattern, to the searcher, for the set of bytes representing an rtti4 location.
	 * Only one VFTable for is allowed for an RTT4 location, last one in wins and gets created.
	 * 
	 * @param searcher byte pattern searcher
	 * @param foundVFtables list of addresses accumulated when actual search is performed
	 * @param rtti4Address location of rttiAddress to find vfTable for
	 * @param bytes bytes representing rtti4Addres to be found in memory
	 */
	private void addByteSearchPattern(MemoryBytePatternSearcher searcher,
			HashMap<Address, VfTableModel> foundVFtables, Address rtti4Address, byte[] bytes) {

		if (bytes == null) {
			return;
		}

		GenericMatchAction<Address> action = new GenericMatchAction<Address>(rtti4Address) {
			@Override
			public void apply(Program prog, Address addr, Match match) {

				Address possibleVfTableAddr = addr.add(prog.getDefaultPointerSize());

				// See if VfTable is valid, and add to rtti4 to vfTable map
				try {
					VfTableModel vfTableModel =
						new VfTableModel(prog, possibleVfTableAddr, validationOptions);
					vfTableModel.validate();

					VfTableModel existing = foundVFtables.put(rtti4Address, vfTableModel);

					if (existing != null) {
						// potential table already found, is an error, don't know which is right
						String message = "More than one possible vfTable found for " +
							Rtti4Model.DATA_TYPE_NAME + " @ " + rtti4Address;
						handleErrorMessage(prog, rtti4Address, message);
					}
				}
				catch (InvalidDataTypeException e) {
					// This isn't a valid model.
				}
			}
		};

		GenericByteSequencePattern<Address> genericByteMatchPattern =
			new GenericByteSequencePattern<Address>(bytes, action);

		searcher.addPattern(genericByteMatchPattern);
	}

	@Override
	protected boolean createMarkup() throws CancelledException, InvalidDataTypeException {

		monitor.checkCanceled();

		Program program = model.getProgram();
		TypeDescriptorModel rtti0Model = model.getRtti0Model();

		if (rtti0Model == null) {
			return true;
		}
		
		monitor.checkCanceled();
		
		// Label
		boolean shouldCreateComment = true;
		if (applyOptions.shouldCreateLabel()) {
			shouldCreateComment = RttiUtil.createSymbolFromDemangledType(program, getDataAddress(), rtti0Model,
					RTTI_4_NAME);
		}

		// Plate Comment
		if (shouldCreateComment) {
			// comment created if a label was created, or createLabel option off
			EHDataTypeUtilities.createPlateCommentIfNeeded(program, RttiUtil.CONST_PREFIX +
					RttiUtil.getDescriptorTypeNamespace(rtti0Model) + Namespace.DELIMITER, RTTI_4_NAME,
					null, getDataAddress(), applyOptions);
		}

		return true;
	}
}
