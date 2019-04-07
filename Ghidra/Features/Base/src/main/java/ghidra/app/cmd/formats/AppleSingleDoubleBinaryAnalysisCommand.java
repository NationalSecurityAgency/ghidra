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
package ghidra.app.cmd.formats;

import java.io.IOException;
import java.util.List;

import ghidra.app.plugin.core.analysis.AnalysisWorker;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.macos.MacException;
import ghidra.app.util.bin.format.macos.asd.*;
import ghidra.app.util.bin.format.macos.cfm.CFragResource;
import ghidra.app.util.bin.format.macos.cfm.CFragResourceMember;
import ghidra.app.util.bin.format.macos.rm.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.cmd.BinaryAnalysisCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class AppleSingleDoubleBinaryAnalysisCommand extends FlatProgramAPI
		implements BinaryAnalysisCommand, AnalysisWorker {
	private MessageLog messages = new MessageLog();

	public AppleSingleDoubleBinaryAnalysisCommand() {
		super();
	}

	@Override
	public boolean analysisWorkerCallback(Program program, Object workerContext,
			TaskMonitor monitor) throws CancelledException, Exception {
		try {
			ByteProvider provider = new MemoryByteProvider(currentProgram.getMemory(),
				currentProgram.getAddressFactory().getDefaultAddressSpace());

			AppleSingleDouble header = new AppleSingleDouble(provider);
			Address address = toAddr(0);
			DataType headerDT = header.toDataType();
			createData(address, headerDT);
			setPlateComment(address, headerDT.getName());
			createFragment(headerDT.getName(), address, headerDT.getLength());
			address = address.add(headerDT.getLength());

			List<EntryDescriptor> entryList = header.getEntryList();
			for (EntryDescriptor descriptor : entryList) {
				if (monitor.isCancelled()) {
					break;
				}

				DataType descriptorDT = descriptor.toDataType();
				createData(address, descriptorDT);
				setPlateComment(address, descriptorDT.getName());
				createFragment(descriptorDT.getName(), address, descriptorDT.getLength());
				address = address.add(descriptorDT.getLength());

				String name = EntryDescriptorID.convertEntryIdToName(descriptor.getEntryID());
				createFragment(name, toAddr(descriptor.getOffset()), descriptor.getLength());

				Object entryObject = descriptor.getEntry();

				if (descriptor.getEntryID() == EntryDescriptorID.ENTRY_RESOURCE_FORK) {
					markup((ResourceHeader) entryObject, descriptor);
				}
			}

			removeEmptyFragments();

			return true;
		}
		catch (MacException e) {
			messages.appendMsg(
				"Not a binary AppleSingleDouble program: AppleSingleDouble header not found.");
			return false;
		}
	}

	@Override
	public String getWorkerName() {
		return getName();
	}

	@Override
	public boolean applyTo(Program program, TaskMonitor monitor) throws Exception {
		set(program, monitor);

		// Modify program and prevent events from triggering follow-on analysis
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
		return manager.scheduleWorker(this, null, false, monitor);
	}

	@Override
	public boolean canApply(Program program) {
		try {
			Memory memory = program.getMemory();

			int magicNumber =
				memory.getInt(program.getAddressFactory().getDefaultAddressSpace().getAddress(0));

			if (magicNumber == AppleSingleDouble.SINGLE_MAGIC_NUMBER ||
				magicNumber == AppleSingleDouble.DOUBLE_MAGIC_NUMBER) {
				return true;
			}
		}
		catch (Exception e) {
			// expected, ignore
		}
		return false;
	}

	@Override
	public MessageLog getMessages() {
		return messages;
	}

	@Override
	public String getName() {
		return "Apple Single/Double Header Annotation";
	}

	private void markup(ResourceHeader header, EntryDescriptor descriptor) throws Exception {
		DataType headerDT = header.toDataType();
		Address address = toAddr(descriptor.getOffset());
		createData(address, headerDT);
		setPlateComment(address, headerDT.getName());
		createFragment(headerDT.getName(), address, headerDT.getLength());

		Address resourceDataAddress =
			toAddr(header.getResourceDataOffset() + descriptor.getOffset());

		markupResourceData(resourceDataAddress, header.getResourceDataLength());

		ResourceMap map = header.getMap();
		Address mapAddress = markupResourceMap(header, descriptor, map);

		ProgramModule typeModule = createModule("ResourceType");
		Address typeAddress = mapAddress.add(map.getResourceTypeListOffset() + 2/*TODO wtf?*/);
		List<ResourceType> types = map.getResourceTypeList();
		for (ResourceType type : types) {
			if (monitor.isCancelled()) {
				return;
			}
			int length = markupResourceType(type, typeAddress, typeModule);
			typeAddress = typeAddress.add(length);

			markupReferenceListEntry(map, mapAddress, type, resourceDataAddress);
			markupCFM(type, resourceDataAddress);
		}

		markupResourceNameList(map, mapAddress);
	}

	private void markupCFM(ResourceType type, Address resourceDataAddress) throws Exception {
		if (type.getType() != ResourceTypes.TYPE_CFRG) {
			return;
		}
		List<ReferenceListEntry> entries = type.getReferenceList();
		if (entries.size() != 1) {
			throw new AssertException();
		}
		int dataOffset = entries.get(0).getDataOffset();
		Address address = resourceDataAddress.add(dataOffset + 4);
		CFragResource cFragResource = (CFragResource) type.getResourceObject();
		DataType dt = cFragResource.toDataType();
		createData(address, dt);
		setPlateComment(address, dt.getName());
		createFragment(dt.getName(), address, dt.getLength());
		address = address.add(dt.getLength());

		List<CFragResourceMember> members = cFragResource.getMembers();
		for (CFragResourceMember member : members) {
			DataType memberDT = member.toDataType();
			createData(address, memberDT);
			String comment = "Name:   " + member.getName() + "\n" + "Offset: 0x" +
				Integer.toHexString(member.getOffset()) + "\n" + "Length: 0x" +
				Integer.toHexString(member.getLength()) + "\n";
			setPlateComment(address, comment);
			createFragment(memberDT.getName(), address, member.getMemberSize());
			address = address.add(member.getMemberSize());
		}
	}

	private Address markupResourceMap(ResourceHeader header, EntryDescriptor descriptor,
			ResourceMap map) throws DuplicateNameException, IOException, Exception {
		Address address = toAddr(descriptor.getOffset() + header.getResourceMapOffset());
		DataType mapDT = map.toDataType();
		createData(address, mapDT);
		setPlateComment(address, mapDT.getName());
		createFragment(mapDT.getName(), address, mapDT.getLength());
		return address;
	}

	private void markupReferenceListEntry(ResourceMap map, Address mapAddress, ResourceType type,
			Address resourceDataAddress) throws DuplicateNameException, IOException, Exception {
		ProgramModule module = createModule("ResourceListEntry");
		int id = 0;
		Address entryAddress =
			mapAddress.add(map.getResourceTypeListOffset() + type.getOffsetToReferenceList());
		List<ReferenceListEntry> reference = type.getReferenceList();
		for (ReferenceListEntry entry : reference) {
			if (monitor.isCancelled()) {
				return;
			}
			DataType entryDT = entry.toDataType();
			createData(entryAddress, entryDT);
			createFragment(module, type.getTypeAsString() + hack(), entryAddress,
				entryDT.getLength());
			String name = "" + (id++);
			if (entry.getName() != null) {
				name += " - " + entry.getName();
			}
			setPlateComment(entryAddress, name);
			entryAddress = entryAddress.add(entryDT.getLength());

			Address dataAddress = resourceDataAddress.add(entry.getDataOffset());
			setPlateComment(dataAddress, type.getTypeAsString() + " - " + entry.getName());
		}
	}

	/**
	 * Ok, we only support one instance of a fragment name anywhere
	 * in a program tree. I think that is silly, but maybe I am
	 * missing something. In any case, append a ' ' the name to prevent
	 * a collision.
	 */
	private String hack() {
		return " ";
	}

	private int markupResourceType(ResourceType type, Address typeAddress, ProgramModule typeModule)
			throws Exception {
		DataType typeDT = type.toDataType();
		createData(typeAddress, typeDT);
		setPlateComment(typeAddress, typeDT.getName() + " - " + type.getTypeAsString());
		createFragment(typeModule, type.getTypeAsString(), typeAddress, typeDT.getLength());
		return typeDT.getLength();
	}

	private void markupResourceNameList(ResourceMap map, Address mapAddress) throws Exception {
		Address nameAddress = mapAddress.add(map.getResourceNameListOffset());
		while (nameAddress.compareTo(currentProgram.getMaxAddress()) < 0) {
			if (monitor.isCancelled()) {
				return;
			}
			createData(nameAddress, new PascalString255DataType());
			Data data = getDataAt(nameAddress);
			createFragment("ResourceNameList", nameAddress, data.getLength());
			nameAddress = nameAddress.add(data.getLength());
		}
	}

	private void markupResourceData(Address address, int resourceDataLength) throws Exception {
		ProgramModule module = createModule("ResourceData");
		int size = 0;
		int id = 0;
		while (size < resourceDataLength) {
			if (monitor.isCancelled()) {
				return;
			}
			createData(address, new DWordDataType());
			setEOLComment(address, "Data Length");
			int length = getInt(address);
			createFragment(module, "" + (id++), address, length + 4);//add 4 bytes for the DWORD
			size += length + 4;//add 4 bytes for the DWORD
			address = address.add(length + 4);
		}
	}

	private ProgramModule createModule(String moduleName) throws Exception {
		ProgramModule module = currentProgram.getListing().getDefaultRootModule();
		try {
			return module.createModule(moduleName);
		}
		catch (DuplicateNameException e) {
			return (ProgramModule) findGroup(module, moduleName);
		}
	}

	private Group findGroup(ProgramModule module, String groupName) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (monitor.isCancelled()) {
				return null;
			}
			if (group.getName().equals(groupName)) {
				return group;
			}
		}
		return null;
	}

	private void removeEmptyFragments() throws NotEmptyException {
		monitor.setMessage("Removing empty fragments...");
		String[] treeNames = currentProgram.getListing().getTreeNames();
		for (String treeName : treeNames) {
			if (monitor.isCancelled()) {
				break;
			}
			ProgramModule rootModule = currentProgram.getListing().getRootModule(treeName);
			Group[] children = rootModule.getChildren();
			for (Group child : children) {
				if (monitor.isCancelled()) {
					break;
				}
				if (child instanceof ProgramFragment) {
					ProgramFragment fragment = (ProgramFragment) child;
					if (fragment.isEmpty()) {
						rootModule.removeChild(fragment.getName());
					}
				}
			}
		}
	}
}
