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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.*;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.objc2.*;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Constants;
import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

public class ObjectiveC2_ClassAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Objective-C 2 Class";
	private static final String DESCRIPTION =
		"An analyzer for extracting and annotating Objective-C 2.0 class structure information.";

	public ObjectiveC2_ClassAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		//The Objective-C 2.0 analyzer should always run first.
		//It knows the deal!
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return processObjectiveC2(program, monitor, log);
	}

	public boolean canAnalyze(Program program) {
		return ObjectiveC2_Constants.isObjectiveC2(program);
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	private boolean processObjectiveC2(Program program, TaskMonitor monitor, MessageLog log) {
		ByteProvider provider =
			new MemoryByteProvider(program.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

		ObjectiveC2_State state =
			new ObjectiveC2_State(program, monitor, ObjectiveC2_Constants.CATEGORY_PATH);

		try {
			processImageInfo(state, reader);

			processClassList(state, reader);
			processCategoryList(state, reader);
			processProtocolList(state, reader);

			processClassReferences(state);
			processSuperReferences(state);
			processProtocolReferences(state);
			processNonLazyClassReferences(state);
			processSelectorReferences(state);
			processMessageReferences(state, reader);

			ObjectiveC1_Utilities.createMethods(state);
			ObjectiveC1_Utilities.createInstanceVariablesC2_OBJC2(state);
			ObjectiveC1_Utilities.fixupReferences(state);

			setDataAndRefBlocksReadOnly(state);
		}
		catch (Exception e) {
			String message = e.getMessage();
			log.appendMsg(getName(), message);
			log.setStatus(message);
			return false;
		}
		finally {
			state.dispose();

			try {
				provider.close();
			}
			catch (IOException e) {
			}
		}
		return true;
	}

	private void setDataAndRefBlocksReadOnly(ObjectiveC2_State state) {
		Memory memory = state.program.getMemory();
		MemoryBlock dataBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_DATA);
		if (dataBlock != null) {
			dataBlock.setWrite(false);
		}

		MemoryBlock classRefsBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_CLASS_REFS);
		if (classRefsBlock != null) {
			classRefsBlock.setWrite(false);
		}

		MemoryBlock messageRefsBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_MESSAGE_REFS);
		if (messageRefsBlock != null) {
			messageRefsBlock.setWrite(false);
		}

		MemoryBlock selectorRefsBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_SELECTOR_REFS);
		if (selectorRefsBlock != null) {
			selectorRefsBlock.setWrite(false);
		}

		MemoryBlock superRefsBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_SUPER_REFS);
		if (superRefsBlock != null) {
			superRefsBlock.setWrite(false);
		}

		MemoryBlock protocolRefsBlock = memory.getBlock(ObjectiveC2_Constants.OBJC2_PROTOCOL_REFS);
		if (protocolRefsBlock != null) {
			protocolRefsBlock.setWrite(false);
		}
	}

	private void processProtocolReferences(ObjectiveC2_State state) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Protocol References...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_PROTOCOL_REFS);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
				address);
			address = address.add(state.pointerSize);
		}
	}

	private void processClassReferences(ObjectiveC2_State state) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Class References...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_CLASS_REFS);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
				address);
			address = address.add(state.pointerSize);
		}
	}

	private void processNonLazyClassReferences(ObjectiveC2_State state) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Non-lazy Class Lists...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_NON_LAZY_CLASS_LIST);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
				address);
			address = address.add(state.pointerSize);
		}
	}

	private void processSuperReferences(ObjectiveC2_State state) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Super References...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_SUPER_REFS);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
				address);
			address = address.add(state.pointerSize);
		}
	}

	private void processCategoryList(ObjectiveC2_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Category Information...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_CATEGORY_LIST);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			Address categoryAddress =
				ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
					address);
			reader.setPointerIndex(categoryAddress.getOffset());
			ObjectiveC2_Category category = new ObjectiveC2_Category(state, reader);
			category.applyTo();
			address = address.add(state.pointerSize);
		}
	}

	private void processImageInfo(ObjectiveC2_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Image Information...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_IMAGE_INFO);
		if (block == null) {
			return;
		}
		Address address = block.getStart();
		reader.setPointerIndex(address.getOffset());
		ObjectiveC2_ImageInfo imageInfo = new ObjectiveC2_ImageInfo(state, reader);
		imageInfo.applyTo();
	}

	private void processProtocolList(ObjectiveC2_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Protocol Information...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_PROTOCOL_LIST);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);

			Address protocolAddress =
				ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
					address);
			reader.setPointerIndex(protocolAddress.getOffset());

			ObjectiveC2_Protocol protocol = new ObjectiveC2_Protocol(state, reader);
			Namespace namespace =
				ObjectiveC1_Utilities.createNamespace(state.program,
					ObjectiveC1_Constants.NAMESPACE, "Protocols", protocol.getName());
			protocol.applyTo(namespace);
			address = address.add(state.pointerSize);
		}
	}

	private void processClassList(ObjectiveC2_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Class Information...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_CLASS_LIST);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);

			Address classAddress =
				ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
					address);
			reader.setPointerIndex(classAddress.getOffset());

			ObjectiveC2_Class clazz = new ObjectiveC2_Class(state, reader);
			clazz.applyTo();
			address = address.add(state.pointerSize);
		}
	}

	private void processMessageReferences(ObjectiveC2_State state, BinaryReader reader)
			throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Message References...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_MESSAGE_REFS);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / ObjectiveC2_MessageReference.SIZEOF(state);

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			reader.setPointerIndex(address.getOffset());
			ObjectiveC2_MessageReference messageRef =
				new ObjectiveC2_MessageReference(state, reader);
			DataType dt = messageRef.toDataType();
			Data messageRefData = state.program.getListing().createData(address, dt);
			Data selData = messageRefData.getComponent(1);
			Object selAddress = selData.getValue();
			Data selStringData = state.program.getListing().getDataAt((Address) selAddress);
			Object selString = selStringData.getValue();
			ObjectiveC1_Utilities.createSymbol(state.program, null, selString + "_" +
				ObjectiveC2_MessageReference.NAME, address);
			address = address.add(dt.getLength());
		}
	}

	private void processSelectorReferences(ObjectiveC2_State state) throws Exception {
		state.monitor.setMessage("Objective-C 2.0 Selector References...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC2_Constants.OBJC2_SELECTOR_REFS);
		if (block == null) {
			return;
		}
		ObjectiveC1_Utilities.clear(state, block);

		long count = block.getSize() / state.pointerSize;

		state.monitor.initialize((int) count);

		Address address = block.getStart();

		for (int i = 0; i < count; ++i) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(i);
			ObjectiveC1_Utilities.createPointerAndReturnAddressBeingReferenced(state.program,
				address);
			address = address.add(state.pointerSize);
		}
	}

}
