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
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.objectiveC.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ObjectiveC1_ClassAnalyzer extends AbstractAnalyzer {
	private static final String DESCRIPTION =
		"An analyzer for extracting Objective-C class structure information.";
	private static final String NAME = "Objective-C Class";

	/* ************************************************************************** */
	/* ************************************************************************** */

	public ObjectiveC1_ClassAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS);
		setDefaultEnablement(true);
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		MemoryByteProvider provider =
			new MemoryByteProvider(program.getMemory(),
				program.getAddressFactory().getDefaultAddressSpace());

		BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

		ObjectiveC1_State state =
			new ObjectiveC1_State(program, monitor, ObjectiveC1_Constants.CATEGORY_PATH);

		try {
			processModules(state, reader);
			processProtocols(state, reader);

			ObjectiveC1_Utilities.createMethods(state);

			setDataAndRefBlocksReadOnly(state);
		}
		catch (Exception e) {
		}

		ObjectiveC1_Utilities.fixupReferences(state);

		return true;
	}

	private void setDataAndRefBlocksReadOnly(ObjectiveC1_State state) {
		Memory memory = state.program.getMemory();

		MemoryBlock dataBlock = memory.getBlock(ObjectiveC1_Constants.OBJC_SECTION_DATA);
		if (dataBlock != null) {
			dataBlock.setWrite(false);
		}

		MemoryBlock classRefsBlock = memory.getBlock(ObjectiveC1_Constants.OBJC_SECTION_CLASS_REFS);
		if (classRefsBlock != null) {
			classRefsBlock.setWrite(false);
		}

		MemoryBlock messageRefsBlock =
			memory.getBlock(ObjectiveC1_Constants.OBJC_SECTION_MESSAGE_REFS);
		if (messageRefsBlock != null) {
			messageRefsBlock.setWrite(false);
		}
	}

	public boolean canAnalyze(Program program) {
		return ObjectiveC1_Constants.isObjectiveC(program);
	}

	/* ************************************************************************** */
	/* ************************************************************************** */

	private void processModules(ObjectiveC1_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C Modules...");

		List<ObjectiveC1_Module> modules = parseModuleList(state, reader);

		state.monitor.initialize(modules.size());
		int progress = 0;

		for (ObjectiveC1_Module module : modules) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress(++progress);

			module.applyTo();
		}
	}

	private List<ObjectiveC1_Module> parseModuleList(ObjectiveC1_State state, BinaryReader reader) {
		List<ObjectiveC1_Module> modules = new ArrayList<ObjectiveC1_Module>();
		state.monitor.setMessage("Parsing Objective-C information...");
		try {
			MemoryBlock moduleInfoBlock =
				state.program.getMemory().getBlock(ObjectiveC1_Constants.OBJC_SECTION_MODULE_INFO);
			long moduleInfoStartIndex = moduleInfoBlock.getStart().getOffset();
			long moduleInfoEndIndex = moduleInfoBlock.getEnd().getOffset();

			state.monitor.initialize((int) (moduleInfoEndIndex - moduleInfoStartIndex));

			reader.setPointerIndex(moduleInfoStartIndex);
			while (reader.getPointerIndex() < moduleInfoEndIndex) {
				if (state.monitor.isCancelled()) {
					break;
				}
				modules.add(new ObjectiveC1_Module(state, reader));
				state.monitor.setProgress((int) (reader.getPointerIndex() - moduleInfoStartIndex));
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return modules;
	}

	private void processProtocols(ObjectiveC1_State state, BinaryReader reader) throws Exception {
		state.monitor.setMessage("Objective-C Protocols...");

		MemoryBlock block =
			state.program.getMemory().getBlock(ObjectiveC1_Constants.OBJC_SECTION_PROTOCOL);
		if (block == null) {
			return;
		}

		state.monitor.initialize((int) block.getSize());

		Address address = block.getStart();

		reader.setPointerIndex(block.getStart().getOffset());

		while (address.compareTo(block.getEnd()) < 0) {
			if (state.monitor.isCancelled()) {
				break;
			}
			state.monitor.setProgress((int) address.subtract(block.getStart()));

			ObjectiveC1_Protocol protocol = new ObjectiveC1_Protocol(state, reader);
			protocol.applyTo();

			address = address.add(ObjectiveC1_Protocol.SIZEOF);
		}
	}
}
