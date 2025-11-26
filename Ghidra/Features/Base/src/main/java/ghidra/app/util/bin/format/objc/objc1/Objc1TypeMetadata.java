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
package ghidra.app.util.bin.format.objc.objc1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.objc.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Objc1TypeMetadata extends AbstractObjcTypeMetadata {

	private List<Objc1Module> modules = new ArrayList<>();
	private List<Objc1Protocol> protocols = new ArrayList<>();

	/**
	 * Creates a new {@link Objc1TypeMetadata}
	 * 
	 * @param program The {@link Program}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public Objc1TypeMetadata(Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		super(new ObjcState(program, Objc1Constants.CATEGORY_PATH), program, monitor, log);
		parse();
	}

	/**
	 * {@return a {@link List} of {@link Objc1Module modules}}
	 */
	public List<Objc1Module> getModules() {
		return modules;
	}

	/**
	 * {@return a {@link List} of {@link Objc1Protocol protocols}}
	 */
	public List<Objc1Protocol> getProtocols() {
		return protocols;
	}

	/**
	 * Parses the {@link Objc1TypeMetadata}
	 * 
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parse() throws IOException, CancelledException {
		try (MemoryByteProvider provider =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false)) {
			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
		
			parseModules(Objc1Constants.OBJC_SECTION_MODULE_INFO, reader);
			parseProtocols(Objc1Constants.OBJC_SECTION_PROTOCOL, reader);
		}
	}

	private void parseModules(String section, BinaryReader reader) throws CancelledException {
		monitor.setMessage("Parsing Objective-C modules...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : ObjcUtils.getObjcBlocks(section, program)) {
				long start = block.getStart().getOffset();
				long end = block.getEnd().getOffset();
				reader.setPointerIndex(start);
				while (reader.getPointerIndex() < end) {
					monitor.checkCancelled();
					modules.add(new Objc1Module(program, state, reader));
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse modules from section '" + section + "'");
		}
	}

	private void parseProtocols(String section, BinaryReader reader) throws CancelledException {
		monitor.setMessage("Parsing Objective-C protocols...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : ObjcUtils.getObjcBlocks(section, program)) {
				long start = block.getStart().getOffset();
				long end = block.getEnd().getOffset();
				reader.setPointerIndex(start);
				while (reader.getPointerIndex() < end) {
					monitor.checkCancelled();
					protocols.add(new Objc1Protocol(program, state, reader));
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse protocols from section '" + section + "'");
		}
	}

	@Override
	public void applyTo() {
		for (Objc1Module module : modules) {
			try {
				module.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup module: " + module.getName());
			}
		}
		for (Objc1Protocol protocol : protocols) {
			try {
				protocol.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup protocol: " + protocol.getName());
			}
		}

		ObjcUtils.createMethods(program, state, log, monitor);
		ObjcUtils.fixupReferences(Objc1Constants.getObjectiveCSectionNames(), program, monitor);

		ObjcUtils.setBlocksReadOnly(program.getMemory(), List.of(
			Objc1Constants.OBJC_SECTION_DATA,
			Objc1Constants.OBJC_SECTION_CLASS_REFS,
			Objc1Constants.OBJC_SECTION_MESSAGE_REFS));
	}
}
