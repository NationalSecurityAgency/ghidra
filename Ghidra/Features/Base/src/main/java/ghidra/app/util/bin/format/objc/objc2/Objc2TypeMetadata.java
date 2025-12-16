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
package ghidra.app.util.bin.format.objc.objc2;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.macho.dyld.LibObjcOptimization;
import ghidra.app.util.bin.format.objc.*;
import ghidra.app.util.bin.format.objc.objc1.Objc1Constants;
import ghidra.app.util.bin.format.objc.objc1.Objc1TypeMetadata;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Objc2TypeMetadata extends AbstractObjcTypeMetadata {

	/**
	 * Creates a new {@link Objc2TypeMetadata}
	 * 
	 * @param program The {@link Program}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public Objc2TypeMetadata(Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		super(new ObjcState(program, Objc2Constants.CATEGORY_PATH), program, monitor, log);
		parse();
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

			// Create a map of Objective-C specific memory blocks.  If this is a dyld_shared_cache
			// file, there will be many of each type.
			Map<String, List<MemoryBlock>> objcBlockMap =
				Arrays.stream(program.getMemory().getBlocks())
						.filter(b -> b.getName().startsWith(Objc2Constants.OBJC2_PREFIX))
						.collect(Collectors.groupingBy(MemoryBlock::getName));

			parseLibObjcOptimization(LibObjcOptimization.SECTION_NAME, objcBlockMap);
			parseRefs(Objc2Constants.OBJC2_CLASS_REFS, refs, objcBlockMap);
			parseRefs(Objc2Constants.OBJC2_SUPER_REFS, refs, objcBlockMap);
			parseRefs(Objc2Constants.OBJC2_PROTOCOL_REFS, refs, objcBlockMap);
			parseRefs(Objc2Constants.OBJC2_SELECTOR_REFS, refs, objcBlockMap);
			parseRefs(Objc2Constants.OBJC2_NON_LAZY_CLASS_LIST, refs, objcBlockMap);
			parseImageInfo(Objc2Constants.OBJC2_IMAGE_INFO, reader, objcBlockMap);
			parseCategoryList(Objc2Constants.OBJC2_CATEGORY_LIST, reader, objcBlockMap);
			parseClassList(Objc2Constants.OBJC2_CLASS_LIST, reader, objcBlockMap);
			parseProtocolList(Objc2Constants.OBJC2_PROTOCOL_LIST, reader, objcBlockMap);
			parseMessageReferences(Objc2Constants.OBJC2_MESSAGE_REFS, reader, objcBlockMap);
		}
	}

	private Set<Address> refs = new HashSet<>();
	private List<Objc2ImageInfo> imageInfos = new ArrayList<>();
	private List<Objc2Category> categories = new ArrayList<>();
	private List<Objc2Class> classes = new ArrayList<>();
	private List<Objc2Protocol> protocols = new ArrayList<>();
	private List<Objc2MessageReference> messageRefs = new ArrayList<>();

	private void parseRefs(String section, Set<Address> set,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Parsing Objective-C %s references...".formatted(section));
		for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
			long count = block.getSize() / program.getDefaultPointerSize();
			monitor.initialize((int) count);
			Address address = block.getStart();
			for (int i = 0; i < count; ++i) {
				monitor.increment();
				set.add(address);
				address = address.add(program.getDefaultPointerSize());
			}
		}
	}

	private void parseImageInfo(String section, BinaryReader reader,
			Map<String, List<MemoryBlock>> objcBlockMap) throws IOException {
		monitor.setMessage("Parsing Objective-C image infos...");
		for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
			Address address = block.getStart();
			reader.setPointerIndex(address.getOffset());
			imageInfos.add(new Objc2ImageInfo(program, state, reader));
		}
	}

	private void parseCategoryList(String section, BinaryReader reader,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Objective-C categories...");
		try {
			for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
				long count = block.getSize() / program.getDefaultPointerSize();
				monitor.initialize((int) count);
				Address address = block.getStart();
				for (int i = 0; i < count; ++i) {
					monitor.increment();
					long categoryAddress =
						program.getDefaultPointerSize() == 4
								? reader.readUnsignedInt(address.getOffset())
								: reader.readLong(address.getOffset());
					reader.setPointerIndex(categoryAddress);
					categories.add(new Objc2Category(program, state, reader));
					refs.add(address);
					address = address.add(program.getDefaultPointerSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse Objective-C categeory from section '" + section + "'");
		}
	}

	private void parseClassList(String section, BinaryReader reader,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Objective-C classes...");
		try {
			for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
				long count = block.getSize() / program.getDefaultPointerSize();
				monitor.initialize((int) count);
				Address address = block.getStart();
				for (int i = 0; i < count; ++i) {
					monitor.increment();
					long classAddress =
						program.getDefaultPointerSize() == 4
								? reader.readUnsignedInt(address.getOffset())
								: reader.readLong(address.getOffset());
					reader.setPointerIndex(classAddress);
					classes.add(new Objc2Class(program, state, reader));
					refs.add(address);
					address = address.add(program.getDefaultPointerSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse Objective-C class from section '" + section + "'");
		}
	}

	private void parseProtocolList(String section, BinaryReader reader,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Objective-C protocols...");
		try {
			for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
				long count = block.getSize() / program.getDefaultPointerSize();
				monitor.initialize((int) count);
				Address address = block.getStart();
				for (int i = 0; i < count; ++i) {
					monitor.increment();
					long protocolAddress =
						program.getDefaultPointerSize() == 4
								? reader.readUnsignedInt(address.getOffset())
								: reader.readLong(address.getOffset());
					reader.setPointerIndex(protocolAddress);
					Objc2Protocol protocol = new Objc2Protocol(program, state, reader);
					protocols.add(protocol);
					refs.add(address);
					address = address.add(program.getDefaultPointerSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse Objective-C protocol from section '" + section + "'");
		}
	}

	private void parseMessageReferences(String section, BinaryReader reader,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Objective-C message references...");
		try {
			for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
				long count =
					block.getSize() / Objc2MessageReference.SIZEOF(program.getDefaultPointerSize());
				monitor.initialize((int) count);
				Address address = block.getStart();
				for (int i = 0; i < count; ++i) {
					monitor.increment();
					reader.setPointerIndex(address.getOffset());
					messageRefs.add(new Objc2MessageReference(program, state, reader));
					address =
						address.add(Objc2MessageReference.SIZEOF(program.getDefaultPointerSize()));
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse Objective-C message reference from section '" + section + "'");
		}
	}

	private void parseLibObjcOptimization(String section,
			Map<String, List<MemoryBlock>> objcBlockMap) throws CancelledException {
		monitor.setMessage("Parsing Objective-C libObjc optimizations...");
		try {
			for (MemoryBlock block : objcBlockMap.getOrDefault(section, List.of())) {
				monitor.checkCancelled();
				state.libObjcOptimization = new LibObjcOptimization(program, block.getStart());
			}
		}
		catch (IOException e) {
			log("Failed to parse Objective-C libObjc optimizations from section '" + section + "'");
		}
	}

	@Override
	public void applyTo() {
		for (Address addr : refs) {
			try {
				DataUtilities.createData(program, addr, new PointerDataType(), -1,
					DataUtilities.ClearDataMode.CLEAR_SINGLE_DATA);
			}
			catch (Exception e) {
				log("Failed to create pointer at " + addr);
			}
		}
		for (Objc2ImageInfo imageInfo : imageInfos) {
			try {
				imageInfo.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup image info: " + imageInfo);
			}
		}
		for (Objc2Category category : categories) {
			try {
				category.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup category: " + category);
			}
		}
		for (Objc2Class cls : classes) {
			try {
				cls.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup class: " + cls);
			}
		}
		for (Objc2Protocol protocol : protocols) {
			try {
				Namespace namespace = ObjcUtils.createNamespace(program,
					Objc1Constants.NAMESPACE, "Protocols", protocol.getName());
				protocol.applyTo(namespace, monitor);
			}
			catch (Exception e) {
				log("Failed to markup protocol: " + protocol);
			}
		}
		for (Objc2MessageReference messageRef : messageRefs) {
			try {
				messageRef.applyTo(program.getGlobalNamespace(), monitor);
			}
			catch (Exception e) {
				log("Failed to markup message reference: " + messageRef);
			}
		}

		ObjcUtils.createMethods(program, state, log, monitor);
		ObjcUtils.fixupReferences(Objc2Constants.getObjectiveC2SectionNames(), program, monitor);
		createInstanceVariables();

		ObjcUtils.setBlocksReadOnly(program.getMemory(), List.of(
			Objc2Constants.OBJC2_DATA,
			Objc2Constants.OBJC2_CLASS_REFS,
			Objc2Constants.OBJC2_MESSAGE_REFS,
			Objc2Constants.OBJC2_SELECTOR_REFS,
			Objc2Constants.OBJC2_SUPER_REFS,
			Objc2Constants.OBJC2_PROTOCOL_REFS));
	}

	/**
	 * Creates instance variables
	 */
	private void createInstanceVariables() {
		monitor.initialize(state.variableMap.size(), "Creating Objective-C Instance Variables...");
		for (Address address : state.variableMap.keySet()) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.incrementProgress();
			Objc2InstanceVariable variable = state.variableMap.get(address);
			try {
				state.encodings.processInstanceVariableSignature(program, address,
					variable.getType(), variable.getSize());
			}
			catch (Exception e) {
				log("Unhandled instance variable signature: " + e.getMessage());
			}
		}
	}
}
