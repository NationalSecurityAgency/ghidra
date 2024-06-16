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
package ghidra.app.util.bin.format.swift;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.swift.types.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Parses marks up, and provide access to Swift type metadata 
 */
public class SwiftTypeMetadata {

	private Program program;
	private TaskMonitor monitor;
	private MessageLog log;

	private List<EntryPoint> entryPoints = new ArrayList<>();
	private List<BuiltinTypeDescriptor> builtinTypeDescriptors = new ArrayList<>();
	private Map<Long, FieldDescriptor> fieldDescriptors = new HashMap<>();
	private List<AssociatedTypeDescriptor> associatedTypeDescriptors = new ArrayList<>();
	private List<CaptureDescriptor> captureDescriptors = new ArrayList<>();
	private List<MultiPayloadEnumDescriptor> mpEnumDescriptors = new ArrayList<>();
	private Map<String, TargetTypeContextDescriptor> typeDescriptors = new HashMap<>();
	private List<TargetProtocolDescriptor> protocolDescriptors = new ArrayList<>();
	private List<TargetProtocolConformanceDescriptor> protocolConformanceDescriptors =
		new ArrayList<>();

	private List<SwiftStructureInfo> markupList = new ArrayList<>();

	/**
	 * Creates a new {@link SwiftTypeMetadata}
	 * 
	 * @param program The {@link Program}
	 * @param monitor A cancellable task monitor
	 * @param log The log
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public SwiftTypeMetadata(Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {
		this.program = program;
		this.monitor = monitor;
		this.log = log;

		parse();
	}

	/**
	 * {@return the entry points}
	 */
	public List<EntryPoint> getEntryPoints() {
		return entryPoints;
	}

	/**
	 * {@return the built-in type descriptors}
	 */
	public List<BuiltinTypeDescriptor> getBuiltinTypeDescriptors() {
		return builtinTypeDescriptors;
	}
	
	/**
	 * {@return the field descriptors}
	 */
	public Map<Long, FieldDescriptor> getFieldDescriptors() {
		return fieldDescriptors;
	}

	/**
	 * {@return the associated type descriptors}
	 */
	public List<AssociatedTypeDescriptor> getAssociatedTypeDescriptor() {
		return associatedTypeDescriptors;
	}

	/**
	 * {@return the capture descriptors}
	 */
	public List<CaptureDescriptor> getCaptureDescriptors() {
		return captureDescriptors;
	}

	/**
	 * {@return the multi-payload enum descriptors}
	 */
	public List<MultiPayloadEnumDescriptor> getMultiPayloadEnumDescriptors() {
		return mpEnumDescriptors;
	}

	/**
	 * {@return the type descriptors}
	 */
	public Map<String, TargetTypeContextDescriptor> getTargetTypeContextDescriptors() {
		return typeDescriptors;
	}

	/**
	 * {@return the target protocol descriptors}
	 */
	public List<TargetProtocolDescriptor> getTargetProtocolDescriptors() {
		return protocolDescriptors;
	}

	/**
	 * {@return the target protocol conformance descriptors}
	 */
	public List<TargetProtocolConformanceDescriptor> getTargetProtocolConformanceDescriptors() {
		return protocolConformanceDescriptors;
	}

	/**
	 * Parses the {@link SwiftTypeMetadata}
	 * 
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parse() throws IOException, CancelledException {
		try (ByteProvider provider =
			MemoryByteProvider.createDefaultAddressSpaceByteProvider(program, false)) {
			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());
			
			parseEntryPoints(SwiftSection.BLOCK_ENTRY, reader);
			parseBuiltinTypeDescriptors(SwiftSection.BLOCK_BUILTIN, reader);
			parseFieldDescriptors(SwiftSection.BLOCK_FIELDMD, reader);
			parseAssociatedTypeDescriptors(SwiftSection.BLOCK_ASSOCTY, reader);
			parseCaptureTypeDescriptors(SwiftSection.BLOCK_CAPTURE, reader);
			parseMultiPayloadEnumDescriptors(SwiftSection.BLOCK_MPENUM, reader);
			parseProtocolDescriptors(SwiftSection.BLOCK_PROTOCS, reader);
			parseProtocolConformanceDescriptors(SwiftSection.BLOCK_CONFORM, reader);
			parseTypeDescriptors(SwiftSection.BLOCK_TYPES, reader);
		}
	}

	/**
	 * Parses the entry point(s)
	 * 
	 * @param section The {@link SwiftSection} that contains the entry point(s)
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseEntryPoints(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift entry point(s)...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				monitor.checkCancelled();
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				EntryPoint entryPoint = new EntryPoint(reader);
				entryPoints.add(entryPoint);
				markupList.add(new SwiftStructureInfo(entryPoint,
					new SwiftStructureAddress(blockStart, null)));
			}
		}
		catch (IOException e) {
			log("Failed to parse entry point(s) from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link BuiltinTypeDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseBuiltinTypeDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift builtin type descriptors...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				int i = skipZeroEntries(reader, 0, block.getSize());
				while (i + BuiltinTypeDescriptor.SIZE <= block.getSize()) {
					monitor.checkCancelled();
					BuiltinTypeDescriptor descriptor = new BuiltinTypeDescriptor(reader);
					builtinTypeDescriptors.add(descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(blockStart.add(i), null)));
					i += BuiltinTypeDescriptor.SIZE;
					i = skipZeroEntries(reader, i, block.getSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse builtin type descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link FieldDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseFieldDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift field descriptors...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				int i = skipZeroEntries(reader, 0, block.getSize());
				while (i + FieldDescriptor.SIZE <= block.getSize()) {
					monitor.checkCancelled();
					FieldDescriptor descriptor = new FieldDescriptor(reader);
					fieldDescriptors.put(descriptor.getBase(), descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(blockStart.add(i), null)));
					List<FieldRecord> records = descriptor.getFieldRecords();
					i += FieldDescriptor.SIZE;
					for (int j = 0; j < records.size(); j++) {
						FieldRecord record = records.get(j);
						markupList.add(new SwiftStructureInfo(record,
							new SwiftStructureAddress(blockStart.add(i + j * FieldRecord.SIZE),
								null)));
					}
					i += descriptor.getNumFields() * FieldRecord.SIZE;
					i = skipZeroEntries(reader, i, block.getSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse field descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link AssociatedTypeDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseAssociatedTypeDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift associated type descriptors...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				int i = skipZeroEntries(reader, 0, block.getSize());
				while (i + AssociatedTypeDescriptor.SIZE <= block.getSize()) {
					monitor.checkCancelled();
					AssociatedTypeDescriptor descriptor = new AssociatedTypeDescriptor(reader);
					associatedTypeDescriptors.add(descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(blockStart.add(i), null)));
					List<AssociatedTypeRecord> records = descriptor.getAssociatedTypeRecords();
					i += AssociatedTypeDescriptor.SIZE;
					for (int j = 0; j < records.size(); j++) {
						AssociatedTypeRecord record = records.get(j);
						markupList.add(new SwiftStructureInfo(record,
							new SwiftStructureAddress(
								blockStart.add(i + j * AssociatedTypeRecord.SIZE), null)));
					}
					i += descriptor.getNumAssociatedTypes() * AssociatedTypeRecord.SIZE;
					i = skipZeroEntries(reader, i, block.getSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse associated type descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link CaptureDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseCaptureTypeDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift capture descriptors...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				int i = skipZeroEntries(reader, 0, block.getSize());
				while (i + CaptureDescriptor.SIZE <= block.getSize()) {
					monitor.checkCancelled();
					CaptureDescriptor descriptor = new CaptureDescriptor(reader);
					captureDescriptors.add(descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(blockStart.add(i), null)));
					List<CaptureTypeRecord> records = descriptor.getCaptureTypeRecords();
					i += CaptureDescriptor.SIZE;
					for (int j = 0; j < records.size(); j++) {
						CaptureTypeRecord record = records.get(j);
						markupList.add(new SwiftStructureInfo(record,
							new SwiftStructureAddress(
								blockStart.add(i + j * CaptureTypeRecord.SIZE), null)));
					}
					i += descriptor.getNumCaptureTypes() * CaptureTypeRecord.SIZE;
					List<MetadataSourceRecord> sourceRecords =
						descriptor.getMetadataSourceRecords();
					for (int j = 0; j < sourceRecords.size(); j++) {
						MetadataSourceRecord record = sourceRecords.get(j);
						markupList.add(new SwiftStructureInfo(record,
							new SwiftStructureAddress(
								blockStart.add(i + j * MetadataSourceRecord.SIZE), null)));
					}
					i += descriptor.getNumMetadataSources() * MetadataSourceRecord.SIZE;
					i = skipZeroEntries(reader, i, block.getSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse capture descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link MultiPayloadEnumDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseMultiPayloadEnumDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift multipayload enum descriptors...");
		monitor.setIndeterminate(true);
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockStart = block.getStart();
				reader.setPointerIndex(blockStart.getOffset());
				int i = skipZeroEntries(reader, 0, block.getSize());
				while (i < block.getSize()) {
					monitor.checkCancelled();
					MultiPayloadEnumDescriptor descriptor = new MultiPayloadEnumDescriptor(reader);
					mpEnumDescriptors.add(descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(blockStart.add(i), null)));
					i += MultiPayloadEnumDescriptor.SIZE + descriptor.getContentsSize();
					i = skipZeroEntries(reader, i, block.getSize());
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse multipayload enum descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link TargetProtocolDescriptor}s
	 * 
	 * @param section The section name that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseProtocolDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift protocol descriptors...");
		monitor.setIndeterminate(true);
		try {
			List<SwiftStructureAddress> addrPairs = parsePointerTable(section, reader);
			for (SwiftStructureAddress addrPair : addrPairs) {
				reader.setPointerIndex(addrPair.structAddr().getOffset());
				TargetProtocolDescriptor descriptor = new TargetProtocolDescriptor(reader);
				protocolDescriptors.add(descriptor);
				markupList.add(new SwiftStructureInfo(descriptor,
					new SwiftStructureAddress(addrPair.structAddr(), addrPair.pointerAddr())));
			}
		}
		catch (IOException e) {
			log("Failed to parse protocol descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses the {@link TargetProtocolConformanceDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseProtocolConformanceDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift protocol conformance descriptors...");
		monitor.setIndeterminate(true);
		try {
			List<SwiftStructureAddress> addrPairs = parsePointerTable(section, reader);
			for (SwiftStructureAddress addrPair : addrPairs) {
				reader.setPointerIndex(addrPair.structAddr().getOffset());
				TargetProtocolConformanceDescriptor descriptor =
					new TargetProtocolConformanceDescriptor(reader);
				protocolConformanceDescriptors.add(descriptor);
				markupList.add(new SwiftStructureInfo(descriptor,
					new SwiftStructureAddress(addrPair.structAddr(),
						addrPair.pointerAddr())));
			}
		}
		catch (IOException e) {
			log("Failed to parse protocol conformance descriptors from section '" + section +
				"'");
		}
	}

	/**
	 * Parses the {@link TargetTypeContextDescriptor}s
	 * 
	 * @param section The {@link SwiftSection} that contains the descriptors
	 * @param reader A {@link BinaryReader}
	 * @throws CancelledException if the user cancelled the operation
	 */
	private void parseTypeDescriptors(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		monitor.setMessage("Parsing Swift type descriptors...");
		monitor.setIndeterminate(true);
		try {
			List<SwiftStructureAddress> addrPairs = parsePointerTable(section, reader);
			for (SwiftStructureAddress addrPair : addrPairs) {
				reader.setPointerIndex(addrPair.structAddr().getOffset());
				long origIndex = reader.getPointerIndex();
				TargetTypeContextDescriptor descriptor = new TargetTypeContextDescriptor(reader);
				reader.setPointerIndex(origIndex);
				int contextDescriptorKind = ContextDescriptorKind.getKind(descriptor.getFlags());
				descriptor = switch (contextDescriptorKind) {
					case ContextDescriptorKind.CLASS:
						yield new TargetClassDescriptor(reader);
					case ContextDescriptorKind.STRUCT:
						yield new TargetStructDescriptor(reader);
					case ContextDescriptorKind.ENUM:
						yield new TargetEnumDescriptor(reader);
					default:
						log("Unrecognized type descriptor %d at index: 0x%x"
								.formatted(contextDescriptorKind, origIndex));
						yield null;
				};
				if (descriptor != null) {
					typeDescriptors.put(descriptor.getName(), descriptor);
					markupList.add(new SwiftStructureInfo(descriptor,
						new SwiftStructureAddress(addrPair.structAddr(), addrPair.pointerAddr())));
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse type descriptors from section '" + section + "'");
		}
	}

	/**
	 * Parses a table of pointers to {@link SwiftTypeMetadataStructure}s found in the given section
	 * 
	 * @param section The {@link SwiftSection} that contains the pointer table
	 * @param reader A {@link BinaryReader}
	 * @return A {@link List} of {@link SwiftStructureAddress}s
	 * @throws CancelledException if the user cancelled the operation
	 */
	private List<SwiftStructureAddress> parsePointerTable(SwiftSection section, BinaryReader reader)
			throws CancelledException {
		final int POINTER_SIZE = 4;
		List<SwiftStructureAddress> result = new ArrayList<>();
		try {
			for (MemoryBlock block : SwiftUtils.getSwiftBlocks(section, program)) {
				Address blockAddr = block.getStart();
				for (int i = 0; i < block.getSize(); i += POINTER_SIZE) {
					monitor.checkCancelled();
					reader.setPointerIndex(blockAddr.getOffset() + i);
					Address pointerAddr = blockAddr.add(i);
					int offset = reader.readInt(pointerAddr.getOffset());
					if (offset != 0) {
						Address structAddr = pointerAddr.add(offset);
						result.add(new SwiftStructureAddress(structAddr, pointerAddr));
					}
				}
			}
		}
		catch (IOException e) {
			log("Failed to parse Swift struction pointers from section '" + section + "'");
		}
		return result;
	}

	/**
	 * Marks up this {@link SwiftTypeMetadata} with data structures and comments
	 * 
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void markup() throws CancelledException {
		monitor.setMessage("Marking up Swift structures...");
		monitor.initialize(markupList.size());
		for (SwiftStructureInfo structInfo : markupList) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			try {
				SwiftTypeMetadataStructure struct = structInfo.struct();
				DataType dt = struct.toDataType();
				DataUtilities.createData(program, structInfo.addr().structAddr(), dt, -1,
					ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
				if (structInfo.addr().pointerAddr() != null) {
					PointerTypedef relativePtrDataType =
						new PointerTypedef(null, dt, 4, null, PointerType.RELATIVE);
					DataUtilities.createData(program, structInfo.addr().pointerAddr(),
						relativePtrDataType, -1, ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
				}
			}
			catch (CodeUnitInsertionException e) {
				// Probably just called more than once
			}
			catch (DuplicateNameException | IOException e) {
				log("Failed to markup: " + structInfo);
			}
		}
	}

	/**
	 * Reads past zeroed out entries in Swift type metadata sections
	 * 
	 * @param reader A {@link BinaryReader} positioned within a type metadata section
	 * @param offset The current offset from the start of the type metadata section
	 * @param size The size of the type metadata section (in bytes)
	 * @return The offset from the start of the type metadata section that contains the next
	 *   non-zero entry
	 * @throws IOException if an IO-related error occurred
	 */
	private int skipZeroEntries(BinaryReader reader, int offset, long size) throws IOException {
		while (offset + 8 <= size) {
			long possibleZero = reader.readNextLong();
			if (possibleZero != 0) {
				reader.setPointerIndex(reader.getPointerIndex() - 8);
				return offset;
			}
			offset += 8;
		}
		return offset;
	}

	/**
	 * Convenience method to perform logging
	 * 
	 * @param message The message to log
	 */
	private void log(String message) {
		log.appendMsg(SwiftTypeMetadata.class.getSimpleName(), message);
	}

	/**
	 * The {@link Address} of a {@link SwiftTypeMetadataStructure} and the optional {@link Address} 
	 * of its pointer
	 * 
	 * @param structAddr The {@link Address} of a {@link SwiftTypeMetadataStructure}
	 * @param pointerAddr The {@link Address} of a pointer to a {@link SwiftTypeMetadataStructure}
	 *   (could be null if there is no associated pointer}
	 */
	private record SwiftStructureAddress(Address structAddr, Address pointerAddr) {}

	/**
	 * Information about a {@link SwiftTypeMetadataStructure}
	 * 
	 * @param struct The {@link SwiftTypeMetadataStructure}
	 * @param addr The {@link SwiftStructureAddress address} of the 
	 *   {@link SwiftTypeMetadataStructure}
	 */
	private record SwiftStructureInfo(SwiftTypeMetadataStructure struct,
			SwiftStructureAddress addr) {

		@Override
		public String toString() {
			return "%s %s".formatted(struct.getDescription(), addr);
		}
	}
}
