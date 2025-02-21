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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.omf.*;
import ghidra.app.util.bin.format.omf.omf51.*;
import ghidra.app.util.bin.format.omf.omf51.Omf51FixupRecord.Omf51Fixup;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link Loader} for OMF-51 files
 */
public class Omf51Loader extends AbstractProgramWrapperLoader {
	public final static String OMF51_NAME = "Object Module Format (OMF-51)";
	public final static long MIN_BYTE_LENGTH = 11;

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < MIN_BYTE_LENGTH) {
			return loadSpecs;
		}

		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			OmfRecord first = factory.readNextRecord();
			if (factory.getStartRecordTypes().contains(first.getRecordType()) &&
				first.validCheckSum()) {
				List<QueryResult> results = QueryOpinionService.query(getName(), "8051", null);
				for (QueryResult result : results) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			}
		}
		catch (IOException | OmfException e) {
			// that's ok, not an OMF-51
		}
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws IOException, CancelledException {

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		AbstractOmfRecordFactory factory = new Omf51RecordFactory(provider);
		try {
			List<OmfRecord> records = OmfUtils.readRecords(factory);
			Map<Integer, Address> segmentToAddr =
				processMemoryBlocks(program, fileBytes, records, log, monitor);
			performFixups(program, fileBytes, records, segmentToAddr, log, monitor);
			markupRecords(program, fileBytes, records, log, monitor);
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	private Map<Integer, Address> processMemoryBlocks(Program program, FileBytes fileBytes,
			List<OmfRecord> records, MessageLog log, TaskMonitor monitor) throws Exception {

		// Gather all segments for processing, putting the absolute segments (id == 0) first since
		// they are not flexible about where they get placed
		List<Omf51Segment> segments = OmfUtils.filterRecords(records, Omf51SegmentDefs.class)
				.map(Omf51SegmentDefs::getSegments)
				.flatMap(List::stream)
				.sorted((a, b) -> Integer.compare(a.id(), b.id())) // absolute (id=0) comes first
				.toList();

		// Group all of a segment's content records together
		Map<Integer, List<Omf51Content>> contentMap =
			OmfUtils.filterRecords(records, Omf51Content.class)
					.collect(Collectors.groupingBy(Omf51Content::getSegId));
		
		// Create some data structures that will aid in segment relocation:
		//   - A set of addresses currently in use, so we can find holes for new segments in the
		//     address space
		//   - A map to keep track of segment's size, since segments with different ID's but the
		//     same name and type must be adjacent
		//   - A map to keep track of where same-named segments currently ends, so the next
		//     same-named segment can easily know where to go
		// NOTE: The key for these maps needs to include both the segment name and the type
		AddressSet usedAddresses = new AddressSet();
		Map<String, Integer> segmentSizes = new HashMap<>();
		Map<String, Address> segmentEnds = new HashMap<>();
		for (Omf51Segment segment : segments) {
			segmentSizes.compute(key(segment),
				(k, v) -> (v == null ? segment.size() : v + segment.size()));
		}

		// We will be returning a map of segment ID's to starting address, for use when we later
		// perform fixups within the content
		Map<Integer, Address> segmentToAddr = new HashMap<>();

		for (Omf51Segment segment : segments) {
			List<Omf51Content> segmentContent = contentMap.get(segment.id());
			String blockName = segment.isAbsolute() ? "<ABSOLUTE>" : segment.name().str();
			if (blockName.isBlank()) {
				blockName = "<NONAME>";
			}
			AddressSpace space = getAddressSpace(program, segment);
			Address segmentAddr;
			if (segmentContent != null) {
				segmentAddr = findAddr(segment, segmentSizes, segmentEnds, space, usedAddresses);
				for (Omf51Content content : segmentContent) {
					Address contentAddr =
						segment.isAbsolute() ? space.getAddress(content.getOffset())
								: segmentAddr.add(content.getOffset());
					try {
						MemoryBlockUtils.createInitializedBlock(program, false, blockName,
							contentAddr, fileBytes, content.getDataIndex(), content.getDataSize(),
							"", space.getName(), true, !segment.isCode(), segment.isCode(), log);
					}
					catch (Exception e) {
						log.appendMsg(e.getMessage());
					}
				}
			}
			else {
				segmentAddr = findAddr(segment, segmentSizes, segmentEnds, space, usedAddresses);
				MemoryBlockUtils.createUninitializedBlock(program, false, blockName, segmentAddr,
					segment.size(), "", space.getName(), true, true, false, log);
			}
			if (segment.isCode()) {
				AbstractProgramLoader.markAsFunction(program, blockName, segmentAddr);
			}
			segmentToAddr.put(segment.id(), segmentAddr);
		}
		return segmentToAddr;
	}

	private void performFixups(Program program, FileBytes fileBytes, List<OmfRecord> records,
			Map<Integer, Address> segmentToAddr, MessageLog log, TaskMonitor monitor)
			throws Exception {
		OmfRecord previous = null;
		for (OmfRecord record : records) {
			if (record instanceof Omf51FixupRecord fixupRec) {
				if (!(previous instanceof Omf51Content content)) {
					throw new Exception("Record prior to fixup is not content!");
				}
				Address segmentAddr = segmentToAddr.get(content.getSegId());
				if (segmentAddr == null) {
					throw new Exception("Failed to get lookup segment ID 0x%x for content fixup!"
							.formatted(content.getSegId()));
				}
				for (Omf51Fixup fixup : fixupRec.getFixups()) {
					Address fixupAddr = segmentAddr.add(fixup.refLoc());
					program.getRelocationTable()
							.add(fixupAddr, Status.UNSUPPORTED, fixup.refType(),
								new long[] { fixup.operand() }, 0, null);
				}
			}
			previous = record;
		}
	}

	private void markupRecords(Program program, FileBytes fileBytes, List<OmfRecord> records,
			MessageLog log, TaskMonitor monitor) {
		monitor.setMessage("Marking up records...");
		int size = records.stream().mapToInt(r -> r.getRecordLength() + 3).sum();
		try {
			Address recordSpaceAddr = AddressSpace.OTHER_SPACE.getAddress(0);
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"RECORDS", recordSpaceAddr, fileBytes, 0, size, "", "", false, false, false, log);
			Address start = headerBlock.getStart();

			for (OmfRecord record : records) {
				try {
					Data d = DataUtilities.createData(program, start.add(record.getRecordOffset()),
						record.toDataType(), -1, DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
					StructConverter.setEndian(d, false);
				}
				catch (Exception e) {
					log.appendMsg("Failed to markup record type 0x%x at offset 0x%x. %s."
							.formatted(record.getRecordType(), record.getRecordOffset(),
								e.getMessage()));
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Failed to markup records: " + e.getMessage());
		}
	}

	private Address findAddr(Omf51Segment segment, Map<String, Integer> segmentSizes,
			Map<String, Address> segmentEnds, AddressSpace space, AddressSet usedAddresses)
			throws Exception {
		return switch (segment.relType()) {
			case Omf51Segment.ABS: {
				if (segment.id() != 0) {
					throw new Exception("Absolute segment does not have ID 0!");
				}
				Address start = space.getAddress(segment.base());
				Address end = start.add(segment.size());
				if (usedAddresses.intersects(start, end)) {
					throw new Exception("Absolute segment overlaps with existing segment!");
				}
				usedAddresses.add(start, end);
				yield start;
			}
			case Omf51Segment.UNIT: {
				Address lastEnd = segmentEnds.get(key(segment));
				if (lastEnd != null) {
					Address start = lastEnd.add(1);
					Address end = start.add(segment.size() - 1);
					segmentEnds.put(key(segment), end);
					yield start;
				}
				Address start = space.getMinAddress();
				Address end = start.add(segment.size() - 1);
				int requiredSize = segmentSizes.get(key(segment));
				AddressSet intersection =
					usedAddresses.intersectRange(start, start.add(requiredSize - 1));
				while (!intersection.isEmpty()) {
					start = intersection.getMaxAddress().add(1);
					end = start.add(segment.size() - 1);
					intersection = usedAddresses.intersectRange(start, start.add(requiredSize - 1));
				}
				usedAddresses.add(start, start.add(requiredSize - 1));
				segmentEnds.put(key(segment), end);
				yield start;
			}
			case Omf51Segment.BITADDRESSABLE:
			case Omf51Segment.INPAGE:
			case Omf51Segment.INBLOCK:
			case Omf51Segment.PAGE:
			default:
				throw new Exception(
					"Skipping segment '%s'. Relocation type 0x%x is not yet supported"
							.formatted(segment.name(), segment.relType()));
		};
	}

	private AddressSpace getAddressSpace(Program program, Omf51Segment segment) throws Exception {
		return program.getAddressFactory().getAddressSpace(switch (segment.getType()) {
			case Omf51Segment.CODE -> "CODE";
			case Omf51Segment.XDATA -> "EXTMEM";
			case Omf51Segment.DATA -> "INTMEM";
			case Omf51Segment.IDATA -> "INTMEM";
			case Omf51Segment.BIT -> "BITS";
			default -> throw new Exception(
				"Unsupported address space: 0x%x".formatted(segment.getType()));
		});
	}

	private String key(Omf51Segment segment) {
		return segment.name().str() + "_" + segment.getType();
	}

	@Override
	public String getName() {
		return OMF51_NAME;
	}
}
