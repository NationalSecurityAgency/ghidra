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

import java.io.ByteArrayInputStream;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

class IntelHexMemImage {
	private HashMap<AddressRange, byte[]> rangeMap = new HashMap<AddressRange, byte[]>();
	private AddressSet set = new AddressSet();
	private HashSet<Address> partitions = new HashSet<Address>();
	private AddressSpace space;
	private Address base;
	private long startEIP = -1;
	private int startCS = -1;
	private int startIP = -1;

	IntelHexMemImage(AddressSpace space, Address base) {
		this.base = base;
		this.space = space;
	}

	boolean hasDefinedBytes() {
		return !set.isEmpty();
	}

	void log(String line, String msg) {
		Msg.info(this, "line: " + line);
		Msg.info(this, "      " + msg + " (base " + base + ")");
	}

	String parseLine(String line) {
		String msg = null;

		try {
			IntelHexRecord record = IntelHexRecordReader.readRecord(line);
			if (!record.isReportedChecksumCorrect()) {
				msg = "WARNING: line checksum (is " + record.getReportedChecksum() +
					") not correct (should be " + record.getActualChecksum() + ")";
			}
			final int loadOffset = record.getLoadOffset();
			final byte[] data = record.getData();
			switch (record.getRecordType()) {
				case IntelHexRecord.DATA_RECORD_TYPE:
					final int rangeStartOffset = loadOffset;
					final int rangeEndOffset = loadOffset + data.length - 1;
					final Address rangeStart = base.addWrap(rangeStartOffset);
					final Address rangeEnd = base.addWrap(rangeEndOffset);
					if (rangeEnd.compareTo(rangeStart) < 0) {
						// split the range
						final long firstRangeEndOffset =
							findWrapPoint(rangeStartOffset, rangeEndOffset);
						final Address firstRangeEnd = base.addWrap(firstRangeEndOffset);
						final AddressRange firstRange =
							new AddressRangeImpl(rangeStart, firstRangeEnd);
						final int firstDataLength = (int) (firstRangeEndOffset - loadOffset + 1);
						final byte[] firstData = new byte[firstDataLength];
						System.arraycopy(data, 0, firstData, 0, firstDataLength);
						rangeMap.put(firstRange, firstData);
						set.add(firstRange);
						final Address secondRangeStart = firstRangeEnd.addWrap(1);
						final AddressRange secondRange =
							new AddressRangeImpl(secondRangeStart, rangeEnd);
						final int secondDataLength = data.length - firstDataLength;
						final byte[] secondData = new byte[secondDataLength];
						System.arraycopy(data, firstDataLength, secondData, 0, secondDataLength);
						rangeMap.put(secondRange, secondData);
						set.add(secondRange);
//                    log(line, "SPLIT data record, offset=" + loadOffset + ", length=" + data.length);
					}
					else {
						AddressRange range = new AddressRangeImpl(rangeStart, rangeEnd);
						rangeMap.put(range, data);
						set.add(range);
//                    log(line, "data record, offset=" + loadOffset + ", length=" + data.length);
					}
					break;
				case IntelHexRecord.END_OF_FILE_RECORD_TYPE:
					// nothing to do, we're at the end (or should we ensure further parses fail?)
//                log(line, "end of file");
					break;
				case IntelHexRecord.EXTENDED_LINEAR_ADDRESS_RECORD_TYPE:
					long newBaseLong = ub(data[0]) << 24 | ub(data[1]) << 16;
					base = space.getAddress(newBaseLong);
					partitions.add(base);
//					log(line, "extended linear address record, offset=" + loadOffset + ", length=" + data.length);
					break;
				case IntelHexRecord.EXTENDED_SEGMENT_ADDRESS_RECORD_TYPE:
					int newBaseSegment = ub(data[0]) << 8 | ub(data[1]);
					if (space instanceof SegmentedAddressSpace) {
						SegmentedAddressSpace sspace = (SegmentedAddressSpace) space;
						base = sspace.getAddress(newBaseSegment, 0);
					}
					else {
						newBaseSegment <<= 4;
						base = space.getAddress(newBaseSegment);
					}
					partitions.add(base);
//					log(line, "extended segment address record, offset=" + loadOffset + ", length=" + data.length);
					break;
				case IntelHexRecord.START_LINEAR_ADDRESS_RECORD_TYPE:
					startEIP =
						ub(data[0]) << 24 | ub(data[1]) << 16 | ub(data[2]) << 8 | ub(data[3]);
//                log(line, "start linear address record (startEIP=" + startEIP + "), offset=" + loadOffset + ", length=" + data.length);
					break;
				case IntelHexRecord.START_SEGMENT_ADDRESS_RECORD:
					startCS = ub(data[0]) << 8 | ub(data[1]);
					startIP = ub(data[2]) << 8 | ub(data[3]);
//                log(line, "start segment address record (startCS=" + startCS + ", startIP=" + startIP + "), offset=" + loadOffset + ", length=" + data.length);
					break;
				default:
					msg =
						"Impossible record type: " + record.getRecordType() + " " + record.format();
//                log(line, "INVALID RECORD TYPE " + record.getRecordType() + ", offset=" + loadOffset + ", length=" + data.length);
					break;
			}
		}
		catch (Exception e) {
			msg = e.getMessage();
		}

		return msg;
	}

	private int ub(byte b) {
		return b & 0xff;
	}

	private long findWrapPoint(int rangeStartOffset, int rangeEndOffset) {
		final Address rangeStart = base.addWrap(rangeStartOffset);
		int leftPtr = rangeStartOffset;
		int rightPtr = rangeEndOffset;
		while (leftPtr + 1 < rightPtr) {
			int midpoint = (leftPtr + rightPtr) / 2;
			final Address middle = base.addWrap(midpoint);
			if (middle.compareTo(rangeStart) < 0) {
				rightPtr = midpoint;
			}
			else {
				leftPtr = midpoint;
			}
		}
		return leftPtr;
	}

	long getStartEIP() {
		return startEIP;
	}

	int getStartCS() {
		return startCS;
	}

	int getStartIP() {
		return startIP;
	}

	String createMemory(String creator, String progFile, String blockName, boolean isOverlay,
			Program program, TaskMonitor monitor) throws AddressOverflowException {
		MessageLog log = new MessageLog();
		//this code is required to allow hex lines to not appear
		//in address order...
		int count = 0;
		AddressSetPartitioner partitioner = new AddressSetPartitioner(set, rangeMap, partitions);
		HashMap<AddressRange, byte[]> myRangeMap =
			new HashMap<AddressRange, byte[]>(partitioner.getPartionedRangeMap());
		for (AddressRange blockRange : partitioner) {
			Iterator<AddressRange> iter = myRangeMap.keySet().iterator();
			HashSet<AddressRange> blockSet = new HashSet<AddressRange>();
			while (iter.hasNext()) {
				AddressRange range = iter.next();
				if (blockRange.intersects(range)) {
					blockSet.add(range);
				}
			}
			boolean[] filled = new boolean[(int) blockRange.getLength()];
			byte[] data = new byte[(int) blockRange.getLength()];
			for (AddressRange range : blockSet) {
				byte[] rangeBytes = myRangeMap.get(range);
				int pos = (int) range.getMinAddress().getOffset() -
					(int) blockRange.getMinAddress().getOffset();
				rangeCheck(rangeBytes, 0, data, pos, rangeBytes.length);
				System.arraycopy(rangeBytes, 0, data, pos, rangeBytes.length);
				for (int jj = 0; jj < rangeBytes.length; ++jj) {
					if (filled[pos + jj]) {
						System.err.println("OVERWRITE!");
					}
					filled[pos + jj] = true;
				}
				myRangeMap.remove(range);
			}

			String name = blockName == null ? base.getAddressSpace().getName() : blockName;
			MemoryBlockUtils.createInitializedBlock(program, isOverlay, name,
				blockRange.getMinAddress(), new ByteArrayInputStream(data), data.length,
				"Generated by " + creator, progFile, true, !isOverlay, !isOverlay, log, monitor);
		}
		return log.toString();
	}

	private static void rangeCheck(byte[] src, int srcPos, byte[] dest, int destPos, int length) {
		if (srcPos + length > src.length) {
			throw new IllegalArgumentException("src range check failed");
		}
		if (destPos + length > dest.length) {
			throw new IllegalArgumentException("dest range check failed");
		}
	}

	String createMemory(String creator, String progFile, Program program, TaskMonitor monitor)
			throws AddressOverflowException {

		return createMemory(creator, progFile, null, false, program, monitor);
	}

	void setBaseAddr(Address address) {
		base = address;
	}
}
