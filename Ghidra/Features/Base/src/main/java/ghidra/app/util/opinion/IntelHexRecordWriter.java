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

import java.util.*;

import ghidra.program.model.address.*;

public class IntelHexRecordWriter {

    private final int maxBytesPerLine;
	private final boolean dropExtraBytes;

    private Address startAddress = null;
    private Long oldSegment = null;
	private ArrayList<Byte> bytes = new ArrayList<>();
    private Boolean isSegmented = null;

	private ArrayList<IntelHexRecord> results = new ArrayList<>();
    private boolean done = false;

	/**
	 * Constructor
	 * 
	 * @param maxBytesPerLine the maximum number of bytes to write per line in the hex output
	 * @param dropExtraBytes if true, only lines matching {@link #maxBytesPerLine} will be output; 
	 * remaining bytes will be left out
	 */
	public IntelHexRecordWriter(int maxBytesPerLine, boolean dropExtraBytes) {
        if (maxBytesPerLine > IntelHexRecord.MAX_RECORD_LENGTH) {
            throw new IllegalArgumentException("maxBytesPerLine > IntelHexRecord.MAX_RECORD_LENGTH");
        }
        this.maxBytesPerLine = maxBytesPerLine;
		this.dropExtraBytes = dropExtraBytes;
    }

    public void addByte(Address address, byte b) {
        if (done) {
            throw new IllegalStateException("cannot addByte() after finish()");
        }

        if (isSegmented == null) {
            if (address.getAddressSpace() instanceof SegmentedAddressSpace) {
                isSegmented = true;
            } else {
                isSegmented = false;
            }
        }

        long offset;
        long newSegment;
        if (isSegmented) {
            offset = ((SegmentedAddress)address).getSegmentOffset();
            newSegment = ((SegmentedAddress)address).getSegment();
        } else {
            offset = address.getOffset();
            newSegment = offset & 0xffff0000;
        }
        boolean changeSegment = false;

        if (oldSegment == null) {
            changeSegment = true;
        } else {
            if (newSegment != oldSegment) {
                changeSegment = true;
            }
        }

        if (changeSegment) {
            emitData();
            byte[] data = new byte[2];
            if (isSegmented) {
                SegmentedAddress saddress = (SegmentedAddress) address;
                int segment = saddress.getSegment();
                data[0] = (byte) ((segment >> 8) & 0xff);
                data[1] = (byte) (segment & 0xff);
                results.add(new IntelHexRecord(2, 0, 2, data));
            } else {
                data[0] = (byte) ((offset >> 24) & 0xff);
                data[1] = (byte) ((offset >> 16) & 0xff);
                results.add(new IntelHexRecord(2, 0, 4, data));
            }
            oldSegment = newSegment;
        }

        if (startAddress == null) {
            startAddress = address;
        }

        bytes.add(b);

        if (bytes.size() >= maxBytesPerLine) {
            emitData();
        }
    }

    private void emitData() {
        final int length = bytes.size();
        if (length > 0) {
            int loadOffset;
            if (isSegmented) {
				loadOffset = ((SegmentedAddress) startAddress).getSegmentOffset();
            } else {
                loadOffset = (int) (startAddress.getOffset() & 0x0000ffff);
            }
            byte[] data = new byte[length];
            for (int ii = 0; ii < length; ++ii) {
                data[ii] = bytes.get(ii);
            }
            results.add(new IntelHexRecord(length, loadOffset, 0, data));
            bytes.clear();
            startAddress = null;
        }
    }

    public List<IntelHexRecord> finish(Address entryPoint) {

		// Before finalizing things, write out any remaining bytes that haven't yet been written, if
		// the user has specified to do so via the drop extra bytes option (false = 
    	// write out everything).
		if (bytes.size() > 0 && !dropExtraBytes) {
			emitData();
		}

        if (entryPoint != null && isSegmented != null) {
            final long offset = entryPoint.getOffset();
            byte[] data = new byte[4];
            data[2] = (byte) ((offset >> 8) & 0xff);
            data[3] = (byte) (offset & 0xff);
            if (isSegmented) {
                SegmentedAddress saddress = (SegmentedAddress) entryPoint;
                int segment = saddress.getSegment();
                data[0] = (byte) ((segment >> 8) & 0xff);
                data[1] = (byte) (segment & 0xff);
                results.add(new IntelHexRecord(4, 0, 3, data));
            } else {
                data[0] = (byte) ((offset >> 24) & 0xff);
                data[1] = (byte) ((offset >> 16) & 0xff);
                results.add(new IntelHexRecord(4, 0, 5, data));
            }
        }
        results.add(new IntelHexRecord(0, 0, 1, new byte[0]));
        done = true;
        return Collections.unmodifiableList(results);
    }
}
