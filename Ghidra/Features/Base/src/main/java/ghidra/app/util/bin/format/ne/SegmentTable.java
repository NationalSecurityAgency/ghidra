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
package ghidra.app.util.bin.format.ne;

import java.io.IOException;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.address.SegmentedAddress;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.util.Conv;

/**
 * A class to represent the new-executable segment table.
 * 
 */
public class SegmentTable {
    private Segment [] segments;

	SegmentTable(FactoryBundledWithBinaryReader reader, SegmentedAddress baseAddr, short index,
			short segmentCount, short shiftAlignCount) throws IOException {
        long oldIndex = reader.getPointerIndex();
        reader.setPointerIndex(Conv.shortToInt(index));

        //create a value of the shift count...
        shiftAlignCount = (short)(0x01 << shiftAlignCount);

        int segmentCountInt = Conv.shortToInt(segmentCount);

        segments = new Segment[segmentCountInt];

		SegmentedAddressSpace space;
		int curSegment;
		if (baseAddr != null) {
			space = (SegmentedAddressSpace) baseAddr.getAddressSpace();
			curSegment = baseAddr.getSegment();
		}
		else {
			space = null;
			curSegment = 0;
		}
        for (int i = 0 ; i < segmentCountInt ; ++i) {
			segments[i] = new Segment(reader, shiftAlignCount, curSegment);
            int size = segments[i].getMinAllocSize() & 0xffff;
            if (size == 0) {
            	size = 0x10000;
            }
			if (space != null) {
				SegmentedAddress endAddr = space.getAddress(curSegment, size - 1);
				curSegment = space.getNextOpenSegment(endAddr);
			}
			else {
				curSegment += 1;
			}
        }

        reader.setPointerIndex(oldIndex);
    }

	/**
	 * Returns an array of the segments defined in this segment table.
	 * @return an array of the segments defined in this segment table
	 */
    public Segment [] getSegments() {
        return segments;
    }
}
