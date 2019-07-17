/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.util.*;

import java.io.*;

/**
 * A class to represent the Object Module Format (OMF) Source Module Line data structure.
 * <br>
 * short seg            - segment index.
 * <br>
 * short cPair          - Count or number of source line pairs to follow.
 * <br>
 * int [] offsets       - offset within the code segment of the start of the line.
 * <br>
 * short [] linenumbers - line numbers that are in the source file that cause code to be emitted to the code segment.
 * <br>
 **/
public class OMFSrcModuleLine {

    private short seg;
	private short cPair;
	private int [] offsets;
	private short [] linenumbers;

    static OMFSrcModuleLine createOMFSrcModuleLine(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFSrcModuleLine omfSrcModuleLine = (OMFSrcModuleLine) reader.getFactory().create(OMFSrcModuleLine.class);
        omfSrcModuleLine.initOMFSrcModuleLine(reader, ptr);
        return omfSrcModuleLine;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSrcModuleLine() {}

	private void initOMFSrcModuleLine(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		int index = ptr;
		
		seg   = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		cPair = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		
		offsets = new int[Conv.shortToInt(cPair)];
		for (int i = 0 ; i < Conv.shortToInt(cPair) ; ++i) {
			offsets[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}
		
		linenumbers = new short[Conv.shortToInt(cPair)];
		for (int i = 0 ; i < Conv.shortToInt(cPair) ; ++i) {
			linenumbers[i] = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		}
	}

	/**
	 * Returns the count or number of source line pairs to follow.
	 * @return the count or number of source line pairs to follow
	 */
	public short getPairCount() {
		return cPair;
	}

	/**
	 * Returns the line numbers that are in the source file that cause code to be emitted to the code segment.
	 * @return the line numbers that are in the source file that cause code to be emitted to the code segment
	 */
	public short[] getLinenumbers() {
		return linenumbers;
	}

	/**
	 * Returns the offset within the code segment of the start of the line.
	 * @return the offset within the code segment of the start of the line
	 */
	public int[] getOffsets() {
		return offsets;
	}

	/**
	 * Returns the segment index.
	 * @return the segment index
	 */
	public short getSegmentIndex() {
		return seg;
	}

	int getByteCount() {
		return BinaryReader.SIZEOF_SHORT
				+BinaryReader.SIZEOF_SHORT
				+BinaryReader.SIZEOF_INT*cPair
				+BinaryReader.SIZEOF_SHORT*cPair;
	}

}
