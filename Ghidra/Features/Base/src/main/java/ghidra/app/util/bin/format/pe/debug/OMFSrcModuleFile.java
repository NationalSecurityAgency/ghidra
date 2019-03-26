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
import java.util.*;

/**
 * A class to represent the Object Module Format (OMF) Source Module File data structure. 
 * <br>
 * This class describes the code segments that receive code from a source file.
 * <br>
 * short cSeg 		- Number of segments that receive code from the source file.
 * <br>
 * short pad 		- pad field to maintain alignment
 * <br>
 * int [] baseSrcLn - array of offsets for the line or address mapping for each segment that receives code from the source file.
 * <br>
 * int [] starts 	- starting addresses within the segment of the first byte of code from the module.
 * <br>
 * int [] ends 		- ending addresses of the code from the module.
 * <br>
 * byte cbName 		- count or number of bytes in source file name.
 * <br>
 * String name 		- name of source file.
 * <br>
 */
public class OMFSrcModuleFile {

    private short cSeg;
	private short pad;
	private int [] baseSrcLn;
	private int [] starts;
	private int [] ends;
	private byte cbName;
	private String name;

	private ArrayList<OMFSrcModuleLine> moduleLineList = new ArrayList<OMFSrcModuleLine>();

    static OMFSrcModuleFile createOMFSrcModuleFile(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFSrcModuleFile omfSrcModuleFile = (OMFSrcModuleFile) reader.getFactory().create(OMFSrcModuleFile.class);
        omfSrcModuleFile.initOMFSrcModuleFile(reader, ptr);
        return omfSrcModuleFile;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSrcModuleFile() {}

	private void initOMFSrcModuleFile(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		int index = ptr;

		cSeg = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		pad  = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;

		baseSrcLn = new int[Conv.shortToInt(cSeg)];
		for (int i = 0 ; i < cSeg ; ++i) {
			baseSrcLn[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}

		starts = new int[Conv.shortToInt(cSeg)];
		ends   = new int[Conv.shortToInt(cSeg)];

		for (int i = 0 ; i < Conv.shortToInt(cSeg) ; ++i) {
			starts[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
			ends  [i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}

		cbName = reader.readByte(index); index+=BinaryReader.SIZEOF_BYTE;

		name = reader.readAsciiString(index, cbName); index+=cbName;

		for (int i = 0 ; i < Conv.shortToInt(cSeg) ; ++i) {
			//OMFSrcModuleLine line = new OMFSrcModuleLine(reader, index);
			OMFSrcModuleLine line = OMFSrcModuleLine.createOMFSrcModuleLine(reader, ptr+baseSrcLn[i]);
			moduleLineList.add(line);
			index+=line.getByteCount();	
		}
	}

	/**
	 * Returns an array of the source module lines.
	 * @return an array of the source module lines
	 */
	public OMFSrcModuleLine [] getOMFSrcModuleLines() {
		OMFSrcModuleLine [] arr = new OMFSrcModuleLine[moduleLineList.size()];
		moduleLineList.toArray(arr);
		return arr;
	}

	/**
	 * Returns an array of offsets for the line or address mapping for each segment 
	 * that receives code from the source file.
	 * @return an array of offsets for the line or address mapping for each segment
	 */
	public int[] getBaseSrcLn() {
		return baseSrcLn;
	}

	/**
	 * Returns the number of segments that receive code from the source file.
	 * @return the number of segments that receive code from the source file
	 */
	public short getSegmentCount() {
		return cSeg;
	}

	/**
	 * Returns the ending addresses of the code from the module.
	 * @return the ending addresses of the code from the module
	 */
	public int[] getEnds() {
		return ends;
	}

	/**
	 * Returns the name of source file.
	 * @return the name of source file
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the pad field to maintain alignment.
	 * @return the pad field to maintain alignment
	 */
	public short getPad() {
		return pad;
	}

	/**
	 * Returns the starting addresses within the segment of the first byte of code from the module.
	 * @return the starting addresses within the segment of the first byte of code from the module
	 */
	public int[] getStarts() {
		return starts;
	}

}
