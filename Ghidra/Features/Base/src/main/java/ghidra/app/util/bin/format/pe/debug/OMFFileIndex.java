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
package ghidra.app.util.bin.format.pe.debug;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.*;
import ghidra.util.*;

import java.io.*;
import java.util.*;

/**
 * A class to represent the Object Module Format (OMF) File Index data structure.
 * <br>
 * <pre>
 * short cMod 		 - Count or number of modules in the executable.
 * short cRef 		 - Count or number of file name references.
 * short [] modStart - array of indices into the nameoffset table for each module.  Each index is the start of the file name references for each module.
 * short cRefCnt 	 - number of file name references per module.
 * int [] nameRef 	 - array of offsets in to the names table.  For each module the offset to the first references file name is at nameRef[modStart] and continues for cRefCnt entries.
 * String names 	 - file names.
 * </pre>
 * 
 * 
 */
public class OMFFileIndex {
    private short cMod;
	private short cRef;
	private short [] modStart;
	private short [] cRefCnt;
	private int [] nameRef;
	private String [] names;

    static OMFFileIndex createOMFFileIndex(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFFileIndex omfFileIndex = (OMFFileIndex) reader.getFactory().create(OMFFileIndex.class);
        omfFileIndex.initOMFFileIndex(reader, ptr);
        return omfFileIndex;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFFileIndex() {}

	private void initOMFFileIndex(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		int index = ptr;

		cMod = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		cRef = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;

		modStart = new short[Conv.shortToInt(cMod)];
		for(int i = 0; i < cMod; ++i){
			modStart[i] = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		}

		cRefCnt = new short[Conv.shortToInt(cMod)];
		for(int i = 0; i < cMod; i++){
			cRefCnt[i] = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		}

		nameRef = new int[Conv.shortToInt(cRef)];
		for(int i = 0; i < cRef; ++i){
			nameRef[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}

		ArrayList<String> namesList = new ArrayList<String>();
		for (int i = 0 ; i < Conv.shortToInt(cRef) ; ++i) {
			int nameIndex = index + nameRef[i];

			byte len = reader.readByte(nameIndex); nameIndex+=BinaryReader.SIZEOF_BYTE;
			int length = Conv.byteToInt(len);

			String name = reader.readAsciiString(nameIndex, length);
			namesList.add(name);
		}
		names = new String[namesList.size()];
		namesList.toArray(names);
	}
	
	/**
	 * Returns the number of modules in the executable.
	 * @return the number of modules in the executable
	 */
	public short getCMod() {
		return cMod;
	}

	/**
	 * Returns the number of file name references in the executable.
	 * @return the number of file name references in the executable
	 */
	public short getCRef() {
		return cRef;
	}

	/**
	 * Returns the array of offsets into the names table.
	 * @return the array of offsets in to the names table
	 */
	public int[] getNameRef() {
		return nameRef;
	}

	/**
	 * Returns the file names referenced in the executable.
	 * @return the file names referenced in the executable
	 */
	public String [] getNames() {
		return names;
	}

	/**
	 * Returns the indices into the nameoffset table for each file.
	 * @return the indices into the nameoffset table for each file
	 */
	public short[] getCRefCnt() {
		return cRefCnt;
	}

	/**
	 * Returns the array of indices into the nameoffset table for each module.
	 * @return the array of indices into the nameoffset table for each module
	 */
	public short[] getModStart() {
		return modStart;
	}

}
