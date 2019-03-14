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
 * A class to represent the Object Module Format (OMF) Source Module data structure.
 * <br>
 * short cFile 		  - Number of source files contributing code to segments
 * <br>
 * short cSeg		  - Number of code segments receiving code from module
 * <br>
 * int [] baseSrcFile -  An array of base offsets
 * <br>
 * int [] starts 	  - start offset within the segment of the first byte of code from the module
 * <br>
 * int [] ends        - ending address of code from the module
 * <br>
 * short [] segs      - Array of segment indicies that receive code from the module
 */
public class OMFSrcModule {

    private short cFile;
	private short cSeg;
	private int [] baseSrcFile;
	private int [] starts;
	private int [] ends;
	private short [] segs;

	private ArrayList<OMFSrcModuleFile> moduleFileList = new ArrayList<OMFSrcModuleFile>();

    static OMFSrcModule createOMFSrcModule(
            FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
        OMFSrcModule omfSrcModule = (OMFSrcModule) reader.getFactory().create(OMFSrcModule.class);
        omfSrcModule.initOMFSrcModule(reader, ptr);
        return omfSrcModule;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public OMFSrcModule() {}

	private void initOMFSrcModule(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		int index = ptr;

		cFile = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		cSeg  = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;

		baseSrcFile = new int[Conv.shortToInt(cFile)];
		for (int i = 0 ; i < Conv.shortToInt(cFile) ; ++i) {
			baseSrcFile[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}

		starts = new int[Conv.shortToInt(cSeg)];
		ends   = new int[Conv.shortToInt(cSeg)];

		for (int i = 0 ; i < Conv.shortToInt(cSeg) ; ++i) {
			starts[i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
			ends  [i] = reader.readInt(index); index+=BinaryReader.SIZEOF_INT;
		}

		segs = new short[Conv.shortToInt(cSeg)];
		for (int i = 0 ; i < Conv.shortToInt(cSeg) ; ++i) {
			segs[i] = reader.readShort(index); index+=BinaryReader.SIZEOF_SHORT;
		}

		for (int i = 0 ; i < Conv.shortToInt(cFile) ; ++i) {
			moduleFileList.add(OMFSrcModuleFile.createOMFSrcModuleFile(reader, ptr+baseSrcFile[i]));
		}
	}

	/**
	 * Returns the array of source files.
	 * @return the array of source files
	 */
	public OMFSrcModuleFile [] getOMFSrcModuleFiles() {
		OMFSrcModuleFile [] arr = new OMFSrcModuleFile[moduleFileList.size()];
		moduleFileList.toArray(arr);
		return arr;
	}

	/**
	 * Returns an array of base offsets.
	 * @return an array of base offsets
	 */
	public int[] getBaseSrcFile() {
		return baseSrcFile;
	}

	/**
	 * Returns the number of source files contributing code to segments.
	 * @return the number of source files contributing code to segments
	 */
	public short getFileCount() {
		return cFile;
	}

	/**
	 * Returns the number of code segments receiving code from module.
	 * @return the number of code segments receiving code from module
	 */
	public short getSegmentCount() {
		return cSeg;
	}

	/**
	 * Returns an array of ending addresses of code from the module.
	 * @return an array of ending addresses of code from the module
	 */
	public int[] getEnds() {
		return ends;
	}

	/**
	 * Returns an array of segment indicies that receive code from the module.
	 * @return an array of segment indicies that receive code from the module
	 */
	public short[] getSegments() {
		return segs;
	}

	/**
	 * Returns an array of start offsets within the segment of the first byte of code from the module.
	 * @return an array of start offsets within the segment of the first byte of code from the module
	 */
	public int[] getStarts() {
		return starts;
	}

}
