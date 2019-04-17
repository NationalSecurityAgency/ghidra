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
import ghidra.program.model.data.*;
import ghidra.util.exception.*;

import java.io.*;
import java.util.*;

/**
 * A class to represent the Object Module Format (OMF)
 * code view symbol table.
 */
public class DebugCodeViewSymbolTable implements StructConverter {
	public final static int MAGIC_NB_09 = 
		DebugCodeViewConstants.SIGNATURE_NB << 16 |
		DebugCodeViewConstants.VERSION_09;
	public final static int MAGIC_NB_11 = 
		DebugCodeViewConstants.SIGNATURE_NB << 16 |
		DebugCodeViewConstants.VERSION_11;
	public final static int MAGIC_N1_12 = 
		DebugCodeViewConstants.SIGNATURE_N1 << 16 |
		DebugCodeViewConstants.VERSION_12;
	public final static int MAGIC_N1_13 = 
		DebugCodeViewConstants.SIGNATURE_N1 << 16 |
		DebugCodeViewConstants.VERSION_13;

	public static boolean isMatch(FactoryBundledWithBinaryReader reader, int ptr) throws IOException {
		//read value out as big endian
		int value = reader.readByte(ptr  ) << 24 |
					reader.readByte(ptr+1) << 16 |
					reader.readByte(ptr+2) << 8 |
					reader.readByte(ptr+3);
		return (MAGIC_NB_09 == value) || (MAGIC_NB_11 == value) || 
			   (MAGIC_N1_12 == value) || (MAGIC_N1_13 == value);
	}

    private byte [] magic;
    private int lfoDirectoryPos;
    private int omfDirHeaderPos;
    private OMFDirHeader header;
    private int omfDirEntryPos;

    private ArrayList<OMFDirEntry>    entriesList = new ArrayList<OMFDirEntry>();
    private ArrayList<OMFModule>      modulesList = new ArrayList<OMFModule>();
    private ArrayList<OMFGlobal>      globalsList = new ArrayList<OMFGlobal>();
    private ArrayList<OMFSegMap>      segMapsList = new ArrayList<OMFSegMap>();
    private ArrayList<OMFSrcModule> srcModuleList = new ArrayList<OMFSrcModule>();
    private ArrayList<OMFFileIndex> fileIndexList = new ArrayList<OMFFileIndex>();
    private ArrayList<OMFAlignSym>  alignSymsList = new ArrayList<OMFAlignSym>();

	private OMFLibrary library;

    static DebugCodeViewSymbolTable createDebugCodeViewSymbolTable(
            FactoryBundledWithBinaryReader reader, int size, int base, int ptr)
            throws IOException {
        DebugCodeViewSymbolTable debugCodeViewSymbolTable = (DebugCodeViewSymbolTable) reader.getFactory().create(DebugCodeViewSymbolTable.class);
        debugCodeViewSymbolTable.initDebugCodeViewSymbolTable(reader, size, base, ptr);
        return debugCodeViewSymbolTable;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DebugCodeViewSymbolTable() {}

    private void initDebugCodeViewSymbolTable(FactoryBundledWithBinaryReader reader, int size, int base, int ptr) throws IOException {
    	magic = reader.readByteArray(ptr, 4); ptr += 4;
        lfoDirectoryPos = reader.readInt(ptr);
        omfDirHeaderPos = base + lfoDirectoryPos;
        header = OMFDirHeader.createOMFDirHeader(reader, omfDirHeaderPos);
        omfDirEntryPos = omfDirHeaderPos + OMFDirHeader.IMAGE_SIZEOF_OMF_DIR_HEADER;

        for (int i = 0 ; i < header.getNumberOfEntries() ; ++i) {
            OMFDirEntry entry = OMFDirEntry.createOMFDirEntry(reader, omfDirEntryPos);
            entriesList.add(entry);
            switch (entry.getSubSectionType()) {
                case DebugCodeViewConstants.sstModule:
                    modulesList.add(OMFModule.createOMFModule(reader, entry.getLargeFileOffset()+base, entry.getNumberOfBytes()));
                    break;
                case DebugCodeViewConstants.sstSegMap:
                    segMapsList.add(OMFSegMap.createOMFSegMap(reader, entry.getLargeFileOffset()+base));
                    break;
                case DebugCodeViewConstants.sstGlobalPub:
				case DebugCodeViewConstants.sstGlobalSym:
				case DebugCodeViewConstants.sstStaticSym:
					globalsList.add(OMFGlobal.createOMFGlobal(reader, entry.getLargeFileOffset()+base));
                    break;
				case DebugCodeViewConstants.sstSrcModule:
					srcModuleList.add(OMFSrcModule.createOMFSrcModule(reader, entry.getLargeFileOffset()+base));
					break;
				case DebugCodeViewConstants.sstFileIndex:
					fileIndexList.add(OMFFileIndex.createOMFFileIndex(reader, entry.getLargeFileOffset()+base));
					break;
				case DebugCodeViewConstants.sstAlignSym:
					alignSymsList.add(OMFAlignSym.createOMFAlignSym(reader, entry.getLargeFileOffset()+base));
					break;
				case DebugCodeViewConstants.sstLibraries:
					library = OMFLibrary.createOMFLibrary(reader, entry.getLargeFileOffset()+base, entry.getNumberOfBytes());
					break;
				case DebugCodeViewConstants.sstGlobalTypes:
					//int type = entry.getLargeFileOffset()+base;
					break;
                default:
					//TODO handle rest of possible types
                    break;
            }
            omfDirEntryPos += OMFDirEntry.IMAGE_SIZEOF_OMF_DIR_ENTRY;
        }
    }

    public byte[] getMagic() {
		return magic;
	}

	public OMFLibrary getOMFLibrary() {
		return library;
	}

	/**
	 * Returns the OMF directory entries.
	 * @return the OMF directory entries
	 */
    public List<OMFDirEntry> getOMFDirectoryEntries() {
        return entriesList;
    }

    /**
     * Returns the OMF modules.
     * @return the OMF modules
     */
    public List<OMFModule> getOMFModules() {
        return modulesList;

    }
    /**
     * Returns the OMF segment maps.
     * @return the OMF segment maps
     */
    public List<OMFSegMap> getOMFSegMaps() {
        return segMapsList;
    }

    /**
     * Returns the OMF globals.
     * @return the OMF globals
     */
    public List<OMFGlobal> getOMFGlobals() {
        return globalsList;
    }

	/**
	 * Returns the OMF Source Modules.
	 * @return the OMF Source Modules
	 */
	public List<OMFSrcModule> getOMFSrcModules() {
		return srcModuleList;
	}

	/**
	 * Returns the OMF Source Files.
	 * @return the OMF Source Files
	 */
	public List<OMFFileIndex> getOMFFiles() {
		return fileIndexList;
	}

	/**
	 * Returns the OMF Align Symbols.
	 * @return the OMF Align Symbols
	 */
	public List<OMFAlignSym> getOMFAlignSym() {
		return alignSymsList;
	}
    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    public DataType toDataType() throws DuplicateNameException {
        return null;
    }
}
