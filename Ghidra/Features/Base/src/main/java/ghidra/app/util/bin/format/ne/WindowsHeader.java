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

/**
 * A class to represent and parse the 
 * Windows new-style executable (NE) header.
 *  
 * 
 */
public class WindowsHeader {
	/**The magic number for Windows NE files.*/
    public final static short IMAGE_NE_SIGNATURE = 0x454E; //NE

    private InformationBlock infoBlock;
    private SegmentTable segTable;
    private ResourceTable rsrcTable;
    private ResidentNameTable resNameTable;
    private ModuleReferenceTable modRefTable;
    private ImportedNameTable impNameTable;
    private EntryTable entryTable;
    private NonResidentNameTable nonResNameTable;

    /**
	 * Constructor
	 * @param reader the binary reader
	 * @param baseAddr the image base address
	 * @param index the index where the windows headers begins
	 * @throws InvalidWindowsHeaderException if the bytes defined in the binary reader at
	 * the specified index do not constitute a valid windows header.
	 * @throws IOException for problems reading the header bytes
	 */
	public WindowsHeader(FactoryBundledWithBinaryReader reader, SegmentedAddress baseAddr,
			short index) throws InvalidWindowsHeaderException, IOException {
        this.infoBlock = new InformationBlock(reader, index);

        short segTableIndex = (short)(infoBlock.getSegmentTableOffset() + index);
        this.segTable = new SegmentTable(reader,
			baseAddr, segTableIndex, infoBlock.getSegmentCount(),
			infoBlock.getSegmentAlignmentShiftCount());

        //if resource table offset == resident name table offset, then
        //we do not have any resources...
        if (infoBlock.getResourceTableOffset() != infoBlock.getResidentNameTableOffset()) {
            short rsrcTableIndex = (short)(infoBlock.getResourceTableOffset() + index);
            this.rsrcTable = new ResourceTable(reader, rsrcTableIndex);
        }

        short resNameTableIndex = (short)(infoBlock.getResidentNameTableOffset() + index);
        this.resNameTable = new ResidentNameTable(reader, resNameTableIndex);

        short impNameTableIndex = (short)(infoBlock.getImportedNamesTableOffset() + index);
        this.impNameTable = new ImportedNameTable(reader, impNameTableIndex);

        short modRefTableIndex = (short)(infoBlock.getModuleReferenceTableOffset() + index);
        this.modRefTable = new ModuleReferenceTable(reader, modRefTableIndex,
                                        infoBlock.getModuleReferenceTableCount(),
                                        impNameTable);

        short entryTableIndex = (short)(infoBlock.getEntryTableOffset() + index);
        this.entryTable = new EntryTable(reader, entryTableIndex, infoBlock.getEntryTableSize());

        this.nonResNameTable = new NonResidentNameTable(reader,
                                        infoBlock.getNonResidentNameTableOffset(),
                                        infoBlock.getNonResidentNameTableSize());
    }

	/**
	 * Returns the processor name.
	 * @return the processor name
	 */
    public String getProcessorName() {
        //TODO:
        //how to properly determine the process name?
        //is there more than one?
        return "x86";
    }

	/**
	 * Returns the information block.
	 * @return the information block
	 */
    public InformationBlock getInformationBlock() {
        return infoBlock;
    }
    /**
     * Returns the segment table.
     * @return the segment table
     */
    public SegmentTable getSegmentTable() {
        return segTable;
    }
    /**
     * Returns the resource table.
     * @return the resource table
     */
    public ResourceTable getResourceTable() {
        return rsrcTable;
    }
    /**
     * Returns the resident name table.
     * @return the resident name table
     */
    public ResidentNameTable getResidentNameTable() {
        return resNameTable;
    }
    /**
     * Returns the module reference table.
     * @return the module reference table
     */
    public ModuleReferenceTable getModuleReferenceTable() {
        return modRefTable;
    }
    /**
     * Returns the imported name table.
     * @return the imported name table
     */
    public ImportedNameTable getImportedNameTable() {
        return impNameTable;
    }
    /**
     * Returns the entry table.
     * @return the entry table
     */
    public EntryTable getEntryTable() {
        return entryTable;
    }
    /**
     * Returns the non-resident name table.
     * @return the non-resident name table
     */
    public NonResidentNameTable getNonResidentNameTable() {
        return nonResNameTable;
    }
}
