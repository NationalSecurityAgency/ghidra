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
package ghidra.app.util.bin.format.pe.resource;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.ResourceDataDirectory;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 * typedef struct _IMAGE_RESOURCE_DIRECTORY {
 *     DWORD   Characteristics;
 *     DWORD   TimeDateStamp;
 *     WORD    MajorVersion;
 *     WORD    MinorVersion;
 *     WORD    NumberOfNamedEntries;
 *     WORD    NumberOfIdEntries;
 * };
 * </pre>
 */
public class ResourceDirectory implements StructConverter {
	public final static String NAME = "IMAGE_RESOURCE_DIRECTORY";
	public final static int SIZEOF = 16;

    private int    characteristics;
    private int    timeDataStamp;
    private short  majorVersion;
    private short  minorVersion;
    private short  numberOfNamedEntries;
    private short  numberOfIdEntries;
    private ArrayList<ResourceDirectoryEntry> entries = new ArrayList<ResourceDirectoryEntry>();

    public ResourceDirectory(FactoryBundledWithBinaryReader reader, 
    						int index, 
    						int resourceBase, 
    						boolean isFirstLevel,
    						NTHeader ntHeader) throws IOException {

    	if (!ntHeader.checkPointer(index)) {
        	Msg.error(this, "Invalid file index "+Integer.toHexString(index));
        	return;	
    	}
    	if (ResourceDataDirectory.directoryMap.contains(index)) {
    		Msg.error(this, "Duplicate ResourceDirectory at "+index+" ignored.");
    		return;
    	}
    	ResourceDataDirectory.directoryMap.add(index);
    	
    	characteristics      = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;
        timeDataStamp        = reader.readInt  (index); index += BinaryReader.SIZEOF_INT;
        majorVersion         = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        minorVersion         = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        numberOfNamedEntries = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;
        numberOfIdEntries    = reader.readShort(index); index += BinaryReader.SIZEOF_SHORT;

        long rva = index + (numberOfNamedEntries+numberOfIdEntries) * ResourceDataDirectory.IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY;
	    if (!ntHeader.checkRVA(rva) || (0 > rva || rva > reader.length())) {
	   		Msg.error(this, "Too many resource entries "+Integer.toHexString(numberOfNamedEntries+numberOfIdEntries));
	   		numberOfNamedEntries = numberOfIdEntries = 0;
	    }
	    for (int i = 0 ; i < numberOfNamedEntries ; ++i) {
        	if (!ntHeader.checkPointer(index)) {
            	Msg.error(this, "Invalid file index "+Integer.toHexString(index));
        		return;	
        	}
	    	ResourceDirectoryEntry entry = new ResourceDirectoryEntry(reader, index, resourceBase, true, isFirstLevel, ntHeader);
	    	if (!entry.isValid()) {
	           	return;
	    	}
			entries.add(entry);
	        index += ResourceDataDirectory.IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY;
		}
		for (int i = 0 ; i < numberOfIdEntries ; ++i) {
        	if (!ntHeader.checkPointer(index)) {
            	Msg.error(this, "Invalid file index "+Integer.toHexString(index));
        		return;	
        	}
			ResourceDirectoryEntry entry = new ResourceDirectoryEntry(reader, index, resourceBase, false, isFirstLevel, ntHeader);
	    	if (!entry.isValid()) {
	           	return;
	    	}
			entries.add(entry);
		    index += ResourceDataDirectory.IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY;
		}
    }

    public List<ResourceDirectoryEntry> getEntries() {
		return new ArrayList<ResourceDirectoryEntry>(entries);
	}

    /**
     * Theoretically, this field could hold flags for the resource, but appears to always be 0. 
     * @return the flags for the resource
     */
    public int getCharacteristics() {
        return characteristics;
    }
    /**
     * Returns the time/date stamp describing the creation time of the resource.
     * @return the time/date stamp describing the creation time of the resource
     */
    public int getTimeDataStamp() {
        return timeDataStamp;
    }
    /**
     * Returns the number of array elements that use names and that follow this structure. 
     * @return the number of array elements that use names and that follow this structure
     */
    public int getNumberOfNamedEntries() {
        return numberOfNamedEntries;
    }
    /**
     * Returns the number of array elements that use integer IDs, and which follow this structure. 
     * @return the number of array elements that use integer IDs, and which follow this structure
     */
    public int getNumberOfIdEntries() {
        return numberOfIdEntries;
    }
	/**
	 * Theoretically these fields would hold a version number for the resource.
	 * These field appear to always be set to 0.
	 * @return the major version number
	 */
	public short getMajorVersion() {
		return majorVersion;
	}
	/**
	 * Theoretically these fields would hold a version number for the resource.
	 * These field appear to always be set to 0.
	 * @return the minor version number
	 */
	public short getMinorVersion() {
		return minorVersion;
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(DWORD, "Characteristics",      null);
		struct.add(DWORD, "TimeDateStamp",        null);
		struct.add( WORD, "MajorVersion",         null);
		struct.add( WORD, "MinorVersion",         null);
		struct.add( WORD, "NumberOfNamedEntries", null);
		struct.add( WORD, "NumberOfIdEntries",    null);
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}
}
