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
package ghidra.file.formats.yaffs2;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class YAFFS2Header implements StructConverter {

	// header objects
	private long objectType;
	private long parentObjectId;
	private short checksum;
    private String fileName;
    private long ystMode;
    private long ystUId;
    private long ystGId;
    private String ystATime;
    private String ystMTime;
    private String ystCTime;
    private long fileSizeLow;
    private long equivId;
    private String aliasFileName;
    private long ystRDev;
    private long winCTime;
    private long winATime;
    private long winMTime;
    private long inbandObjId;
    private long inbandIsShrink;
    private long fileSizeHigh;
    private long shadowsObject;
    private long isShrink;

	/**
     * Construct an entry from an archive's header bytes.
     */
    public YAFFS2Header(byte[] buffer) {
        
        // parse header structure
        objectType 		= YAFFS2Utils.parseInteger(buffer, 0, 4);
        parentObjectId 	= YAFFS2Utils.parseInteger(buffer, 4, 4);
        checksum 		= (short) YAFFS2Utils.parseInteger(buffer, 8, 2);
        fileName 		= YAFFS2Utils.parseName(buffer, 10, 256);
        // skip 2 bytes for the "unknown1" short field
        ystMode 		= YAFFS2Utils.parseInteger(buffer, 268, 4);
        ystUId 			= YAFFS2Utils.parseInteger(buffer, 272, 4);
	    ystGId 			= YAFFS2Utils.parseInteger(buffer, 276, 4);
	    ystATime 		= YAFFS2Utils.parseDateTime(buffer, 280, 4);
	    ystMTime 		= YAFFS2Utils.parseDateTime(buffer, 284, 4);
	    ystCTime 		= YAFFS2Utils.parseDateTime(buffer, 288, 4);
	    fileSizeLow 	= YAFFS2Utils.parseFileSize(buffer, 292, 4);
	    equivId 		= YAFFS2Utils.parseInteger(buffer, 296, 4);
	    aliasFileName 	= YAFFS2Utils.parseName(buffer, 300, 160);
        ystRDev 		= YAFFS2Utils.parseInteger(buffer, 460, 4);
		winCTime = buffer[464];
		winATime = buffer[472];
		winMTime = buffer[480];
        inbandObjId 	= YAFFS2Utils.parseInteger(buffer, 488, 4);
        inbandIsShrink 	= YAFFS2Utils.parseInteger(buffer, 492, 4);
        fileSizeHigh 	= YAFFS2Utils.parseInteger(buffer, 496, 4);
        // skip 4 bytes for the "reserved" int field
        shadowsObject 	= YAFFS2Utils.parseInteger(buffer, 504, 4);
        isShrink 		= YAFFS2Utils.parseInteger(buffer, 508, 4);

    }

	public YAFFS2Header() {
	}

	public long getObjectType() {
		return objectType;
	}
	
	public boolean isDirectory() {
		if (objectType == 3) {
			return true;
		}
		return false;
	}

	public short getChecksum() {
		return checksum;
	}

	public String getName() {
		return fileName;
	}

	public long getYstMode() {
		return ystMode;
	}

	public long getYstUId() {
		return ystUId;
	}

	public long getYstGId() {
		return ystGId;
	}

	public String getYstATime() {
		return ystATime;
	}

	public String getYstMTime() {
		return ystMTime;
	}

	public String getYstCTime() {
		return ystCTime;
	}

	public long getSize() {
		return fileSizeLow;
	}

	public long getEquivId() {
		return equivId;
	}

    public String getAliasFileName() {
    	return aliasFileName;
    }

    public long getYstRDev() {
    	return ystRDev;
    }

    public long getWinCTime() {
    	return winCTime;
    }

    public long getWinATime() {
    	return winATime;
    }

    public long getWinMTime() {
    	return winMTime;
    }

    public long getInbandObjId() {
    	return inbandObjId;
    }

    public long getInbandIsShrink() {
    	return inbandIsShrink;
    }

    public long getFileSizeHigh() {
    	return fileSizeHigh;
    }

    public long getShadowsObject() {
    	return shadowsObject;
    }

    public long getIsShrink() {
    	return isShrink;
    }

	public long getParentObjectId() {
		return parentObjectId;
	}

	public boolean isFile() {
		if (objectType == 1) {
			return true;
		}
		return false;
	}
	
	// header structure for analyzer
	public DataType toDataType() throws DuplicateNameException, IOException {
		
		Structure structure = new StructureDataType( "yaffs2Hdr", 0 );
		structure.add( DWORD, "objectType", null );
		structure.add( DWORD, "parentObjectId", null );
		structure.add( WORD, "checksum", null );
		structure.add( STRING, YAFFS2Constants.FILE_NAME_SIZE, "fileName", null );
		structure.add( WORD, "unknown1", null );
		structure.add( DWORD, "ystMode", null );
		structure.add( DWORD, "ystUId", null );
		structure.add( DWORD, "ystGId", null );
		structure.add( DWORD, "ystATime", null );
		structure.add( DWORD, "ystMTime", null );
		structure.add( DWORD, "ystCTime", null );
		structure.add( DWORD, "fileSizeLow", null );
		structure.add( DWORD, "equivId", null );
		structure.add( STRING, YAFFS2Constants.ALIAS_FILE_NAME_SIZE, "aliasFileName", null );
		structure.add( DWORD, "ystRDev", null );
		structure.add( QWORD, "winCTime", null );
		structure.add( QWORD, "winATime", null );
		structure.add( QWORD, "winMTime", null );
		structure.add( DWORD, "inbandObjId", null );
		structure.add( DWORD, "inbandIsShrink", null );
		structure.add( DWORD, "fileSizeHigh", null );
		structure.add( DWORD, "reserved", null );
		structure.add( DWORD, "shadowsObject", null );
		structure.add( DWORD, "isShrink", null );
		structure.add(new ArrayDataType(BYTE, YAFFS2Constants.EMPTY_DATA_SIZE, BYTE.getLength()), "emptyData", null);
		return structure;
		
	}
	
}
