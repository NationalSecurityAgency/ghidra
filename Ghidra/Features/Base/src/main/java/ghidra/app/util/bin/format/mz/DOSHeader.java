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
package ghidra.app.util.bin.format.mz;

import java.io.IOException;
import java.io.RandomAccessFile;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.ne.InvalidWindowsHeaderException;
import ghidra.app.util.bin.format.ne.WindowsHeader;
import ghidra.app.util.bin.format.pe.InvalidNTHeaderException;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;


/**
 * This class represents the <code>IMAGE_DOS_HEADER</code> struct
 * as defined in <b><code>winnt.h</code></b>.
 * <br>
 * <pre>
 * typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
 *     WORD   e_magic;                     // Magic number								// MANDATORY
 *     WORD   e_cblp;                      // Bytes on last page of file
 *     WORD   e_cp;                        // Pages in file
 *     WORD   e_crlc;                      // Relocations
 *     WORD   e_cparhdr;                   // Size of header in paragraphs
 *     WORD   e_minalloc;                  // Minimum extra paragraphs needed
 *     WORD   e_maxalloc;                  // Maximum extra paragraphs needed
 *     WORD   e_ss;                        // Initial (relative) SS value
 *     WORD   e_sp;                        // Initial SP value
 *     WORD   e_csum;                      // Checksum
 *     WORD   e_ip;                        // Initial IP value
 *     WORD   e_cs;                        // Initial (relative) CS value
 *     WORD   e_lfarlc;                    // File address of relocation table
 *     WORD   e_ovno;                      // Overlay number
 *     WORD   e_res[4];                    // Reserved words
 *     WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
 *     WORD   e_oeminfo;                   // OEM information; e_oemid specific
 *     WORD   e_res2[10];                  // Reserved words							// MANDATORY
 *     LONG   e_lfanew;                    // File address of new exe header
 * } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
 * </pre>
 *
 * 
 */
public class DOSHeader extends OldDOSHeader {
	
    /** The name to use when converting into a structure data type. */
    public final static String NAME = "IMAGE_DOS_HEADER";
    
	public final static int SIZEOF_DOS_HEADER = 64;

    private short [] e_res = new short[4];     // Reserved words
    private short e_oemid;                     // OEM identifier (for e_oeminfo)
    private short e_oeminfo;                   // OEM information; e_oemid specific
    private short [] e_res2 = new short[10];   // Reserved words
    private int   e_lfanew;                    // File address of new exe header		

	private byte [] stubBytes;

    /**
	 * Constructs a new DOS header.
	 * @param reader the binary reader
	 * @throws IOException if there was an IO-related error
	 */
	public DOSHeader(BinaryReader reader) throws IOException {
		super(reader);
    }

	/**
     * Returns the reserved words.
     * @return the reserved words
     */
    public short [] e_res() {
        return e_res;
    }
    /**
     * Returns the OEM identifier (for e_oeminfo).
     * @return the OEM identifier (for e_oeminfo)
     */
    public short e_oemid() {
        return e_oemid;
    }
    /**
     * Returns the OEM information; e_oemid specific.
     * @return the OEM information; e_oemid specific
     */
    public short e_oeminfo() {
        return e_oeminfo;
    }
    /**
     * Returns the reserved words (2).
     * @return the reserved words (2)
     */
    public short [] e_res2() {
        return e_res2;
    }
    /**
     * Returns the file address of new EXE header.
     * @return the file address of new EXE header
     */
    public int e_lfanew() {
        return e_lfanew;
    }
    
	/**
	 * Returns true if a new EXE header exists.
	 * @return true if a new EXE header exists
	 */
    @Override
	public boolean hasNewExeHeader() {
        if (e_lfanew >= 0 && e_lfanew <= 0x10000) {
        	if (e_lfarlc() == 0x40) {
				// There are some non-NE files out there than may have e_lfarlc == 0x40, so we need 
				// to actually read the bytes at e_lfanew and check for the required NE signature.
				try {
					new WindowsHeader(reader, null, (short) e_lfanew);
					return true;
				}
				catch (InvalidWindowsHeaderException | IOException e) {
					return false;
				}
        	}
        }
        return false;
    }

	/**
	 * Returns true if a PE header exists.
	 * @return true if a PE header exists
	 */
    @Override
	public boolean hasPeHeader() {
		if (e_lfanew >= 0 && e_lfanew <= 0x1000000) {
			try {
				NTHeader ntHeader =
					new NTHeader(reader, e_lfanew, SectionLayout.FILE, false, false);
				if (ntHeader != null && ntHeader.getOptionalHeader() != null) {
					return true;
				}
			}
			catch (InvalidNTHeaderException | IOException e) {
				// Fall through and return false
			}
		}
		return false;
	}

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = (StructureDataType)super.toDataType();
		
		struct.add(new ArrayDataType(WORD,4,2));
		struct.add(WORD);
		struct.add(WORD);
		struct.add(new ArrayDataType(WORD,10,2));
		struct.add(DWORD);
		if (getProgramLen() > 0) {
			struct.add(new ArrayDataType(BYTE, getProgramLen(), 1));
		}

        struct.getComponent(14).setFieldName("e_res[4]");
        struct.getComponent(15).setFieldName("e_oemid");
        struct.getComponent(16).setFieldName("e_oeminfo");
        struct.getComponent(17).setFieldName("e_res2[10]");
        struct.getComponent(18).setFieldName("e_lfanew");
		if (getProgramLen() > 0) {
        	struct.getComponent(19).setFieldName("e_program");
		}

        struct.getComponent(14).setComment("Reserved words");
        struct.getComponent(15).setComment("OEM identifier (for e_oeminfo)");
        struct.getComponent(16).setComment("OEM information; e_oemid specific");
        struct.getComponent(17).setComment("Reserved words");
        struct.getComponent(18).setComment("File address of new exe header");
		if (getProgramLen() > 0) {
        	struct.getComponent(19).setComment("Actual DOS program");
		}

        return struct;
    }
    
    /**
	 * Helper to override the value of name
	 * @return The name of the header
	 */
    @Override
    public String getName() {
    	return NAME;
    }

    /**
     * Returns the length (in bytes) of the DOS
     * program.
     * <p>
     * In other words:
     * <code>e_lfanew() - SIZEOF_DOS_HEADER</code>
     * 
     * @return  the length (in bytes)
     */
    public int getProgramLen() {
        return stubBytes == null ? 0 : stubBytes.length;
    }

    @Override
    protected void parse() throws IOException {
        super.parse();
        
        if (!isDosSignature()) {
			return;
		}
        
        e_res         = reader.readNextShortArray(4);
        e_oemid       = reader.readNextShort();
        e_oeminfo     = reader.readNextShort();
        e_res2        = reader.readNextShortArray(10);
        e_lfanew      = reader.readNextInt();

		if (e_lfanew < 0x10000) {
			try {
				stubBytes = e_lfanew > SIZEOF_DOS_HEADER ? 
					reader.readByteArray(SIZEOF_DOS_HEADER, e_lfanew - SIZEOF_DOS_HEADER) : new byte[0];
			}
			catch (Exception exc) {
				stubBytes = new byte[0];				
			}
		}
		else {
			stubBytes = new byte[0];
		}
    }

	public void decrementStub(int start) {
		if (stubBytes.length > 0) {
			try {
				stubBytes = start > SIZEOF_DOS_HEADER ? 
					reader.readByteArray(SIZEOF_DOS_HEADER, start - SIZEOF_DOS_HEADER) : new byte[0];
			}
			catch (Exception exc) {
				stubBytes = new byte[0];				
			}
		}
	}

	/**
	 * @see ghidra.app.util.bin.format.Writeable#write(java.io.RandomAccessFile, ghidra.util.DataConverter)
	 */
	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		super.write(raf, dc);
		for (short e_re : e_res) {
			raf.write(dc.getBytes(e_re));
		}
		raf.write(dc.getBytes(e_oemid));
		raf.write(dc.getBytes(e_oeminfo));
		for (short element : e_res2) {
			raf.write(dc.getBytes(element));
		}
		raf.write(dc.getBytes(e_lfanew));
		raf.write(stubBytes);		
	}
}
