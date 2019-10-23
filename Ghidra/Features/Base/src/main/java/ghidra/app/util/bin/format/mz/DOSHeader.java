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

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.Writeable;
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
public class DOSHeader implements StructConverter, Writeable {
    /** The name to use when converting into a structure data type. */
    public final static String NAME = "IMAGE_DOS_HEADER";
	public final static int IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    public final static int SIZEOF_DOS_HEADER   = 64;

    private short e_magic;                     // Magic number							
    private short e_cblp;                      // Bytes on last page of file
    private short e_cp;                        // Pages in file
    private short e_crlc;                      // Relocations
    private short e_cparhdr;                   // Size of header in paragraphs
    private short e_minalloc;                  // Minimum extra paragraphs needed
    private short e_maxalloc;                  // Maximum extra paragraphs needed
    private short e_ss;                        // Initial (relative) SS value
    private short e_sp;                        // Initial SP value
    private short e_csum;                      // Checksum
    private short e_ip;                        // Initial IP value
    private short e_cs;                        // Initial (relative) CS value
    private short e_lfarlc;                    // File address of relocation table
    private short e_ovno;                      // Overlay number
    private short [] e_res = new short[4];     // Reserved words
    private short e_oemid;                     // OEM identifier (for e_oeminfo)
    private short e_oeminfo;                   // OEM information; e_oemid specific
    private short [] e_res2 = new short[10];   // Reserved words
    private int   e_lfanew;                    // File address of new exe header		

	private byte [] stubBytes;

    private FactoryBundledWithBinaryReader reader;

    /**
     * Constructs a new DOS header.
     * @param reader the binary reader
     */
    public static DOSHeader createDOSHeader(
            FactoryBundledWithBinaryReader reader) throws IOException {
        DOSHeader dosHeader = (DOSHeader) reader.getFactory().create(DOSHeader.class);
        dosHeader.initDOSHeader(reader);
        return dosHeader;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public DOSHeader() {}

    private void initDOSHeader(FactoryBundledWithBinaryReader reader) throws IOException {
        this.reader = reader;

        parse();
    }

    /**
     * Returns the processor name.
     * @return the processor name
     */
    public String getProcessorName() {
        return "x86";
    }
    /**
     * Returns the magic number.
     * @return the magic number
     */
    public short e_magic() {
        return e_magic;
    }
    /**
     * Returns the number of bytes on the last page of file.
     * @return the number of bytes on the last page of the file
     */
    public short e_cblp() {
        return e_cblp;
    }
    /**
     * Returns the number of pages in the file.
     * @return the number of pages in the file
     */
    public short e_cp() {
        return e_cp;
    }
    /**
     * Returns the number of relocations.
     * @return the number of relocations
     */
    public short e_crlc() {
        return e_crlc;
    }
    /**
     * Returns the size of header in paragraphs.
     * @return the size of header in paragraphs
     */
    public short e_cparhdr() {
        return e_cparhdr; 
    }
    /**
     * Returns the minimum extra paragraphs needed.
     * @return the minimum extra paragraphs needed
     */
    public short e_minalloc() {
        return e_minalloc;
    }
    /**
     * Returns the maximum extra paragraphs needed.
     * @return the maximum extra paragraphs needed
     */
    public short e_maxalloc() {
        return e_maxalloc;
    }
    /**
     * Returns the initial (relative) SS value.
     * @return the initial (relative) SS value
     */
    public short e_ss() {
        return e_ss;
    }
    /**
     * Returns the initial SP value.
     * @return the initial SP value
     */
    public short e_sp() {
        return e_sp;
    }
    /**
     * Returns the checksum.
     * @return the checksum
     */
    public short e_csum() {
        return e_csum;
    }
    /**
     * Returns the initial IP value.
     * @return the initial IP value
     */ 
    public short e_ip() {
        return e_ip;
    }
    /**
     * Returns the initial (relative) CS value.
     * @return the initial (relative) CS value
     */
    public short e_cs() {
        return e_cs;
    }
    /**
     * Returns the file address of relocation table.
     * @return the file address of relocation table
     */
    public short e_lfarlc() {
        return e_lfarlc;
    }
    /**
     * Returns the overlay number.
     * @return the overlay number
     */
    public short e_ovno() {
        return e_ovno;
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
	public boolean hasNewExeHeader() {
        if (e_lfanew >= 0 && e_lfanew <= 0x10000) {
        	if (e_lfarlc == 0x40) {
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
	public boolean hasPeHeader() {
		if (e_lfanew >= 0 && e_lfanew <= 0x1000000) {
			try {
				NTHeader ntHeader =
					NTHeader.createNTHeader(reader, e_lfanew, SectionLayout.FILE, false, false);
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
     * Returns true if the DOS magic number is correct
     * @return true if the DOS magic number is correct
     */
    public boolean isDosSignature() {
        return e_magic == IMAGE_DOS_SIGNATURE;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);
        struct.add(new ArrayDataType(ASCII,2,1));
        for (int i=1; i <= 13; i++) {
			struct.add(WORD);
        }
		struct.add(new ArrayDataType(WORD,4,2));
		struct.add(WORD);
		struct.add(WORD);
		struct.add(new ArrayDataType(WORD,10,2));
		struct.add(DWORD);
		if (getProgramLen() > 0) {
			struct.add(new ArrayDataType(BYTE, getProgramLen(), 1));
		}

        struct.getComponent( 0).setFieldName("e_magic");
        struct.getComponent( 1).setFieldName("e_cblp");
        struct.getComponent( 2).setFieldName("e_cp");
        struct.getComponent( 3).setFieldName("e_crlc");
        struct.getComponent( 4).setFieldName("e_cparhdr");
        struct.getComponent( 5).setFieldName("e_minalloc");
        struct.getComponent( 6).setFieldName("e_maxalloc");
        struct.getComponent( 7).setFieldName("e_ss");
        struct.getComponent( 8).setFieldName("e_sp");
        struct.getComponent( 9).setFieldName("e_csum");
        struct.getComponent(10).setFieldName("e_ip");
        struct.getComponent(11).setFieldName("e_cs");
        struct.getComponent(12).setFieldName("e_lfarlc");
        struct.getComponent(13).setFieldName("e_ovno");
        struct.getComponent(14).setFieldName("e_res[4]");
        struct.getComponent(15).setFieldName("e_oemid");
        struct.getComponent(16).setFieldName("e_oeminfo");
        struct.getComponent(17).setFieldName("e_res2[10]");
        struct.getComponent(18).setFieldName("e_lfanew");
		if (getProgramLen() > 0) {
        	struct.getComponent(19).setFieldName("e_program");
		}

        struct.getComponent( 0).setComment("Magic number");
        struct.getComponent( 1).setComment("Bytes of last page");
        struct.getComponent( 2).setComment("Pages in file");
        struct.getComponent( 3).setComment("Relocations");
        struct.getComponent( 4).setComment("Size of header in paragraphs");
        struct.getComponent( 5).setComment("Minimum extra paragraphs needed");
        struct.getComponent( 6).setComment("Maximum extra paragraphs needed");
        struct.getComponent( 7).setComment("Initial (relative) SS value");
        struct.getComponent( 8).setComment("Initial SP value");
        struct.getComponent( 9).setComment("Checksum");
        struct.getComponent(10).setComment("Initial IP value");
        struct.getComponent(11).setComment("Initial (relative) CS value");
        struct.getComponent(12).setComment("File address of relocation table");
        struct.getComponent(13).setComment("Overlay number");
        struct.getComponent(14).setComment("Reserved words");
        struct.getComponent(15).setComment("OEM identifier (for e_oeminfo)");
        struct.getComponent(16).setComment("OEM information; e_oemid specific");
        struct.getComponent(17).setComment("Reserved words");
        struct.getComponent(18).setComment("File address of new exe header");
		if (getProgramLen() > 0) {
        	struct.getComponent(19).setComment("Actual DOS program");
		}

		struct.setCategoryPath(new CategoryPath("/DOS"));

        return struct;
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

    private void parse() throws IOException {
        reader.setPointerIndex(0);

        e_magic       = reader.readNextShort();

		if (e_magic != IMAGE_DOS_SIGNATURE) {
			return;
		}

        e_cblp        = reader.readNextShort();
        e_cp          = reader.readNextShort();
        e_crlc        = reader.readNextShort();
        e_cparhdr     = reader.readNextShort();
        e_minalloc    = reader.readNextShort();
        e_maxalloc    = reader.readNextShort();
        e_ss          = reader.readNextShort();
        e_sp          = reader.readNextShort();
        e_csum        = reader.readNextShort();
        e_ip          = reader.readNextShort();
        e_cs          = reader.readNextShort();
        e_lfarlc      = reader.readNextShort();
        e_ovno        = reader.readNextShort();
        e_res         = reader.readNextShortArray(4);
        e_oemid       = reader.readNextShort();
        e_oeminfo     = reader.readNextShort();
        e_res2        = reader.readNextShortArray(10);
        e_lfanew      = reader.readNextInt();

		if (isDosSignature() && e_lfanew < 0x10000) {
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
		raf.write(dc.getBytes(e_magic));
		raf.write(dc.getBytes(e_cblp));
		raf.write(dc.getBytes(e_cp));
		raf.write(dc.getBytes(e_crlc));
		raf.write(dc.getBytes(e_cparhdr));
		raf.write(dc.getBytes(e_minalloc));
		raf.write(dc.getBytes(e_maxalloc));
		raf.write(dc.getBytes(e_ss));
		raf.write(dc.getBytes(e_sp));
		raf.write(dc.getBytes(e_csum));
		raf.write(dc.getBytes(e_ip));
		raf.write(dc.getBytes(e_cs));
		raf.write(dc.getBytes(e_lfarlc));
		raf.write(dc.getBytes(e_ovno));
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
