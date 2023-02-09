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
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.Writeable;
import ghidra.program.model.data.*;
import ghidra.util.DataConverter;
import ghidra.util.exception.DuplicateNameException;

/**
 * This class represents a DOS Header
 * <br>
 * <pre>
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
 *     
 * </pre>
 */

public class OldDOSHeader implements StructConverter, Writeable {

	/** The name to use when converting into a structure data type. */
	public static final String NAME = "OLD_IMAGE_DOS_HEADER";

	public static final int IMAGE_DOS_SIGNATURE = 0x5A4D;
	
	private short e_magic;
	private short e_cblp;
	private short e_cp;
	private short e_crlc;
	private short e_cparhdr;
	private short e_minalloc;
	private short e_maxalloc;
	private short e_ss;
	private short e_sp;
	private short e_csum;
	private short e_ip;
	private short e_cs;
	private short e_lfarlc;
	private short e_ovno;

	protected BinaryReader reader;

	/**
	 * Constructs a new DOS header.
	 * @param reader the binary reader
	 * @throws IOException if there was an IO-related error
	 */
	public OldDOSHeader(BinaryReader reader) throws IOException {
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
	 * Returns true if a new EXE header exists.
	 * @return true if a new EXE header exists
	 */
	public boolean hasNewExeHeader() {
	    return false;
	}

	/**
	 * Returns true if a PE header exists.
	 * @return true if a PE header exists
	 */
	public boolean hasPeHeader() {
		return false;
	}

	/**
	 * Returns true if the DOS magic number is correct
	 * @return true if the DOS magic number is correct
	 */
	public boolean isDosSignature() {
	    return e_magic == IMAGE_DOS_SIGNATURE;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(getName(), 0);
	    struct.add(new ArrayDataType(ASCII,2,1));
	    for (int i=1; i <= 13; i++) {
			struct.add(WORD);
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
	
		struct.setCategoryPath(new CategoryPath("/DOS"));
	
	    return struct;
	}
	
	/**
	 * Helper to override the value of name
	 * @return The name of the header
	 */
	protected String getName() {
		return NAME;
	}

	protected void parse() throws IOException {
	    reader.setPointerIndex(0);
	
	    e_magic       = reader.readNextShort();
	
		if (!isDosSignature()) {
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
	}

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
	}

}
