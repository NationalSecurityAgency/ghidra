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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.io.RandomAccessFile;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;

/**
 * A class to manage loading Portable Executables (PE).
 * 
 * 
 */
public class PortableExecutable {
	public static final String NAME = "PORTABLE_EXECUTABLE";
	public static boolean DEBUG = false;

	/**
	 * Indicates how sections of this PE are laid out in the underlying ByteProvider.
	 * Use {@link SectionLayout#FILE} when loading from a file, and {@link SectionLayout#MEMORY} when
	 * loading from a memory model (like an already-loaded program in Ghidra).
	 */
	public static enum SectionLayout {
		/** Indicates the sections of this PE are laid out as stored in a file. **/
		FILE,
		/** Indicates the sections of this PE are laid out as loaded into memory **/
		MEMORY
	}

	private BinaryReader reader;
	private DOSHeader dosHeader;
	private RichHeader richHeader;
	private NTHeader ntHeader;

	//private FileHeader fileHeader;

	/**
	 * Constructs a new Portable Executable using the specified byte provider and layout.
	 *  <p>
	 * Same as calling <code>createFileAlignedPortableExecutable(factory, bp, layout, true, false)</code>
	 * @param bp the byte provider
	 * @param layout specifies the layout of the underlying provider and governs RVA resolution
	 * @throws IOException if an I/O error occurs.
	 * @see #PortableExecutable(ByteProvider, SectionLayout, boolean, boolean)
	 **/
	public PortableExecutable(ByteProvider bp, SectionLayout layout) throws IOException {
		this(bp, layout, true, false);
	}

	/**
	 * Constructs a new Portable Executable using the specified byte provider and layout.
	 * @param bp the byte provider
	 * @param layout specifies the layout of the underlying provider and governs RVA resolution
	 * @param advancedProcess if true, the data directories are also processed
	 * @param parseCliHeaders if true, CLI headers are parsed (if present)
	 * @throws IOException if an I/O error occurs.
	 */
	public PortableExecutable(ByteProvider bp, SectionLayout layout, boolean advancedProcess,
			boolean parseCliHeaders) throws IOException {
		reader = new BinaryReader(bp, true);

		dosHeader = new DOSHeader(reader);
		if (dosHeader.isDosSignature()) {
			richHeader = new RichHeader(reader);
			if (richHeader.getSize() > 0) {
				dosHeader.decrementStub(richHeader.getOffset());
			}

			try {
				ntHeader = new NTHeader(reader, dosHeader.e_lfanew(), layout, advancedProcess,
					parseCliHeaders);
			}
			catch (InvalidNTHeaderException e) {
				Msg.debug(this, "Expected InvalidNTHeaderException, ignoring");
			}
			catch (NotYetImplementedException e) {
				Msg.debug(this, "Expected NotYetImplementedException, ignoring");
			}
			catch (ArrayIndexOutOfBoundsException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			return;
		}

		//fileHeader = new FileHeader(reader);
		//
		//if (fileHeader.getMachineName() != null) {
		//    if (fileHeader.getSizeOfOptionalHeader() == 0) {
		//        Err.debug(this, "This is a .OBJ file...");
		//    }
		//    else if (fileHeader.getSizeOfOptionalHeader() == Constants.IMAGE_SIZEOF_ROM_OPTIONAL_HEADER) {
		//        Err.debug(this, "This is a ROM image...");
		//    }
		//}
		//if (isValidLibrary(reader)) {
		//    Err.debug(this, "This is a library/archive file...");
		//}
	}

	/**
	 * Returns the DOS header from the PE image.
	 * @return the DOS header from the PE image
	 */
	public DOSHeader getDOSHeader() {
		return dosHeader;
	}

	/**
	 * Returns the Rich header from the PE image.
	 * @return the Rich header from the PE image
	 */
	public RichHeader getRichHeader() {
		return richHeader;
	}

	/**
	 * Returns the NT header from the PE image.
	 * @return the NT header from the PE image
	 */
	public NTHeader getNTHeader() {
		return ntHeader;
	}

	//private boolean isValidLibrary(BinaryReader reader) throws IOException {
	//    String s = reader.readAsciiString(0);
	//    if (s != null && s.length() >= Constants.IMAGE_ARCHIVE_START_SIZE) {
	//        return s.substring(0, Constants.IMAGE_ARCHIVE_START_SIZE).equals(Constants.IMAGE_ARCHIVE_START);
	//    }
	//    return false;
	//}

	public void writeHeader(RandomAccessFile raf, DataConverter dc) throws IOException {

		raf.seek(0);
		if (dosHeader != null) {
			dosHeader.write(raf, dc);
		}
		if (richHeader != null) {
			richHeader.write(raf, dc);
		}
		if (ntHeader != null) {
			ntHeader.writeHeader(raf, dc);
		}
	}

	public static int computeAlignment(int value, int alignment) {
		if (alignment == 0 || (value % alignment) == 0) {
			return value;
		}
		int a = ((value + alignment) / alignment) * alignment;
		return a;
	}
	
	public long getFileLength() {
		if (reader != null) {
			try {
				return reader.length();
			} catch (IOException e) {
				// IGNORE
				return  0;
			}
		}
		return  0;
	}
}
