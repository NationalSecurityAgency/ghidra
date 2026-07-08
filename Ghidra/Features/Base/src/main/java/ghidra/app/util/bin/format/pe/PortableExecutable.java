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
import ghidra.app.util.bin.format.Writeable;
import ghidra.app.util.bin.format.mz.DOSHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * A class to manage loading Portable Executables (PE).
 */
public class PortableExecutable implements Writeable {
	public static final String NAME = "PORTABLE_EXECUTABLE";
	public static boolean DEBUG = false;

	/**
	 * Indicates how sections of this PE are laid out in the underlying {@link ByteProvider}.
	 * Use {@link SectionLayout#FILE} when loading from a file, and {@link SectionLayout#MEMORY}
	 * when loading from a memory model (like an already-loaded program in Ghidra).
	 */
	public static enum SectionLayout {
		FILE, MEMORY
	}

	private BinaryReader reader;
	private DOSHeader dosHeader;
	private RichHeader richHeader;
	private NTHeader ntHeader;

	/**
	 * Constructs a new {@link PortableExecutable} using the specified byte provider and layout
	 *
	 * @param bp the {@link ByteProvider}
	 * @param layout specifies the layout of the underlying provider and governs RVA resolution
	 * @throws IOException if an I/O error occurs
	 */
	public PortableExecutable(ByteProvider bp, SectionLayout layout) throws IOException {
		this(bp, layout, true, false);
	}

	/**
	 * Constructs a new {@link PortableExecutable} using the specified byte provider and layout
	 * 
	 * @param bp the {@link ByteProvider}
	 * @param layout specifies the layout of the underlying provider and governs RVA resolution
	 * @param advancedProcess if true, the data directories are also processed
	 * @param parseCliHeaders if true, CLI headers are parsed (if present)
	 * @throws IOException if an I/O error occurs
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
				ntHeader = new NTHeader(reader, dosHeader.e_lfanew(), layout, parseCliHeaders);
				if (advancedProcess) {
					ntHeader.getOptionalHeader()
							.processDataDirectories(new MessageLog(), TaskMonitor.DUMMY);
				}
			}
			catch (InvalidNTHeaderException e) {
				Msg.debug(this, "Expected InvalidNTHeaderException, ignoring");
			}
			catch (ArrayIndexOutOfBoundsException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			return;
		}
	}

	/**
	 * {@return the DOS header from the PE image}
	 */
	public DOSHeader getDOSHeader() {
		return dosHeader;
	}

	/**
	 * {@return the rich header from the PE image}
	 */
	public RichHeader getRichHeader() {
		return richHeader;
	}

	/**
	 * {@return the NT header from the PE image}
	 */
	public NTHeader getNTHeader() {
		return ntHeader;
	}

	/**
	 * {@return the length of the {@link PortableExecutable} file in bytes}
	 */
	public long getFileLength() {
		return reader != null ? reader.length() : 0;
	}

	@Override
	public void write(RandomAccessFile raf, DataConverter dc) throws IOException {
		raf.seek(0);
		if (dosHeader != null) {
			dosHeader.write(raf, dc);
		}
		if (richHeader != null) {
			richHeader.write(raf, dc);
		}
		if (ntHeader != null) {
			ntHeader.write(raf, dc);
		}
	}
}
