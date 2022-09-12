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
package ghidra.app.util.bin.format.pdb2.pdbreader.msf;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Arrays;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.task.TaskMonitor;

/**
 * This class is the version of {@link Msf} for Microsoft v2.00 MSF.
 */
public class Msf200 extends AbstractMsf {

	private static final int PAGE_NUMBER_SIZE = 2;
	private static final byte[] IDENTIFICATION =
		"Microsoft C/C++ program database 2.00\r\n\u001aJG".getBytes();
	// Padding between IDENTIFICATION and pageSize
	private static final int IDENTIFICATION_PADDING = 2;

	private static final int PAGE_SIZE_OFFSET = IDENTIFICATION.length + IDENTIFICATION_PADDING;
	static final int NUM_REQUIRED_DETECTION_BYTES_200 = PAGE_SIZE_OFFSET + 4;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor
	 * @param file the {@link RandomAccessFile} to process as a {@link Msf200}
	 * @param filename name of {@code #file}
	 * @param monitor the TaskMonitor
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB
	 * @throws IOException upon file IO seek/read issues
	 * @throws PdbException upon unknown value for configuration
	 */
	public Msf200(RandomAccessFile file, String filename, TaskMonitor monitor,
			PdbReaderOptions pdbOptions)
			throws IOException, PdbException {
		super(file, filename, monitor, pdbOptions);
	}

	//==============================================================================================
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Static method used to detect the header that belongs to this class
	 * @param file the {@link RandomAccessFile} to process as a {@link Msf200}
	 * @return {@code true} if the header for this class is positively identified
	 * @throws IOException upon file IO seek/read issues
	 */
	static boolean detected(RandomAccessFile file) throws IOException {
		byte[] bytes = new byte[IDENTIFICATION.length];
		file.seek(0);
		file.read(bytes, 0, IDENTIFICATION.length);
		return Arrays.equals(bytes, IDENTIFICATION);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	public void create() {
		streamTable = new MsfStreamTable200(this);
		freePageMap = new MsfFreePageMap200(this);
		directoryStream = new MsfDirectoryStream200(this);
	}

	@Override
	public void configureParameters() throws PdbException {
		switch (pageSize) {
			case 0x400:
				log2PageSize = 10;
				freePageMapNumSequentialPage = 8;
				break;
			case 0x800:
				log2PageSize = 11;
				freePageMapNumSequentialPage = 4;
				break;
			case 0x1000:
				log2PageSize = 12;
				freePageMapNumSequentialPage = 1;
				break;
			default:
				throw new PdbException(String.format("Unknown page size: 0X%08X", pageSize));
		}
		pageSizeModMask = pageSize - 1;
	}

	//==============================================================================================
	// Class Internals
	//==============================================================================================
	@Override
	public void parseFreePageMapPageNumber(PdbByteReader reader) throws PdbException {
		currentFreePageMapFirstPageNumber = reader.parseShort();
	}

	@Override
	public void parseCurrentNumPages(PdbByteReader reader) throws PdbException {
		numPages = reader.parseShort();
	}

	@Override
	public int getPageNumberSize() {
		return PAGE_NUMBER_SIZE;
	}

	@Override
	public byte[] getIdentification() {
		return IDENTIFICATION;
	}

	@Override
	public int getPageSizeOffset() {
		return PAGE_SIZE_OFFSET;
	}

}
