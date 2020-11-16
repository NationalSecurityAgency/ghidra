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

/**
 * This class is the version of {@link AbstractMsf} for Microsoft v7.00 MSF.
 */
public class Msf700 extends AbstractMsf {

	private static final int PAGE_NUMBER_SIZE = 4;
	private static final byte[] IDENTIFICATION = "Microsoft C/C++ MSF 7.00\r\n\u001aDS".getBytes();
	// Padding between magic and pageSize
	private static final int IDENTIFICATION_PADDING = 3;

	private static final int PAGE_SIZE_OFFSET = IDENTIFICATION.length + IDENTIFICATION_PADDING;
	static final int NUM_REQUIRED_DETECTION_BYTES_700 = PAGE_SIZE_OFFSET + 4;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor.
	 * @param file The {@link RandomAccessFile} to process as a {@link Msf700}.
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB.
	 * @throws IOException Upon file IO seek/read issues.
	 * @throws PdbException Upon unknown value for configuration.
	 */
	public Msf700(RandomAccessFile file, PdbReaderOptions pdbOptions)
			throws IOException, PdbException {
		super(file, pdbOptions);
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	@Override
	void create() {
		streamTable = new MsfStreamTable700(this);
		freePageMap = new MsfFreePageMap700(this);
		directoryStream = new MsfDirectoryStream700(this);
	}

	@Override
	protected void parseFreePageMapPageNumber(PdbByteReader reader) throws PdbException {
		currentFreePageMapFirstPageNumber = reader.parseInt();
	}

	@Override
	protected void parseCurrentNumPages(PdbByteReader reader) throws PdbException {
		numPages = reader.parseInt();
	}

	@Override
	void configureParameters() throws PdbException {
		switch (pageSize) {
			case 0x200:
				log2PageSize = 9;
				freePageMapNumSequentialPage = 1;
				break;
			case 0x400:
				log2PageSize = 10;
				freePageMapNumSequentialPage = 1;
				break;
			case 0x800:
				log2PageSize = 11;
				freePageMapNumSequentialPage = 1;
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
	// Package-Protected Internals
	//==============================================================================================
	/**
	 * Static method used to detect the header that belongs to this class.
	 * @param file The RandomAccessFile to process as a {@link Msf700}.
	 * @return True if the header for this class is positively identified.
	 * @throws IOException Upon file IO seek/read issues.
	 */
	static boolean detected(RandomAccessFile file) throws IOException {
		byte[] bytes = new byte[IDENTIFICATION.length];
		file.seek(0);
		file.read(bytes, 0, IDENTIFICATION.length);
		return Arrays.equals(bytes, IDENTIFICATION);
	}

	//==============================================================================================
	// Class Internals
	//==============================================================================================
	@Override
	protected int getPageNumberSize() {
		return PAGE_NUMBER_SIZE;
	}

	@Override
	protected byte[] getIdentification() {
		return IDENTIFICATION;
	}

	@Override
	public int getPageSizeOffset() {
		return PAGE_SIZE_OFFSET;
	}

}
