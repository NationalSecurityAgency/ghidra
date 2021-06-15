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

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class represents the the Multi-Stream Format File used for Windows PDB files.
 *  We have intended to implement to the Microsoft PDB API (source); see the API for truth.
 *  <P>
 *  Derived classes represents the real formats.  The file format represents a kind of
 *  file system within a file and is based upon pages in order to try to optimize
 *  disk I/O and system update.  There was also a mechanism to allow for ping-ponged
 *  commit for file updates.  Our implementation is only used for reading the file
 *  format; it is not intended to write or modify an existing file.  Much work would
 *  need to be done to create a version with those capabilities.
 *  <P>
 * The file format consists of a first page that contains identifying header information
 *  that consists of an ID string, and limited parameters needed for pointing to
 *  directory information and the Free Page Map.  We do not use the latter information.
 *  <P>
 * Note that the API (source) description on indicates that the original tools could
 *  have been built with different parameter sets, which also impacts the page size
 *  and other parameters for the format.  We intended to create a reader that is capable
 *  of reading any of these files.
 *  <P>
 * The file header generally contains the following information, but their sizes on disk
 *  depends on whether this is a file of the older or newer format.  Generally, the fields follow:
 * <PRE>
 *      Field          Description      Size on Disk Old   Size on Disk New   Java Type
 *      ID               ID "string"           42              29               byte[]
 *                         identifying
 *                         old vs. new
 *      ID padding       Padding between        2               3               N/A
 *                         ID and next
 *                         field
 *      Page Size        Power-of-2 page        4               4               int
 *                         size used
 *      Free Page Map    Page Number of         2               4               int
 *                         current free
 *                         page map
 *      Number of Pages  Number of pages        2               4               int
 *                         currently used
 *                         in the file
 *      Serialized       Sequence of page		 
 *        info about       numbers
 *        directory
 *        stream:
 *         -Directory    Num of bytes          4+4              4               int
 *           Length      + (opt addr field)
 *         -Page number  Page number that      2+2              4
 *                         contains page
 *                         numbers for the
 *                         stream; see note
 *                         below regarding new!
 * </PRE>
 * The file directory is stored in stream 0, which has its information persisted in
 *  the header as described above.  However, for the newest format, the page (pointed
 *  to in the header) for the directory stream has an extra level of indirection.  The
 *  page contains page numbers, whose pages contain contain page numbers for the
 *  directory stream.  Note that the page numbers listed on any of these pages have
 *  the following format on disk:
 * <PRE>
 *      Field          Description      Size on Disk Old   Size on Disk New   Java Type
 *      Page Number    Page Number             2+2              4               int
 *                     + (opt addr field)
 * </PRE>
 * The directory stream contain StreamTable information, which is serialized into the
 *  directory stream as follows:
 * <PRE>
 *   numStreams
 *   streamLength[numStreams]
 *   serializedStream[numStreams]
 * </PRE>
 * Note that the StreamTable parsed from the directory stream does not have the most
 *  up-to-date information about stream 0 (the directory stream); the up-to-date
 *  version of stream 0 is what was persisted in the header.  So after the StreamTable
 *  has been deserialized from the directory stream, the stream 0 information in the
 *  StreamTable gets overwritten with the stream 0 that we had already obtained.
 * <P>
 * @see MsfFileReader
 * @see MsfStream
 * @see AbstractMsfDirectoryStream
 * @see AbstractMsfFreePageMap
 * @see AbstractMsfStreamTable
 */
public abstract class AbstractMsf implements AutoCloseable {

	private static final int HEADER_PAGE_NUMBER = 0;
	private static final int DIRECTORY_STREAM_NUMBER = 0;

	//==============================================================================================
	// Internals
	//==============================================================================================
	protected String filename;
	protected MsfFileReader fileReader;

	protected AbstractMsfFreePageMap freePageMap;
	protected AbstractMsfDirectoryStream directoryStream;
	protected AbstractMsfStreamTable streamTable;

	protected int pageSize;
	protected int log2PageSize;
	protected int freePageMapNumSequentialPage;
	protected int pageSizeModMask;

	protected int currentFreePageMapFirstPageNumber;
	protected int numPages = 1; // Set to 1 to allow initial read

	protected PdbReaderOptions pdbOptions;

	//==============================================================================================
	// API
	//==============================================================================================
	/**
	 * Constructor for this class.
	 * @param file The {@link RandomAccessFile} to process for this class.
	 * @param pdbOptions {@link PdbReaderOptions} used for processing the PDB.
	 * @throws IOException Upon file IO seek/read issues.
	 * @throws PdbException Upon unknown value for configuration.
	 */
	public AbstractMsf(RandomAccessFile file, PdbReaderOptions pdbOptions)
			throws IOException, PdbException {
		// Do initial configuration with largest possible page size.  ConfigureParameters will
		//  be called again later with the proper pageSize set.
		this.pdbOptions = pdbOptions;
		pageSize = 0x1000;
		configureParameters();
		// Create components.
		fileReader = new MsfFileReader(this, file);
		create();
	}

	/**
	 * Returns the page size employed by this {@link AbstractMsf}.
	 * @return Page size.
	 */
	public int getPageSize() {
		return pageSize;
	}

	/**
	 * Returns the number of streams found in this {@link AbstractMsf}.
	 * @return Number of streams.
	 */
	public int getNumStreams() {
		return streamTable.getNumStreams();
	}

	/**
	 * Returns the {@link MsfStream} specified by {@link AbstractMsf}.
	 * @param streamNumber The number of the Stream to return.  Must be less than the number
	 *  of streams returned by {@link #getNumStreams()}.
	 * @return {@link MsfStream} or {@code null} if no stream for the streamNumber.
	 */
	public MsfStream getStream(int streamNumber) {
		return streamTable.getStream(streamNumber);
	}

	/**
	 * Closes resources used by this {@link AbstractMsf}.
	 * @throws IOException Under circumstances found when closing a {@link RandomAccessFile}.
	 */
	@Override
	public void close() throws IOException {
		if (fileReader != null) {
			fileReader.close();
		}
	}

	//==============================================================================================
	// Package-Protected Utilities
	//==============================================================================================
	/**
	 * Returns the value of the floor (greatest integer less than or equal to) of the result
	 *  upon dividing the dividend by a divisor which is the power-of-two of the log2Divisor.
	 * @param dividend The dividend to the operator
	 * @param log2Divisor The log2 of the intended divisor value.
	 * @return The floor of the division result.
	 */
	static final int floorDivisionWithLog2Divisor(int dividend, int log2Divisor) {
		return (dividend + (1 << log2Divisor) - 1) >> log2Divisor;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Method that returns the identification byte[] required by this format.
	 * @return The minimum required number.
	 */
	protected abstract byte[] getIdentification();

	/**
	 * Returns the offset (in bytes) of the PageSize within the header.
	 * @return The offset of the PageSize within the header.
	 */
	protected abstract int getPageSizeOffset();

	/**
	 * Deserializes the Free Page Map page number from the {@link PdbByteReader}.
	 * @param reader {@link PdbByteReader} from which to read.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseFreePageMapPageNumber(PdbByteReader reader) throws PdbException;

	/**
	 * Deserializes the value of the number of pages in the MSF.
	 * @param reader {@link PdbByteReader} from which to read.
	 * @throws PdbException Upon not enough data left to parse.
	 */
	protected abstract void parseCurrentNumPages(PdbByteReader reader) throws PdbException;

	/**
	 * Method to create the following components: StreamTable, FreePageMap, and DirectoryStream.
	 *  FreePageMap.
	 */
	abstract void create();

	/**
	 * Method to set parameters for the file based on version and page size.
	 * @throws PdbException Upon unknown value for configuration.
	 */
	abstract void configureParameters() throws PdbException;

	/**
	 * Method to get the size of the page number (in bytes) when serialized to disc.
	 * @return The page size (in bytes).
	 */
	abstract protected int getPageNumberSize();

	//==============================================================================================
	// Class Internals
	//==============================================================================================
	/**
	 * Returns Log2 value of the page size employed by this MSF.
	 * @return The Log2 value of the page size employed by this MSF.
	 */
	protected int getLog2PageSize() {
		return log2PageSize;
	}

	/**
	 * Returns the the mask used for masking off the upper bits of a value use to get the
	 *  mod-page-size of the value (pageSizes must be power of two for this to work).
	 * @return The mask.
	 */
	protected int getPageSizeModMask() {
		return pageSizeModMask;
	}

	/**
	 * Returns the number of pages found in sequence that compose the {@link AbstractMsfFreePageMap}
	 * (for this {@link AbstractMsf}) when on disk. 
	 * @return The number of sequential pages in the {@link AbstractMsfFreePageMap}.
	 */
	protected int getNumSequentialFreePageMapPages() {
		return freePageMapNumSequentialPage;
	}

	/**
	 * Returns the page number containing the header of this MSF file.
	 * @return The header page number.
	 */
	protected int getHeaderPageNumber() {
		return HEADER_PAGE_NUMBER;
	}

	/**
	 * Returns the stream number containing the directory of this MSF file. 
	 * @return The directory stream number.
	 */
	protected int getDirectoryStreamNumber() {
		return DIRECTORY_STREAM_NUMBER;
	}

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Returns the number of pages contained in this MSF file.
	 * @return The number of pages in this MSF.
	 */
	protected int getNumPages() {
		return numPages;
	}

	/**
	 * Returns the first page number of the current Free Page Map.
	 * @return The first page number of the current Free Page Map.
	 */
	protected int getCurrentFreePageMapFirstPageNumber() {
		return currentFreePageMapFirstPageNumber;
	}

	/**
	 * Performs required initialization of this class, needed before trying to read any
	 *  Streams.  Initialization includes deserializing the remainder of the header as well
	 *  as stream directory information.
	 * @param monitor {@link TaskMonitor} used for checking cancellation.
	 * @throws IOException On file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes.
	 * @throws PdbException Upon unknown value for configuration.
	 * @throws CancelledException Upon user cancellation.
	 */
	protected void deserialize(TaskMonitor monitor)
			throws IOException, PdbException, CancelledException {
		byte[] bytes = new byte[getPageSize()];
		fileReader.read(getHeaderPageNumber(), 0, getPageSize(), bytes, 0);

		PdbByteReader reader = new PdbByteReader(bytes);
		reader.setIndex(getPageSizeOffset());
		pageSize = reader.parseInt();
		parseFreePageMapPageNumber(reader);
		parseCurrentNumPages(reader);
		configureParameters();

		directoryStream.deserializeStreamInfo(reader, monitor);

		// Do not need FreePageMap for just reading files.
		freePageMap.deserialize(monitor);
		// For debug: freePageMap.dump();

		streamTable.deserialize(directoryStream, monitor);
	}

}
