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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
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
 * @see MsfDirectoryStream
 * @see MsfFreePageMap
 * @see MsfStreamTable
 */
public interface Msf extends AutoCloseable {

	/**
	 * Returns the filename
	 * @return the filename
	 */
	public String getFilename();

	/**
	 * Returns the TaskMonitor
	 * @return the monitor
	 */
	public TaskMonitor getMonitor();

	/**
	 * Check to see if this monitor has been canceled
	 * @throws CancelledException if monitor has been cancelled
	 */
	public void checkCancelled() throws CancelledException;

	/**
	 * Returns the page size employed by this {@link Msf}
	 * @return page size
	 */
	public int getPageSize();

	/**
	 * Returns the number of streams found in this {@link Msf}
	 * @return number of streams
	 */
	public int getNumStreams();

	/**
	 * Returns the file reader
	 * @return the file reader
	 */
	public MsfFileReader getFileReader();

	/**
	 * Closes resources used by this {@link Msf}
	 * @throws IOException under circumstances found when closing a {@link RandomAccessFile}
	 */
	@Override
	public void close() throws IOException;

	/**
	 * Returns the {@link MsfStream} specified by {@link Msf}
	 * @param streamNumber the number of the Stream to return.  Must be less than the number
	 *  of streams returned by {@link #getNumStreams()}
	 * @return {@link MsfStream} or {@code null} if no stream for the streamNumber
	 */
	public MsfStream getStream(int streamNumber);

	//==============================================================================================
	// Package-Protected Utilities
	//==============================================================================================
	/**
	 * Returns the value of the floor (greatest integer less than or equal to) of the result
	 *  upon dividing the dividend by a divisor which is the power-of-two of the log2Divisor
	 * @param dividend the dividend to the operator
	 * @param log2Divisor the log2 of the intended divisor value
	 * @return the floor of the division result
	 */
	static int floorDivisionWithLog2Divisor(int dividend, int log2Divisor) {
		return (dividend + (1 << log2Divisor) - 1) >> log2Divisor;
	}

	//==============================================================================================
	// Abstract Methods
	//==============================================================================================
	/**
	 * Method that returns the identification byte[] required by this format
	 * @return the minimum required number
	 */
	abstract byte[] getIdentification();

	/**
	 * Returns the offset (in bytes) of the PageSize within the header
	 * @return the offset of the PageSize within the header
	 */
	abstract int getPageSizeOffset();

	/**
	 * Deserializes the Free Page Map page number from the {@link PdbByteReader}
	 * @param reader {@link PdbByteReader} from which to read
	 * @throws PdbException upon not enough data left to parse
	 */
	abstract void parseFreePageMapPageNumber(PdbByteReader reader) throws PdbException;

	/**
	 * Deserializes the value of the number of pages in the MSF
	 * @param reader {@link PdbByteReader} from which to read
	 * @throws PdbException upon not enough data left to parse
	 */
	abstract void parseCurrentNumPages(PdbByteReader reader) throws PdbException;

	/**
	 * Method to create the following components: StreamTable, FreePageMap, and DirectoryStream.
	 */
	abstract void create();

	/**
	 * Method to set parameters for the file based on version and page size
	 * @throws PdbException upon unknown value for configuration
	 */
	abstract void configureParameters() throws PdbException;

	/**
	 * Method to get the size of the page number (in bytes) when serialized to disc
	 * @return the page size (in bytes)
	 */
	abstract int getPageNumberSize();

	//==============================================================================================
	// Class Internals
	//==============================================================================================
	/**
	 * Returns Log2 value of the page size employed by this MSF
	 * @return the Log2 value of the page size employed by this MSF
	 */
	int getLog2PageSize();

	/**
	 * Returns the the mask used for masking off the upper bits of a value use to get the
	 *  mod-page-size of the value (pageSizes must be power of two for this to work)
	 * @return the mask
	 */
	int getPageSizeModMask();

	/**
	 * Returns the number of pages found in sequence that compose the {@link MsfFreePageMap}
	 * (for this {@link Msf}) when on disk
	 * @return the number of sequential pages in the {@link MsfFreePageMap}
	 */
	int getNumSequentialFreePageMapPages();

	/**
	 * Returns the page number containing the header of this MSF file
	 * @return the header page number
	 */
	int getHeaderPageNumber();

	/**
	 * Returns the stream number containing the directory of this MSF file
	 * @return the directory stream number
	 */
	int getDirectoryStreamNumber();

	//==============================================================================================
	// Internal Data Methods
	//==============================================================================================
	/**
	 * Returns the number of pages contained in this MSF file
	 * @return the number of pages in this MSF
	 */
	int getNumPages();

	/**
	 * Returns the first page number of the current Free Page Map
	 * @return the first page number of the current Free Page Map
	 */
	int getCurrentFreePageMapFirstPageNumber();

	/**
	 * Performs required initialization of this class, needed before trying to read any
	 *  Streams.  Initialization includes deserializing the remainder of the header as well
	 *  as stream directory information
	 * @throws IOException on file seek or read, invalid parameters, bad file configuration, or
	 *  inability to read required bytes
	 * @throws PdbException upon unknown value for configuration
	 * @throws CancelledException upon user cancellation
	 */
	void deserialize() throws IOException, PdbException, CancelledException;

}
