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
package db.buffers;

import java.io.*;
import java.util.*;

import ghidra.util.BigEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.datastruct.IntSet;
import ghidra.util.exception.*;
import ghidra.util.task.*;

/**
 * <code>LocalBufferFile</code> implements a BufferFile as block-oriented
 * random-access file.  This type of buffer file supports save-as but does
 * not support the save operation.
 */
public class LocalBufferFile implements BufferFile {
//	static final Logger log = Logger.getLogger(LocalBufferFile.class);

	static final long MAGIC_NUMBER = 0x2f30312c34292c2aL;

	public static final String BUFFER_FILE_EXTENSION = ".gbf";
	public static final String PRESAVE_FILE_EXT = ".ps";
	public static final String PRESAVE_FILE_PREFIX = "tmp";
	public static final String TEMP_FILE_EXT = ".tmp";

	private static final String STRING_ENCODING = "UTF-8";

// ?? Should be changed !!
	private static final int MINIMUM_BLOCK_SIZE = 128;

	private static final Random random = new Random();

	/**
	 * Current file header format version number.
	 * The third field of the file header indicates a 
	 * format version which indicates how the header
	 * is formatted.
	 */
	private static final int HEADER_FORMAT_VERSION = 1;

	// 
	// The first block is reserved for use by the BlockFile header.
	// The format of this header is determined by the Field #3.  
	//
	// FILE FORMAT - VERSION 1
	// 
	// A file header is contained within the first buffer at offset 0 within the file.
	// This header contains the following fields:
	// 
	// 1. Magic number (8,long)
	// 2. File ID (8,long)
	// 3. Block file header format version (4,int) = 1
	// 5. Block size (4,int)
	// 6. First free block index (4,int)
	// 7. User-defined parameter count (4,int)
	// 8. User-defined parameters stored as:
	//       * Parm name length (4,int)
	//       * Parm name (?,char[])
	//       * Parm value (4,int)
	//    Parameter space is limited by buffer size.
	// 
	// In Version 1 - the first available user buffer immediately follows the file 
	// header block (i.e., buffer index 0 corresponds to block index 1).
	//
	// Each user block has the following prefix data:
	// 1. Flags (1,byte)
	//   * Bit 0: 1=empty block, 0=not empty
	// 2. DataBuffer ID (4,int) if not empty, or next empty buffer index if empty
	//        (-1 indicates last empty buffer)
	//

	// File Header offset where File ID is stored
	private static final int FILE_ID_OFFSET = 8;

	// Number of bytes added to buffer to allow for storage of flag bits.
	private static final int BUFFER_PREFIX_SIZE = 5;

	// Number of header bytes before the user-defined parameter area
	private static final int VER1_FIXED_HEADER_LENGTH = 32;

	// Buffer Flags bits
	private static final byte EMPTY_BUFFER = 0x01;

	static final int MAX_BUFFER_INDEX = Integer.MAX_VALUE - 1;

	/**
	 * <code>userParms</code> contains application parameters which correspond to
	 * this buffer file.  This list is established for 
	 * an existing buffer file when the readHeader is invoked.  For a non-temporary 
	 * writable buffer file, this list is flushed to the file when either close or
	 * setReadOnly is invoked.
	 */
	private Hashtable<String, Integer> userParms = new Hashtable<>();

	/**
	 * <code>freeIndexes</code> contains those buffer indexes which are free/empty
	 * and may be re-used in an update of this file.  This list is established for 
	 * an existing buffer file when the readHeader is invoked.  For a non-temporary 
	 * writable buffer file, this list is flushed to the file when either close or
	 * setReadOnly is invoked.
	 */
	private int[] freeIndexes = new int[0];

	/**
	 * <code>file</code> is the underlying storage file for this buffer file.
	 */
	private File file;

	/**
	 * <code>raf</code> is the random-access object for the underlying file.
	 */
	private RandomAccessFile raf;

	/**
	 * <code>activeBlockStream</code> provides a handle to the active 
	 * OutputBlockStream used to update file via raf.  This should be
	 * checked during {@link #close()} to guard against partially 
	 * written file.  A LocalOutputBlockStream should only be used
	 * for files open for writing (i.e., !readOnly).
	 */
	private volatile LocalOutputBlockStream activeOutputBlockStream;

	/**
	 * When <code>temporary</code> is true and this file is writable (!readOnly)
	 * it will be deleted when disposed or closed.
	 */
	private boolean temporary = false;

	/**
	 * <code>fileId</code> corresponds to a random file ID assigned to this file.
	 * This file ID can be used as an integrity check when applying version files
	 * to a specific buffer file.
	 */
	private long fileId;

	/**
	 * If <code>readOnly</code> is true, this file may not be modified 
	 * via the buffer put method.  
	 * A read-only file may be considered "updateable" if the canSave
	 * method returns true.  The term "updateable" means that a Save file
	 * can be obtained via the getSaveFile method.
	 */
	private boolean readOnly;

	/**
	 * <code>blockSize</code> is the "actual" size of each block within this
	 * file. The <code>blockSize</code> equals the <code>bufferSize</code> plus
	 * a few bytes used for flags and to identify the user-level buffer ID.
	 */
	private int blockSize;

	/**
	 * <code>bufferSize</code> is the "usable" buffer space within each
	 * block of this file.
	 */
	private int bufferSize;

	/**
	 * <code>bufferCount</code> indicates the number of buffer which have been 
	 * allocated within this file and directly reflects the size of the file.
	 * The value corresponds to the next buffer index which can be allocated once all
	 * free indexes have been utilized.  When an existing file is opened, this value
	 * is computed based upon the file length and the buffer size.
	 */
	private int bufferCount = 0;

	/**
	 * Create a temporary read/write block file.
	 * @param bufferSize user buffer size
	 * @param tmpPrefix temporary file prefix
	 * @param tmpExtension temporary file extension
	 */
	LocalBufferFile(int bufferSize, String tmpPrefix, String tmpExtension) throws IOException {
		this.bufferSize = bufferSize;
		this.blockSize = bufferSize + BUFFER_PREFIX_SIZE;
		this.readOnly = false;
		this.temporary = true;
		file = File.createTempFile(tmpPrefix, tmpExtension);
//		file.deleteOnExit();
		raf = new RandomAccessFile(file, "rw");
	}

	/**
	 * Create a new buffer file for writing.
	 * If the file does not exist and create is true, a new buffer file will
	 * be created.
	 * The file will be saved when closed.
	 * @param file buffer file
	 * @param bufferSize user buffer size
	 * @throws DuplicateFileException if file already exists
	 * @throws IOException if an I/O error occurs during file creation
	 */
	public LocalBufferFile(File file, int bufferSize) throws IOException {
		if (file.exists()) {
			throw new DuplicateFileException("File " + file + " already exists");
		}
		this.file = file;
		this.bufferSize = bufferSize;
		this.blockSize = bufferSize + BUFFER_PREFIX_SIZE;
		this.readOnly = false;
		raf = new RandomAccessFile(file, "rw");

		fileId = random.nextLong();
	}

	/**
	 * Open an existing block file.
	 * @param file block file
	 * @param readOnly if true the file will be opened read-only
	 * @throws IOException if an IO error occurs or the incorrect magicNumber
	 * was read from the file.
	 */
	public LocalBufferFile(File file, boolean readOnly) throws IOException {
		this.file = file;
		this.readOnly = readOnly;
		raf = new RandomAccessFile(file, readOnly ? "r" : "rw");

		readHeader();
	}

	/**
	 * Modify an existing buffer file.
	 * WARNING! Use with extreme caution since this modifies
	 * the original file and could destroy data if used
	 * improperly.
	 * @param file
	 * @param bufferIndex
	 * @param buf
	 * @throws IOException
	 */
	public static void poke(File file, int bufferIndex, DataBuffer buf) throws IOException {
		LocalBufferFile bf = new LocalBufferFile(file, false);
		try {
			bf.put(buf, bufferIndex);
		}
		finally {
			bf.close();
		}
	}

	/**
	 * Read a buffer from an existing buffer file.
	 * @param file
	 * @param bufferIndex
	 * @return
	 * @throws IOException
	 */
	public static DataBuffer peek(File file, int bufferIndex) throws IOException {
		LocalBufferFile bf = new LocalBufferFile(file, false);
		try {
			DataBuffer buf = new DataBuffer(bf.getBufferSize());
			bf.get(buf, bufferIndex);
			return buf;
		}
		finally {
			bf.close();
		}
	}

	/**
	 * Returns the physical file associated with this BufferFile.
	 */
	public File getFile() {
		return file;
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return readOnly;
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#getParameter(java.lang.String)
	 */
	@Override
	public int getParameter(String name) throws NoSuchElementException {
		Object obj = userParms.get(name);
		if (obj == null) {
			throw new NoSuchElementException(name);
		}
		return ((Integer) obj).intValue();
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#setParameter(java.lang.String, int)
	 */
	@Override
	public void setParameter(String name, int value) {
		userParms.put(name, new Integer(value));
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#clearParameters()
	 */
	@Override
	public void clearParameters() {
		userParms.clear();
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#getParameterNames()
	 */
	@Override
	public String[] getParameterNames() {
		ArrayList<String> list = new ArrayList<>();
		Enumeration<String> it = userParms.keys();
		while (it.hasMoreElements()) {
			list.add(it.nextElement());
		}
		String[] names = new String[list.size()];
		list.toArray(names);
		return names;
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#getFreeIndexes()
	 */
	@Override
	public int[] getFreeIndexes() {
		return freeIndexes.clone();
	}

	/*
	 * @see ghidra.framework.store.buffers.BufferFile#setFreeIndexes(int[])
	 */
	@Override
	public void setFreeIndexes(int[] indexes) {
		freeIndexes = indexes.clone();
		Arrays.sort(freeIndexes);
	}

	/**
	 * @return the file ID assigned to this file.
	 */
	long getFileId() {
		return fileId;
	}

	/**
	 * Assigns the file ID for this file.  This should only be done
	 * when reconstructing a file.
	 * @param fileId file ID
	 */
	void setFileId(long id) {
		fileId = id;
	}

	/**
	 * @return number of buffers countained within this file
	 */
	int getBufferCount() {
		return bufferCount;
	}

	/**
	 * Assigns the buffer count for this file.  This should only be done
	 * when reconstructing a file.
	 * @param count number of valid buffers contained within this file
	 */
	void setBufferCount(int count) {
		bufferCount = count;
	}

	/**
	 * Set the temporary status of this buffer file.
	 * Temporary buffer files are deleted when closed.
	 * @param isTemporary
	 */
	void setTemporary(boolean isTemporary) {
		temporary = isTemporary;
	}

	/**
	 * Rename underlying file
	 * @param newFile
	 * @return true if rename successful
	 * @throws IOException
	 */
	boolean renameFile(File newFile) throws IOException {
		if (raf != null) {
			raf.close();
		}
		if (file.renameTo(newFile)) {
			file = newFile;
			if (raf != null) {
				raf = new RandomAccessFile(file, "rw");
			}
			return true;
		}
		return false;
	}

	/**
	 * Set random access file (raf) position to the file block containing the specified buffer 
	 * identified by its bufferIndex.  It is important to understand the distinction between 
	 * blocks and buffers, where buffers are stored within file blocks which are slightly larger.  
	 * In addition, the first file block stores the file header and is not used to store a buffer.
	 * @param bufferIndex buffer index
	 * @return file block index (=bufferIndex+1)
	 * @throws IOException
	 */
	private int seekBufferBlock(int bufferIndex) throws IOException {
		// Perform long multiplication to support file sizes greater than 2-GBytes
		// Add 1 to buffer index to obtain block index (first useable buffer, buffer#0, is 
		// contained within block#1 since block#0 contains file header)
		int blockIndex = bufferIndex + 1;
		long offset = (long) blockIndex * (long) blockSize;
		raf.seek(offset);
		return blockIndex;
	}

	/**
	 * Set random access file (raf) position to the specified file block and offset
	 * within that block.  NOTE: block#0 contains the file header.
	 * @param blockIndex block index
	 * @param offsetWithinBlock offset within file block
	 * @throws IOException
	 */
	private void seekBlock(int blockIndex, int offsetWithinBlock) throws IOException {
		// Perform long multiplication to support file sizes greater than 2-GBytes
		long offset = ((long) blockIndex * (long) blockSize) + offsetWithinBlock;
		raf.seek(offset);
	}

	/**
	 * Read file header and initialize the user parameter and free buffer index lists.
	 * @throws IOException if an I/O error occurs while reading file
	 */
	private void readHeader() throws IOException {

		seekBlock(0, 0);

		// Check magic number
		long magicNumber = raf.readLong();
		if (magicNumber != MAGIC_NUMBER) {
			throw new IOException("Unrecognized file format");
		}

		// Read file ID
		fileId = raf.readLong();

		// Check file format version	
		int headerFormatVersion = raf.readInt();
		if (headerFormatVersion != HEADER_FORMAT_VERSION) {
			throw new IOException("Unrecognized file format");
		}

		// Read buffer size, free buffer count, and first free buffer index
		blockSize = raf.readInt();
		bufferSize = blockSize - BUFFER_PREFIX_SIZE;
		int firstFreeBufferIndex = raf.readInt();
		long len = raf.length();
		if ((len % blockSize) != 0) {
			throw new IOException("Corrupt file");
		}
		bufferCount = (int) (len / blockSize) - 1;

		// Read user-defined integer parameters values
		int cnt = raf.readInt();
		clearParameters();
		for (int i = 0; i < cnt; i++) {
			int nameLen = raf.readInt();
			byte[] nameBytes = new byte[nameLen];
			raf.read(nameBytes);
			setParameter(new String(nameBytes, STRING_ENCODING), raf.readInt());
		}
		buildFreeIndexList(firstFreeBufferIndex);
	}

	/**
	 * Store the user parameter and free buffer index lists and write the 
	 * file header.
	 * @throws IOException if an I/O error occurs while writing file
	 */
	private void writeHeader() throws IOException {

		if (readOnly) {
			throw new IOException("File is read-only");
		}

		// Output free list
		int prev = -1;
		for (int index : freeIndexes) {
			putFreeBlock(index, prev);
			prev = index;
		}

		seekBlock(0, 0);

		// Write Header values
		raf.writeLong(MAGIC_NUMBER);
		raf.writeLong(fileId);
		raf.writeInt(HEADER_FORMAT_VERSION);
		raf.writeInt(blockSize);
		raf.writeInt(prev);

		// Write user parameter count and values
		String[] parmNames = getParameterNames();
		raf.writeInt(parmNames.length);
		int cnt = VER1_FIXED_HEADER_LENGTH;
		for (String parmName : parmNames) {
			byte[] nameBytes = parmName.getBytes(STRING_ENCODING);
			cnt += 8 + nameBytes.length;
			if (cnt > bufferSize) {
				throw new IOException("Buffer size too small");
			}
			raf.writeInt(nameBytes.length);
			raf.write(nameBytes);
			raf.writeInt(getParameter(parmName));
		}
	}

	/**
	 * Build free index stack from file.
	 */
	private void buildFreeIndexList(int firstFreeBufferIndex) throws IOException {

		ArrayList<Integer> freeIndexList = new ArrayList<>();
		int nextIndex = firstFreeBufferIndex;
		while (nextIndex >= 0) {

			// Push index on stack
			freeIndexList.add(new Integer(nextIndex));

			// Read block to get next index
			seekBufferBlock(nextIndex);

			// Read version 1 buffer prefix and next empty index
			byte flags = raf.readByte();
			if ((flags & EMPTY_BUFFER) == 0) {
				throw new IOException("Corrupt file");
			}
			nextIndex = raf.readInt();
		}

		int[] newFreeIndexes = new int[freeIndexList.size()];
		for (int i = 0; i < newFreeIndexes.length; i++) {
			newFreeIndexes[i] = freeIndexList.get(i).intValue();
		}
		setFreeIndexes(newFreeIndexes);
	}

	/**
	 * Update a storage block as free and link to the next free block.
	 * @param index block index of free block
	 * @param nextFreeIndex block index of next free block, a -1 should be
	 * specified to mark the end of the linked list.
	 * @throws IOException thrown if an IO error occurs
	 */
	void putFreeBlock(int index, int nextFreeIndex) throws IOException {

		if (index > bufferCount) {
			throw new EOFException(
				"Free buffer index too large (" + index + " > " + bufferCount + ")");
		}
		if (index == bufferCount) {
			++bufferCount;
		}

		// Write version 1 buffer prefix
		seekBufferBlock(index);

		raf.writeByte(EMPTY_BUFFER);
		raf.writeInt(nextFreeIndex);
	}

	/**
	 * Generate a DataBuffer instance which corresponds to the specified block
	 * based upon LocalBufferFile block usage.
	 * @param block the buffer file block to be converted
	 * @return DataBuffer instance or null if head block.  If empty block
	 * DataBuffer will have null data
	 */
	public static DataBuffer getDataBuffer(BufferFileBlock block) {
		int blockIndex = block.getIndex();
		if (blockIndex <= 0) {
			return null; // head or invalid block
		}
		byte[] blockData = block.getData();
		byte flags = blockData[0];

		DataBuffer buf = new DataBuffer();

		if (flags == EMPTY_BUFFER) {
			buf.setId(-1);
			buf.setEmpty(true);
			return buf;
		}

		int bufferId = BigEndianDataConverter.INSTANCE.getInt(blockData, 1);
		buf.setId(bufferId);

		byte[] bufData = new byte[blockData.length - BUFFER_PREFIX_SIZE];
		System.arraycopy(blockData, BUFFER_PREFIX_SIZE, bufData, 0, bufData.length);
		buf.setData(bufData);

		return buf;
	}

	/**
	 * Generate a BufferFileBlock instance which corresponds to the specified DataBuffer
	 * based upon LocalBufferFile block usage.  This should generally not be used for writing
	 * empty blocks since they will not be properly linked which is normally handled during 
	 * header flush which is performed by BufferFile close on files being written. 
	 * @param buf the data buffer to be converted
	 * @param bufferSize data buffer size used for integrity check and generating empty buffer
	 * @return BufferFileBlock instance.
	 */
	public static BufferFileBlock getBufferFileBlock(DataBuffer buf, int bufferSize) {

		byte[] data = buf.data;
		boolean empty = buf.isEmpty();
		if (!empty && data.length != bufferSize) {
			throw new IllegalArgumentException("Bad buffer size");
		}

		int blockIndex = buf.getId() + 1;

		byte[] bytes = new byte[bufferSize + BUFFER_PREFIX_SIZE];
		bytes[0] = empty ? EMPTY_BUFFER : 0; // set empty flag
		BigEndianDataConverter.INSTANCE.putInt(bytes, 1, buf.getId());
		if (!empty) {
			System.arraycopy(data, 0, bytes, BUFFER_PREFIX_SIZE, data.length);
		}
		return new BufferFileBlock(blockIndex, bytes);
	}

	/*
	 * @see db.buffers.BufferFile#get(db.buffers.DataBuffer, int)
	 */
	@Override
	public synchronized DataBuffer get(DataBuffer buf, int index) throws IOException {

		if (index > bufferCount) {
			throw new EOFException("Buffer index too large (" + index + " > " + bufferCount + ")");
		}
		if (raf == null) {
			throw new ClosedException();
		}

		seekBufferBlock(index);

		// Read version 1 buffer prefix
		byte flags = raf.readByte();

		// Read buffer ID
		buf.setId(raf.readInt());

		if ((flags & EMPTY_BUFFER) != 0) {
			buf.setEmpty(true);
			buf.setId(-1);
		}
		else {
			buf.setEmpty(false);
			byte[] data = buf.data;
			if (data == null) {
				data = new byte[bufferSize];
				buf.data = data;
			}
			else if (data.length != bufferSize) {
				throw new IllegalArgumentException("Bad buffer size");
			}
			// Non-empty Buffer - read data	
			raf.readFully(data);
		}
		buf.setDirty(false);
		return buf;
	}

	/*
	 * @see db.buffers.BufferFile#put(db.buffers.DataBuffer, int)
	 */
	@Override
	public synchronized void put(DataBuffer buf, int index) throws IOException {

		if (readOnly) {
			throw new IOException("File is read-only");
		}
		if (raf == null) {
			throw new ClosedException();
		}

		if (index > MAX_BUFFER_INDEX) {
			throw new EOFException("Buffer index too large, exceeds max-int");
		}

		byte[] data = buf.data;
		boolean empty = buf.isEmpty();
		if (!empty && data.length != bufferSize) {
			throw new IllegalArgumentException("Bad buffer size");
		}

		seekBufferBlock(index);

		// Write block
		if (empty) {
			raf.writeByte(EMPTY_BUFFER); // Empty flag only
			raf.writeInt(buf.getId()); // ID
		}
		else {
			raf.writeByte(0); // Clear Flags
			raf.writeInt(buf.getId()); // ID

			// Write data
			raf.write(data, 0, bufferSize);
		}

		if (index >= bufferCount) {
			// we must assume that any buffers starting with bufferCount upto index will
			// be accounted for in the ultimate free-list maintained outside the buffer file.
			bufferCount = index + 1;
		}
	}

	/*
	 * @see db.buffers.BufferFile#getBufferSize()
	 */
	@Override
	public int getBufferSize() {
		return bufferSize;
	}

	/*
	 * @see db.buffers.BufferFile#getIndexCount()
	 */
	@Override
	public int getIndexCount() {
		return bufferCount;
	}

	/**
	 * Truncate the buffer file length to the specified index count.
	 * @param indexCount
	 */
	void truncate(int indexCount) throws IOException {

		if (readOnly) {
			throw new IOException("File is read-only");
		}

		long size = (indexCount + 1) * blockSize;
		raf.setLength(size);
		this.bufferCount = indexCount;
	}

	/**
	 * Write all unwritten data to the file prior to closing.
	 * @return true if flush was performed, false if not required.
	 * @throws IOException thrown if flush failed
	 */
	boolean flush() throws IOException {

		if (raf == null || readOnly || temporary) {
			return false;
		}

		// write header
		writeHeader();

		// Adjust file length
		long len = raf.length();
		long d = len % blockSize;
		if (d != 0) {
			raf.setLength(len - d + blockSize);
		}

		try {
			raf.getFD().sync();
		}
		catch (SyncFailedException e) {
			// Sync not supported - we tried our best
		}

		return true;
	}

	/*
	 * @see db.buffers.BufferFile#dispose()
	 */
	@Override
	public void dispose() {
		try {
			if (!readOnly) {
				delete();
			}
			else {
				close();
			}
		}
		catch (Throwable t) {
			Msg.error(this, t);
		}
		finally {
			if (activeOutputBlockStream != null) {
				try {
					// force closure of active block stream
					activeOutputBlockStream.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			activeOutputBlockStream = null;
		}
	}

	/*
	 * @see java.lang.Object#finalize()
	 */
	@Override
	protected void finalize() throws Throwable {
		dispose();
		super.finalize();
	}

	/*
	 * @see db.buffers.BufferFile#setReadOnly()
	 */
	@Override
	public synchronized boolean setReadOnly() throws IOException {

		if (!flush()) {
			return false;
		}

		raf.close();
		raf = new RandomAccessFile(file, "r");
		readOnly = true;

		return true;
	}

	/**
	 * @return true if this is a temporary buffer file
	 */
	boolean isTemporary() {
		return temporary;
	}

	/**
	 * @return true if buffer file is closed
	 */
	boolean isClosed() {
		return raf == null;
	}

	/*
	 * @see db.buffers.BufferFile#close()
	 */
	@Override
	public synchronized void close() throws IOException {
		if (raf == null) {
			return;
		}

		boolean commit = false;
		try {
			if (activeOutputBlockStream != null) {
				// active block stream was not closed properly
				try {
					activeOutputBlockStream.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
			else {
				commit = flush();
			}
			raf.close();
		}
		finally {
			raf = null;
			if (!readOnly && !commit) {
				// commit failed
				file.delete();
				if (activeOutputBlockStream != null) {
					// block stream forced closed above but need to throw critical error
					activeOutputBlockStream = null;
					throw new IOException("active block stream was not closed properly");
				}
			}
		}
	}

	/*
	 * @see db.buffers.BufferFile#delete()
	 */
	@Override
	public synchronized boolean delete() {

		if (raf == null || readOnly) {
			return false;
		}

		boolean success = false;
		try {
			try {
				raf.close();
			}
			catch (IOException e) {
				// ignored
			}
			raf = null;
		}
		finally {
			success = file.delete();
		}
		return success;
	}

	/**
	 * Clone this buffer file to the specified file.  The file must not 
	 * already exist.  If the operation is cancelled or an error occurs
	 * the file is not created. 
	 * @param destinationFile destination file
	 * @param monitor progress monitor
	 * @throws IOException if IO error occurs.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public void clone(File destinationFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		LocalBufferFile destBf = new LocalBufferFile(destinationFile, bufferSize);
		boolean success = false;
		try {
			copyFile(this, destBf, null, monitor);
			destBf.setFileId(fileId);
			destBf.close();
			success = true;
		}
		finally {
			if (!success) {
				destBf.delete();
			}
		}
	}

	@Override
	public String toString() {
		return file.toString();
	}

	/**
	 * <code>LocalBufferInputBlockStream</code> provides an input BlockStream for 
	 * transferring the entire file content associated with a read-only buffer
	 * file use a buffer-based transfer.
	 */
	class LocalBufferInputBlockStream implements InputBlockStream {

		private int nextBufferIndex = 0;
		private DataBuffer buf;

		/**
		 * Construct input block stream for this buffer file.
		 * @throws IOException
		 */
		LocalBufferInputBlockStream() throws IOException {
			if (!isReadOnly()) {
				throw new IOException("Read stream only permitted on read-only buffer file");
			}
			buf = new DataBuffer();
		}

		@Override
		public boolean includesHeaderBlock() {
			return false;
		}

		@Override
		public int getBlockCount() {
			// header block is excluded
			return getBufferCount();
		}

		@Override
		public int getBlockSize() {
			return blockSize;
		}

		@Override
		public void close() throws IOException {
			// raf remains open
		}

		@Override
		public BufferFileBlock readBlock() throws IOException {
			synchronized (LocalBufferFile.this) {

				// Must add 1 to buffer index values to produce block index value.

				if (nextBufferIndex == getBufferCount()) {
					return null;
				}

				get(buf, nextBufferIndex);

				int blockIndex = (nextBufferIndex++) + 1;

				byte[] block = new byte[getBlockSize()];
				if (buf.isEmpty()) {
					block[0] = EMPTY_BUFFER; // Empty flag only
				}
				BigEndianDataConverter.INSTANCE.putInt(block, 1, buf.getId());
				if (!buf.isEmpty()) {
					byte[] data = buf.getData();
					System.arraycopy(data, 0, block, BUFFER_PREFIX_SIZE, data.length);
				}

				return new BufferFileBlock(blockIndex, block);
			}
		}
	}

	/**
	 * <code>LocalFileInputBlockStream</code> provides an input BlockStream for 
	 * transferring the entire file content associated with a read-only file.
	 * This implementation reads the data directly from a single local file
	 * and must not be used when performing version reconstruction or 
	 * change-map driven streams.
	 */
	private class LocalFileInputBlockStream implements InputBlockStream {

		private InputStream fin;
		private int blockCount;
		private int nextIndex = 0;

		/**
		 * Construct input block stream for entire file
		 * @throws IOException
		 */
		LocalFileInputBlockStream() throws IOException {
			if (!readOnly) {
				throw new IOException("Read stream only permitted on read-only buffer file");
			}

			long fileLength = file.length();
			if (fileLength <= 0 || (fileLength % blockSize) != 0) {
				throw new IOException("Corrupt file");
			}
			blockCount = (int) (fileLength / blockSize);
			fin = new BufferedInputStream(new FileInputStream(file));
		}

		@Override
		public boolean includesHeaderBlock() {
			return true;
		}

		@Override
		public int getBlockCount() {
			return blockCount;
		}

		@Override
		public int getBlockSize() {
			return blockSize;
		}

		@Override
		public void close() throws IOException {
			fin.close();
		}

		@Override
		public BufferFileBlock readBlock() throws IOException {
			byte[] data = new byte[blockSize];
			int total = 0;
			while (total < blockSize) {
				int readlen = fin.read(data, total, blockSize - total);
				if (readlen < 0) {
					if (total == 0 && nextIndex == blockCount) {
						return null;
					}
					throw new EOFException("unexpected end of file");
				}
				total += readlen;
			}
			return new BufferFileBlock(nextIndex++, data);
		}
	}

	/**
	 * <code>LocalRandomInputBlockStream</code> provides ability to
	 * selectively read a select set of buffers from the LocalBufferFile
	 * based upon a specified ChangeMap.
	 */
	class LocalRandomInputBlockStream implements InputBlockStream {

		/**
		 * The <code>bufferIndexList</code> contains the DataBuffer indexes
		 * which are to be transferred.  Buffer index values plus 1 equal the 
		 * file block index.
		 */
		private List<Integer> bufferIndexList;

		/**
		 * If the bufferIndexList is not null, this index identifies the next
		 * entry within the list whose block should be transferred, otherwise
		 * the index directly identifies the next DataBuffer to be transferred.
		 */
		private int nextIndex;

		/**
		 * Construct input block stream for specific block indexes
		 * within the file based upon a changeMap.  The head buffer 
		 * will never be included in the transfer.
		 * @param changeMapData ChangeMap data which is used in determining which 
		 * buffers should be streamed
		 * @throws IOException
		 */
		LocalRandomInputBlockStream(byte[] changeMapData) throws IOException {
			if (!readOnly) {
				throw new IOException("Read stream only permitted on read-only buffer file");
			}
			buildBufferIndexList(changeMapData);
		}

		private void buildBufferIndexList(byte[] changeMapData) {

			ChangeMap changeMap = new ChangeMap(changeMapData);

			bufferIndexList = new ArrayList<>();

			IntSet emptySet = new IntSet(getFreeIndexes());

			for (int bufferIndex = 0; bufferIndex < bufferCount; bufferIndex++) {
				if (!emptySet.contains(bufferIndex) &&
					(changeMap.hasChanged(bufferIndex) || !changeMap.containsIndex(bufferIndex))) {
					// Add block index if block is not empty and block has either been
					// modified in versioned srcFile since checkout to initial destFile, or
					// block was added in most recent version of srcFile
					bufferIndexList.add(bufferIndex);
				}
			}
		}

		@Override
		public boolean includesHeaderBlock() {
			return false;
		}

		@Override
		public int getBlockCount() {
			return bufferIndexList != null ? bufferIndexList.size() : bufferCount;
		}

		@Override
		public int getBlockSize() {
			return blockSize;
		}

		@Override
		public void close() throws IOException {
			// raf remains open
		}

		@Override
		public BufferFileBlock readBlock() throws IOException {
			synchronized (LocalBufferFile.this) {
				if (raf == null) {
					throw new ClosedException();
				}

				if (nextIndex == bufferIndexList.size()) {
					return null; // no more buffers
				}

				int blockIndex = seekBufferBlock(bufferIndexList.get(nextIndex++));

				byte[] block = new byte[blockSize];
				raf.readFully(block);

				return new BufferFileBlock(blockIndex, block);
			}
		}
	}

	/**
	 * <code>LocalOutputBlockStream</code> provides an OutputBlockStream for 
	 * updating specific buffers of a non-read-only file.
	 */
	class LocalOutputBlockStream implements OutputBlockStream {

		private final long orignalFileId = fileId;
		private final int blockCount;

		private boolean isClosed = false;
		private boolean refreshOnClose;

		public LocalOutputBlockStream(int blockCount) throws IOException {
			if (readOnly) {
				throw new IOException("Write stream only permitted on updateable buffer file");
			}
			if (activeOutputBlockStream != null) {
				throw new IOException("Active block stream already exists");
			}
			this.blockCount = blockCount;
			activeOutputBlockStream = this;
		}

		@Override
		public void close() throws IOException {
			synchronized (LocalBufferFile.this) {

				if (isClosed) {
					return;
				}
				isClosed = true;

				if (raf == null) {
					throw new ClosedException();
				}

				try {
					if (refreshOnClose) {

						// read file header required
						readHeader();

						// restore fileId within file
						fileId = orignalFileId;
						seekBlock(0, FILE_ID_OFFSET);
						raf.writeLong(fileId);
					}
				}
				finally {
					activeOutputBlockStream = null;
				}

				// don't close file
			}
		}

		@Override
		public void writeBlock(BufferFileBlock block) throws IOException {
			if (blockSize != block.size()) {
				throw new IOException("incompatible block size");
			}
			synchronized (LocalBufferFile.this) {
				if (raf == null) {
					throw new ClosedException();
				}
				int blockIndex = block.getIndex();
				if (blockIndex == 0) {
					// must refresh buffer file if head block is written
					refreshOnClose = true;
				}
				seekBlock(blockIndex, 0);
				raf.write(block.getData());
				if (blockIndex > bufferCount) {
					// we must assume that any buffers starting with bufferCount upto blockIndex will
					// be accounted for in the ultimate free-list maintained outside the buffer file.
					// NOTE: bufferCount reflects DataBuffers which excludes the first block at blockIndex=0
					bufferCount = blockIndex; // 
				}
			}
		}

		@Override
		public int getBlockCount() {
			return blockCount;
		}

		@Override
		public int getBlockSize() {
			return blockSize;
		}

	}

	/**
	 * Obtain a direct stream to read all blocks of this buffer file 
	 * @return input block stream
	 * @throws IOException
	 */
	public InputBlockStream getInputBlockStream() throws IOException {
		if (!readOnly) {
			throw new IOException("Read stream only permitted on read-only buffer file");
		}
		return new LocalFileInputBlockStream();
	}

	/**
	 * Obtain a direct stream to write blocks to this buffer file
	 * @param blockCount number of blocks to be transferred
	 * @return output block stream
	 * @throws IOException
	 */
	public OutputBlockStream getOutputBlockStream(int blockCount) throws IOException {
		return new LocalOutputBlockStream(blockCount);
	}

	/**
	 * Factory method for generating the appropriate type of {@link InputBlockStream}
	 * for the specified read-only bufferFile.  Input stream may not supply header block in which case 
	 * free list and file parameters may need to be set separately.
	 * @param bufferFile buffer file opened read-only
	 * @return input block stream object
	 * @throws IOException
	 */
	private static InputBlockStream getInputBlockStream(BufferFile bufferFile) throws IOException {
		// This method is used so we can utilize a package method and avoid putting
		// it on the BufferFile interface
		if (bufferFile instanceof BufferFileAdapter) {
			return ((BufferFileAdapter) bufferFile).getInputBlockStream();
		}
		if (bufferFile instanceof LocalBufferFile) {
			return ((LocalBufferFile) bufferFile).getInputBlockStream();
		}
		throw new IllegalArgumentException(
			"Unsupported buffer file implementation: " + bufferFile.getClass().getName());
	}

	/**
	 * Factory method for generating the appropriate type of {@link InputBlockStream}
	 * for the specified read-only bufferFile with an optional changeMap used
	 * to select which buffer should be transferred.  Input stream may not supply header block 
	 * in which case free list and file parameters may need to be set separately.
	 * @param bufferFile buffer file opened read-only
	 * @return input block stream object
	 * @throws IOException
	 */
	private static InputBlockStream getInputBlockStream(BufferFile bufferFile, ChangeMap changeMap)
			throws IOException {
		if (changeMap == null) {
			return getInputBlockStream(bufferFile);
		}
		// This method is used so we can utilize a package method and avoid putting
		// it on the BufferFile interface
		if (bufferFile instanceof ManagedBufferFileAdapter) {
			return ((ManagedBufferFileAdapter) bufferFile).getInputBlockStream(changeMap.getData());
		}
		if (bufferFile instanceof LocalManagedBufferFile) {
			return ((LocalManagedBufferFile) bufferFile).getInputBlockStream(changeMap.getData());
		}
		throw new IllegalArgumentException(
			"Unsupported buffer file implementation: " + bufferFile.getClass().getName());
	}

	/**
	 * Factory method for generating the appropriate type of {@link OutputBlockStream}
	 * for the specified write-able bufferFile.  
	 * @param bufferFile write-able buffer file 
	 * @param blockCount number of blocks to be written.  This should be available from
	 * the corresponding {@link InputBlockStream}.
	 * @return output block stream object
	 * @throws IOException
	 */
	static OutputBlockStream getOutputBlockStream(BufferFile bufferFile, int blockCount)
			throws IOException {
		// This method is used so we can utilize a package method and avoid putting
		// it on the BufferFile interface
		if (bufferFile instanceof BufferFileAdapter) {
			return ((BufferFileAdapter) bufferFile).getOutputBlockStream(blockCount);
		}
		if (bufferFile instanceof LocalBufferFile) {
			return ((LocalBufferFile) bufferFile).getOutputBlockStream(blockCount);
		}
		throw new IllegalArgumentException(
			"Unsupported buffer file implementation: " + bufferFile.getClass().getName());
	}

	/**
	 * Copy the complete content of a specfied srcFile into a destFile
	 * excluding file ID.  Both files remain open.
	 * @param srcFile open buffer file
	 * @param destFile empty buffer file which is open for writing.
	 * @param changeMap optional change map which indicates those buffers which must be copied.
	 * Any buffer index outside the range of the change map will also be copied.
	 * @param monitor progress monitor
	 * @throws IOException if IO error occurs.
	 * @throws CancelledException if the monitor cancels the operation.
	 */
	public static void copyFile(BufferFile srcFile, BufferFile destFile, ChangeMap changeMap,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (destFile.isReadOnly()) {
			throw new IOException("File is read-only");
		}

		if (srcFile.getBufferSize() != destFile.getBufferSize()) {
			throw new IOException("Buffer sizes differ");
		}

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		int srcBlockCnt;
		boolean headerTransferRequired;

		try (InputBlockStream in = getInputBlockStream(srcFile, changeMap)) {
			headerTransferRequired = !in.includesHeaderBlock();
			srcBlockCnt = in.getBlockCount();
			monitor.initialize(srcBlockCnt + 2);
			try (OutputBlockStream out = getOutputBlockStream(destFile, in.getBlockCount())) {
				completeBlockStreamTransfer(in, out, monitor);
			}
		}
		finally {
			// circumvent other exceptions if cancelled
			monitor.checkCanceled();
		}

		if (headerTransferRequired) {
			destFile.clearParameters();
			String[] parmNames = srcFile.getParameterNames();
			for (String name : parmNames) {
				destFile.setParameter(name, srcFile.getParameter(name));
			}
			monitor.setProgress(srcBlockCnt + 1);

			// Copy free index list
			destFile.setFreeIndexes(srcFile.getFreeIndexes());
		}
		monitor.setProgress(srcBlockCnt + 2);
	}

	/**
	 * Perform a complete block stream transfer from in to out
	 * @param in input block stream
	 * @param out output block stream
	 * @param monitor progress and cancel monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	static void completeBlockStreamTransfer(InputBlockStream in, OutputBlockStream out,
			TaskMonitor monitor) throws CancelledException, IOException {
		int count = 0;
		try (BlockStreamCancelMonitor cancelMonitor =
			new BlockStreamCancelMonitor(monitor, in, out)) {
			int srcBlockCnt = in.getBlockCount();
			BufferFileBlock block;
			while ((block = in.readBlock()) != null) {
				monitor.checkCanceled();
				out.writeBlock(block);
				monitor.setProgress(count++);
			}
			if (count != srcBlockCnt) {
				throw new IOException("unexpected block transfer count");
			}
		}
	}

	/**
	 * <code>BlockStreamCancelMonitor</code> is used to close associated BlockStreams
	 * when a TaskMonitor is cancelled
	 */
	static class BlockStreamCancelMonitor implements Closeable, CancelledListener {

		private TaskMonitor monitor;
		private BlockStream[] blockStreams;

		BlockStreamCancelMonitor(TaskMonitor monitor, BlockStream... blockStreams) {
			this.monitor = monitor;
			this.blockStreams = blockStreams;
			monitor.addCancelledListener(this);
		}

		@Override
		public void close() throws IOException {
			monitor.removeCancelledListener(this);
		}

		@Override
		public void cancelled() {
			for (BlockStream blockStream : blockStreams) {
				try {
					blockStream.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

	}

	/**
	 * File filter to identify various files
	 */
	static class BufferFileFilter implements FileFilter {
		private final String ext;
		private final String prefix;

		BufferFileFilter(String prefix, String ext) {
			this.prefix = prefix;
			this.ext = ext;
		}

		@Override
		public boolean accept(File file) {
			if (file.isFile()) {
				String name = file.getName();
				if (prefix == null || name.indexOf(prefix) == 0) {
					if (ext == null || name.endsWith(ext)) {
						return true;
					}
				}
			}
			return false;
		}
	}

	/**
	 * Attempt to remove all pre-save files.
	 * Those still open by an existing process should 
	 * not be removed by the operating system.
	 * @param dir data directory containing presave files
	 * @param beforeNow if not 0, file mod time must be less than the specified time
	 */
	public static void cleanupOldPreSaveFiles(File dir, long beforeNow) {
		File[] oldFiles = dir.listFiles(new BufferFileFilter(null, PRESAVE_FILE_EXT));
		if (oldFiles == null) {
			return;
		}
		for (File oldFile : oldFiles) {
			if ((beforeNow == 0 || oldFile.lastModified() < beforeNow) &&
				oldFile.delete()) {
				Msg.info(LocalBufferFile.class, "Removed old presave file: " + oldFile);
			}
		}
	}

	/**
	 * Get the recommended buffer size given a target buffer size.
	 * @param requestedBufferSize target buffer size
	 * @return recommended buffer size
	 */
	static int getRecommendedBufferSize(int requestedBufferSize) {
		int size = (requestedBufferSize + BUFFER_PREFIX_SIZE) & -MINIMUM_BLOCK_SIZE;
		if (size <= 0) {
			size = MINIMUM_BLOCK_SIZE;
		}
		return size - BUFFER_PREFIX_SIZE;
	}

//	private void checkSameContent(BufferFile expectedBf, BufferFile inspectedBf) throws IOException {
//		
//		//assertEquals(inspectedBf.getIndexCount(), expectedBf.getIndexCount());
//		if(inspectedBf.getIndexCount() != expectedBf.getIndexCount()) {
//			System.err.println("Buffer count mismatch following update");
//		}
//		
//		int[] vFreeList = inspectedBf.getFreeIndexes();
//		int[] pFreeList = inspectedBf.getFreeIndexes();
//		Arrays.sort(vFreeList);
//		Arrays.sort(pFreeList);
//		if (!Arrays.equals(vFreeList, pFreeList)) {
//			System.err.println("Freelist mismatch following update");
//		}
//
//		if (!Arrays.equals(expectedBf.getParameterNames(), inspectedBf.getParameterNames())) {
//			System.err.println("Parameter list mismatch following update");
//		}
//		
//		for (String name : expectedBf.getParameterNames()) {
//			if (expectedBf.getParameter(name) != inspectedBf.getParameter(name)) {
//				System.err.println("Parameter " + name + " mismatch following update");
//			}
//		}
//		
//		DataBuffer pbuf = new DataBuffer();
//		DataBuffer vbuf = new DataBuffer();
//		int cnt = inspectedBf.getIndexCount();
//		for (int i = 0; i < cnt; i++) {
//			checkSameContent(i, expectedBf.get(vbuf, i), inspectedBf.get(pbuf, i));
//		}
//	}
//	
//	private void checkSameContent(int index, DataBuffer expectedBuf, DataBuffer inspectedBuf) {
//		if (expectedBuf.isEmpty() != inspectedBuf.isEmpty()) {
//			System.err.println("Buffer " + index + " empty flag mismatch following update");
//		}
//		if (expectedBuf.getId() != inspectedBuf.getId()) {
//			System.err.println("Buffer " + index + " has unexpected ID following update");
//		}
//		if (!expectedBuf.isEmpty()) {
//			if (!Arrays.equals(expectedBuf.data, inspectedBuf.data)) {
//				System.err.println("Buffer " + index + " content differ following update");
//			}
//		}
//	}

}
