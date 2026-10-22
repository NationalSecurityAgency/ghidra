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
package ghidra.framework.store.local;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.commons.lang3.StringUtils;

import generic.jar.ResourceFile;
import ghidra.util.MonitoredInputStream;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ItemDeserializer</code> facilitates the reading of a compressed data stream
 * contained within a "packed" file.  A "packed" file contains the following meta-data
 * which is available after construction:
 * <ul>
 * <li>Item name</li>
 * <li>Content type (int)</li>
 * <li>File type (int)</li>
 * <li>Data length</li>
 * </ul>
 */
public class ItemDeserializer implements Closeable {

	private static final long MAGIC_NUMBER = ItemSerializer.MAGIC_NUMBER;
	private static final int FORMAT_VERSION = ItemSerializer.FORMAT_VERSION;
	private static final String ZIP_ENTRY_NAME = ItemSerializer.ZIP_ENTRY_NAME;

	private final static int IO_BUFFER_SIZE = ItemSerializer.IO_BUFFER_SIZE;

	// Maximum compression ratio allowed
	private final static int MAX_EXPECTED_COMPRESSION_RATIO = 20;

	private InputStream in;
	private String itemName;
	private String contentType;
	private int fileType;
	private long length;

	private boolean saved = false;

	/**
	 * Constructor.
	 * @param packedFile item to deserialize.
	 * @throws IOException if an IO error occurs opening packed file
	 */
	public ItemDeserializer(File packedFile) throws IOException {
		this(new ResourceFile(packedFile));
	}

	public ItemDeserializer(ResourceFile packedFile) throws IOException {

		long fileLen = packedFile.length();

		in = new BufferedInputStream(packedFile.getInputStream());

		// Read header containing: original item name and content type
		boolean success = false;
		try {
			ObjectInputStream objIn = new ObjectInputStream(in);
			if (objIn.readLong() != MAGIC_NUMBER) {
				throw new IOException("Invalid data");
			}
			if (objIn.readInt() != FORMAT_VERSION) {
				throw new IOException("Unsupported data format");
			}

			itemName = objIn.readUTF();
			contentType = objIn.readUTF();
			if (StringUtils.isBlank(contentType)) {
				contentType = null;
			}
			fileType = objIn.readInt();
			length = objIn.readLong();

			if (StringUtils.isBlank(itemName) || length <= 0) {
				throw new IOException("Invalid packed data file");
			}

			long compressionRatio = length / fileLen;
			if (compressionRatio > MAX_EXPECTED_COMPRESSION_RATIO) {
				throw new IOException(
					"Suspicious packed data file compression ratio: " + compressionRatio);
			}

			success = true;
		}
		catch (UTFDataFormatException e) {
			throw new IOException("Invalid item data");
		}
		finally {
			if (!success) {
				try {
					in.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	/**
	 * Close packed-file input stream and free resources.
	 * @deprecated {@link #close()} should be used.
	 */
	@Deprecated
	public void dispose() {
		try {
			close();
		}
		catch (IOException e) {
			// ignore
		}
	}

	@Override
	public void close() throws IOException {
		if (in != null) {
			in.close();
			in = null;
		}
	}

	/**
	 * {@return packed item name}
	 */
	public String getItemName() {
		return itemName;
	}

	/**
	 * {@return packed content type}
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * {@return packed file type}
	 */
	public int getFileType() {
		return fileType;
	}

	/**
	 * {@return unpacked data length}
	 */
	public long getLength() {
		return length;
	}

	/**
	 * Save the item to the specified output stream.
	 * This method may only be invoked once.
	 * The caller may want to check target file-system for sufficient storage 
	 * based upon uncompressed {@link #length}.
	 * 
	 * @param out destination output stream
	 * @param monitor task monitor
	 * @throws IOCancelledException if stream cancelled by monitor
	 * @throws IOException if an IO error occurs
	 */
	public void saveItem(OutputStream out, TaskMonitor monitor) throws IOCancelledException,
			IOException {

		if (saved) {
			throw new IllegalStateException("Already saved");
		}
		saved = true;

		ZipInputStream zipIn = new ZipInputStream(in);
		ZipEntry entry = zipIn.getNextEntry();
		if (entry == null || !ZIP_ENTRY_NAME.equals(entry.getName())) {
			throw new IOException("Data error");
		}

		InputStream itemIn = zipIn;
		if (monitor != null) {
			itemIn = new MonitoredInputStream(zipIn, monitor);
			monitor.initialize((int) length);
		}
		long len = length;
		byte[] buffer = new byte[IO_BUFFER_SIZE];

		// Copy file contents
		int cnt = (int) (len < IO_BUFFER_SIZE ? len : IO_BUFFER_SIZE);
		while ((cnt = itemIn.read(buffer, 0, cnt)) > 0) {
			out.write(buffer, 0, cnt);
			len -= cnt;
			cnt = (int) (len < IO_BUFFER_SIZE ? len : IO_BUFFER_SIZE);
		}

		if (itemIn.read() > 0) {
			throw new IOException("Data error: expected end of data");
		}
	}

}
