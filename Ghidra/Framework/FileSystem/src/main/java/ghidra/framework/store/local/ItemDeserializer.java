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

import generic.jar.ResourceFile;
import ghidra.util.MonitoredInputStream;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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
public class ItemDeserializer {

	private static final long MAGIC_NUMBER = ItemSerializer.MAGIC_NUMBER;
	private static final int FORMAT_VERSION = ItemSerializer.FORMAT_VERSION;
	private static final String ZIP_ENTRY_NAME = ItemSerializer.ZIP_ENTRY_NAME;

	private final static int IO_BUFFER_SIZE = ItemSerializer.IO_BUFFER_SIZE;

	private InputStream in;
	private String itemName;
	private String contentType;
	private int fileType;
	private long length;

	private boolean saved = false;

	/**
	 * Constructor.
	 * @param packedFile item to deserialize.
	 * @throws IOException
	 */
	public ItemDeserializer(File packedFile) throws IOException {
		this(new ResourceFile(packedFile));
	}

	public ItemDeserializer(ResourceFile packedFile) throws IOException {

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
			if (contentType.length() == 0) {
				contentType = null;
			}
			fileType = objIn.readInt();
			length = objIn.readLong();
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
				}
			}
		}
	}

	@Override
	protected void finalize() throws Throwable {
		dispose();
		super.finalize();
	}

	/**
	 * Close packed-file input stream and free resources.
	 */
	public void dispose() {
		if (in != null) {
			try {
				in.close();
			}
			catch (IOException e) {
			}
			finally {
				in = null;
			}
		}
	}

	/**
	 * Returns packed item name
	 */
	public String getItemName() {
		return itemName;
	}

	/**
	 * Returns packed content type
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Returns packed file type.
	 */
	public int getFileType() {
		return fileType;
	}

	/**
	 * Returns unpacked data length
	 */
	public long getLength() {
		return length;
	}

	/**
	 * Save the item to the specified output stream.
	 * This method may only be invoked once.
	 * @param out
	 * @param monitor
	 * @throws IOException
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
//		if (length != entry.getSize()) {
//			throw new IOException("Content length is " + entry.getSize() + ", expected " + length);
//		}

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

	}

}
