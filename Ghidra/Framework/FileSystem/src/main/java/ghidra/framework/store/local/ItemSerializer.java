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

import ghidra.util.BigEndianDataConverter;
import ghidra.util.MonitoredOutputStream;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * <code>ItemSerializer</code> facilitates the compressing and writing of a data stream
 * to a "packed" file.  The resulting "packed" file will contain the following meta-data
 * which is available after construction:
 * <ul>
 * <li>Item name</li>
 * <li>Content type (int)</li>
 * <li>File type (int)</li>
 * <li>Data length</li>
 * </ul>
 */
public class ItemSerializer {
	private static final int MAGIC_NUMBER_POS = 6;
	private static final int MAGIC_NUMBER_SIZE = 8;

	static final long MAGIC_NUMBER = 0x2e30212634e92c20L;
	static final int FORMAT_VERSION = 1;
	static final String ZIP_ENTRY_NAME = "FOLDER_ITEM";
	static final int IO_BUFFER_SIZE = 32 * 1024;

	private ItemSerializer() {
	}

	/**
	 * Read and compress data from the specified content stream and write to 
	 * a packed file along with additional meta-data.
	 * @param itemName item name
	 * @param contentType content type
	 * @param fileType file type
	 * @param length content length to be read
	 * @param content content input stream
	 * @param packedFile output packed file to be created
	 * @param monitor task monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	public static void outputItem(String itemName, String contentType, int fileType, long length,
			InputStream content, File packedFile, TaskMonitor monitor) throws CancelledException,
			IOException {

		OutputStream out = new BufferedOutputStream(new FileOutputStream(packedFile));
		boolean success = false;
		try {
			// Output header containing: original item name and content type
			ObjectOutputStream objOut = new ObjectOutputStream(out);
			objOut.writeLong(MAGIC_NUMBER);
			objOut.writeInt(FORMAT_VERSION);
			objOut.writeUTF(itemName);
			objOut.writeUTF(contentType != null ? contentType : "");
			objOut.writeInt(fileType);
			objOut.writeLong(length);
			objOut.flush();

			// Output item content
			ZipOutputStream zipOut = new ZipOutputStream(out);
			ZipEntry entry = new ZipEntry(ZIP_ENTRY_NAME);
			entry.setSize(length);
			entry.setMethod(ZipEntry.DEFLATED);
			zipOut.putNextEntry(entry);

			OutputStream itemOut = zipOut;
			if (monitor != null) {
				itemOut = new MonitoredOutputStream(zipOut, monitor);
				monitor.initialize((int) length);
			}

			long lengthWritten = 0;
			byte[] buffer = new byte[IO_BUFFER_SIZE];

			// Copy file contents
			int cnt = 0;
			while ((cnt = content.read(buffer)) > 0) {
				itemOut.write(buffer, 0, cnt);
				lengthWritten += cnt;
			}

			if (lengthWritten != length) {
				throw new IOException("Did not write all content - written length is " +
					lengthWritten + ", expected " + length + ".\n\tItem: " + itemName + " in " +
					"packed file: " + packedFile.getAbsolutePath());
			}
			itemOut.flush();

			zipOut.closeEntry();
			zipOut.flush();
			success = true;
		}
		catch (IOCancelledException e) {
			throw new CancelledException();
		}
		finally {
			try {
				out.close();
				if (!success) {
					packedFile.delete();
				}
			}
			catch (IOException e) {
				// we tried
			}
		}
	}

	/**
	 * A simple utility method to determine if the given file is a packed file as created by 
	 * this class. 
	 * @param file The file to check
	 * @return True if it is a packed file
	 * @throws IOException If there is a problem reading the given file
	 */
	public static boolean isPackedFile(File file) throws IOException {
		InputStream inputStream = null;
		try {
			inputStream = new BufferedInputStream(new FileInputStream(file));
			return isPackedFile(inputStream);
		}
		finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}
	}

	/**
	 * A convenience method for checking if the file denoted by the given inputStream is a 
	 * packed file.  
	 * <p>
	 * <b>Note: </b> This method will NOT close the given inputStream.
	 * @param inputStream a stream for accessing bytes of what may be a packed file
	 * @return true if the bytes from the inputStream represent the bytes of a packed file
	 * @throws IOException If there is a problem accessing the inputStream
	 * @see #isPackedFile(File)
	 */
	public static boolean isPackedFile(InputStream inputStream) throws IOException {
		inputStream.skip(MAGIC_NUMBER_POS);
		byte[] magicBytes = new byte[MAGIC_NUMBER_SIZE];
		inputStream.read(magicBytes);
		BigEndianDataConverter dc = BigEndianDataConverter.INSTANCE;
		long magic = dc.getLong(magicBytes);
		return (magic == MAGIC_NUMBER);
	}
}
