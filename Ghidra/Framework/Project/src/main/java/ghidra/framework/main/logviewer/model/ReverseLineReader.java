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
package ghidra.framework.main.logviewer.model;

import java.io.*;

/**
 * 
 * Reads in a single line of text from a given input file, in reverse order. 
 * 
 * CONOPS:
 * 	1. Start at a given position in the file and read BUFFER_SIZE bytes into a byte array
 *  2. From the end of the array, read a character
 *  3. If the character represents a newline (or carriage return), the line is finished, so return.
 *  4. If not, continue reading.
 */
public class ReverseLineReader {

	private static final int BUFFER_SIZE = 8192;
	private final String encoding;
	private ByteArrayOutputStream baos = new ByteArrayOutputStream();
	public RandomAccessFile raf;

	/**
	 * 
	 * @param encoding
	 * @param raf
	 * @throws IOException
	 */
	public ReverseLineReader(String encoding, RandomAccessFile raf) throws IOException {
		this.raf = raf;
		this.encoding = encoding;
	}

	/**
	 * Moves the file pointer to the given byte location.
	 * 
	 * @param position
	 */
	public void setFilePos(long position) {

		try {
			raf.seek(position < 0 ? 0 : position);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

	
	/**
	 * Reads a single line from the current file pointer position, in reverse.  To do this we do
	 * the following:
	 * 
	 * 1. Read a 'large enough' number of bytes into a buffer (enough to guarantee a full line of
	 *    text.
	 * 2. Move backwards through the bytes just read until a newline or carriage return is found.
	 * 3. Throw away the rest of the bytes and return the line found.
	 * 
	 * @return
	 * @throws IOException
	 */
	public synchronized String readLine() throws IOException {

		// If we're at the beginning of the file, there's nothing to read.
		if (raf.getFilePointer() == 0) {
			return null;
		}

		// Set the start/end positions we'll be reading from. The start is the lower byte
		// position and the end is the higher (where we'll actually start reading from).
		long end = raf.getFilePointer();
		long start = end - BUFFER_SIZE;

		// Make sure we aren't trying to read past the beginning of the file. If so, just set
		// our start to 0 so we'll stop there.
		if (start < 0) {
			start = 0;
		}

		// Now create a byte array to hold the line we'll read.
		byte[] linePlus = new byte[(int) (end - start)];

		// Move the file pointer to our start location and read.
		raf.seek(start);
		raf.read(linePlus);

		// And finally move backwards from the end, writing characters to our outputs stream
		// as we go until we see a newline character.
		for (int i = linePlus.length - 1; i >= -1; i--) {

			if (i == -1) {
				raf.seek(0);
				String str = bufToString();
				return str;
			}

			byte c = linePlus[i];

			if (c == '\r' || c == '\n') {
				String str = bufToString();
				int newlineSubtrahend = 0;
				if (c == '\n' && i > 0 && linePlus[i - 1] == '\r') {
					// Need to subtract off another character for Windows newlines (\r\n)
					newlineSubtrahend = 1;
				}
				raf.seek(raf.getFilePointer() - (linePlus.length - i) - newlineSubtrahend);
				return str;
			}

			baos.write(c);
		}

		return null;
	}

	/*********************************************************************************
	 * PRIVATE METHODS
	 *********************************************************************************/

	/**
	 * Converts the contents of the output stream to a string.
	 * 
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	private synchronized String bufToString() throws UnsupportedEncodingException {

		if (baos.size() == 0) {
			return "";
		}

		byte[] bytes = baos.toByteArray();
		for (int i = 0; i < bytes.length / 2; i++) {
			byte t = bytes[i];
			bytes[i] = bytes[bytes.length - i - 1];
			bytes[bytes.length - i - 1] = t;
		}

		// Make sure to call reset so we effectively clear the outputs stream.
		baos.reset();

		// And return the new string.
		return new String(bytes, encoding);
	}
}
