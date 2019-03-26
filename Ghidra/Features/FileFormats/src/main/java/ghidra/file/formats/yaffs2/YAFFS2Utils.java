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
package ghidra.file.formats.yaffs2;

import java.text.DateFormat;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class YAFFS2Utils {

	/**
		parse file names
	 */
	public static String parseName(byte[] buffer, final int offset, final int length) {
		StringBuffer result = new StringBuffer(length);
		int end = offset + length;

		for (int i = offset; i < end; ++i) {
			byte b = buffer[i];
			if (b == 0) { // Trailing null
				break;
			}
			result.append((char) (b & 0xFF)); // Allow for sign-extension
		}

		return result.toString();
	}

	/**
		read values are unsigned int, return as a long (because of Java)
	 */
	public static long parseInteger(final byte[] buffer, final int offset, final int length) {
		long result = 0;
		int end = offset + length;
		int start = offset;
		int j = 0;

		for (int i = start; i < end; i++) {
			result += ((long) buffer[i] & 0xFF) << (8 * j);
			j++;
		}
		return result;
	}

	/**
		compute the file size, set file size to 0 if object type is dir
	 */
	public static long parseFileSize(final byte[] buffer, final int offset, final int length) {
		long result = 0;
		int end = offset + length;
		int start = offset;
		int j = 0;
		int k = 0;

		for (int i = start; i < end; i++) {
			// check for 0xffffffff buffer value, a special case
			if (buffer[i] == -1)
				k++;

			// compute integer result
			result += ((long) buffer[i] & 0xFF) << (8 * j);
			j++;
		}

		// if special case was found (ex, for a dir header), return 0 as size
		if (k < 4) {
			return result;
		}
		return 0;
	}

	/**
		return the date/time string for the parsed file
	 */
	public static String parseDateTime(final byte[] buffer, final int offset, final int length) {
		long result = 0;
		int end = offset + length;
		int start = offset;
		int j = 0;

		for (int i = start; i < end; i++) {
			result += ((long) buffer[i] & 0xFF) << (8 * j);
			j++;
		}

		// note that input here needs to be ms, result above is in sec
		return DateFormat.getDateTimeInstance().format(result * 1000);
	}

	/**
		no Magic Bytes, so check for an empty directory in the first header
	 */
	public final static boolean isYAFFS2Image(Program program) {
		byte[] bytes = new byte[YAFFS2Constants.MAGIC_SIZE];
		try {
			Address address = program.getMinAddress();
			program.getMemory().getBytes(address, bytes);
		}
		catch (Exception e) {
		}
		// check for initial byte equal to 0x03, 'directory'
		// and check that the first byte of the file name is null
		// ... this is the yaffs2 root level dir header
		return ((bytes[0] == 0x03) && (bytes[10] == 0x00));

	}

}
