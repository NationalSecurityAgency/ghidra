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
package ghidra.app.plugin.core.byteviewer;

import ghidra.app.plugin.core.format.ByteBlock;
import ghidra.app.plugin.core.format.ByteBlockAccessException;
import ghidra.util.*;

import java.math.BigInteger;

/**
 * ByteBlock for a byte buffer read from a file.
 * 
 * 
 *
 */
class FileByteBlock implements ByteBlock {

	private byte[] buf;
	private boolean bigEndian;
	private DataConverter converter;

	FileByteBlock(byte[] b) {
		buf = b;
		converter = LittleEndianDataConverter.INSTANCE;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getLocationRepresentation(int)
	 */
	public String getLocationRepresentation(BigInteger bigIndex) {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			return pad(Integer.toString(index), 8);
		}
		return null;
	}

	public int getMaxLocationRepresentationSize() {
		return 8;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getIndexName()
	 */
	public String getIndexName() {
		return "Bytes";
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getLength()
	 */
	public BigInteger getLength() {
		return BigInteger.valueOf(buf.length);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getByte(int)
	 */
	public byte getByte(BigInteger bigIndex) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			return buf[index];
		}
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getInt(int)
	 */
	public int getInt(BigInteger bigIndex) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			byte[] b = new byte[4];
			System.arraycopy(buf, index, b, 0, b.length);
			return converter.getInt(b);
		}
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getLong(int)
	 */
	public long getLong(BigInteger bigIndex) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			byte[] b = new byte[8];
			System.arraycopy(buf, index, b, 0, b.length);
			return converter.getLong(b);
		}
		return 0;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#setByte(int, byte)
	 */
	public void setByte(BigInteger bigIndex, byte value) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			buf[index] = value;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#setInt(int, int)
	 */
	public void setInt(BigInteger bigIndex, int value) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			byte[] b = new byte[4];
			converter.putInt(b, 0, value);
			System.arraycopy(b, 0, buf, index, b.length);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#setLong(int, long)
	 */
	public void setLong(BigInteger bigIndex, long value) throws ByteBlockAccessException {
		int index = bigIndex.intValue();
		if (index < buf.length) {
			byte[] b = new byte[8];
			converter.putLong(b, 0, value);
			System.arraycopy(b, 0, buf, index, b.length);
		}

	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#isEditable()
	 */
	public boolean isEditable() {
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#setBigEndian(boolean)
	 */
	public void setBigEndian(boolean bigEndian) {
		if (this.bigEndian != bigEndian) {
			this.bigEndian = bigEndian;
			converter = DataConverter.getInstance(bigEndian);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#isBigEndian()
	 */
	public boolean isBigEndian() {
		return bigEndian;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlock#getAlignment(int)
	 */
	public int getAlignment(int radix) {
		return 0;
	}

	byte[] getBytes() {
		return buf;
	}

	private String pad(String str, int length) {
		StringBuffer sb = new StringBuffer();
		int nspaces = length - str.length();
		for (int i = 0; i < nspaces; i++) {
			sb.append(" ");
		}
		sb.append(str);
		return sb.toString();
	}
}
