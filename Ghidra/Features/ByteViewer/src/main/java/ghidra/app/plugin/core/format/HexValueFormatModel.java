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
package ghidra.app.plugin.core.format;

import java.math.BigInteger;

import ghidra.util.HelpLocation;

/**
 * Converts byte values to value represented as a 2, 4, 8, or 16-byte hex number.
 */
public abstract class HexValueFormatModel implements UniversalDataFormatModel {

	protected String name;

	private int symbolSize;
	protected int nbytes;

	public HexValueFormatModel(String name, int nbytes) {
		this.name = name;
		this.nbytes = nbytes;
		symbolSize = nbytes * 2;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getUnitByteSize() {
		return nbytes;
	}

	@Override
	public int getByteOffset(ByteBlock block, int position) {

		int o = position / 2;

		if (block.isBigEndian()) {
			return o;
		}
		return nbytes - 1 - o;
	}

	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		if (byteOffset > nbytes - 1) {
			throw new IllegalArgumentException("invalid byteOffset: " + byteOffset);
		}
		if (block.isBigEndian()) {
			return byteOffset * 2;
		}
		return (nbytes - 1 - byteOffset) * 2;
	}

	@Override
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	@Override
	public abstract String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException;

	@Override
	public boolean isEditable() {
		return true;
	}

	@Override
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (charPosition < 0 || charPosition > symbolSize - 1) {
			// Not sure how this is possible, but...
			return false;
		}
		char[] charArray = { c };
		byte cb = Byte.parseByte(new String(charArray), 16);
		// get the correct byte offset based on position
		int byteOffset = getByteOffset(block, charPosition);
		index = index.add(BigInteger.valueOf(byteOffset));
		byte b = block.getByte(index);
		b = adjustByte(b, cb, charPosition);
		block.setByte(index, b);
		return true;
	}

	@Override
	public int getGroupSize() {
		return 1;
	}

	/**
	 * Set the number of units in a group. This format does not
	 * support groups.
	 */
	@Override
	public void setGroupSize(int groupSize) {
		throw new UnsupportedOperationException("groups are not supported");
	}

	@Override
	public int getUnitDelimiterSize() {
		return 1;
	}

	@Override
	public boolean validateBytesPerLine(int bytesPerLine) {
		return bytesPerLine % nbytes == 0;
	}

	/**
	 * Returns value with leading zeros.
	 */
	protected String pad(String value) {
		StringBuffer sb = new StringBuffer();
		int len = symbolSize - value.length();

		for (int i = 0; i < len; i++) {
			sb.append("0");
		}
		sb.append(value);
		return sb.toString();
	}

	/**
	 * adjust byte b to use either the upper 4 bits or
	 * the lower 4 bits of newb according to charPosition.
	 */
	private byte adjustByte(byte b, byte newb, int charPosition) {
		if (charPosition % 2 == 0) {
			// its the high order byte
			b &= 0x0f;
			newb <<= 4;
		}
		else {
			b &= 0xf0;
		}
		b += newb;
		return b;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "HexValue");
	}

	@Override
	public void dispose() {
	}

}
