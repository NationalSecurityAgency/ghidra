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

import ghidra.app.plugin.core.byteviewer.ByteViewerConfigOptions;
import ghidra.util.HelpLocation;

/**
 * Converts byte values to hex representation, optionally grouping the byte values
 * together in groups of {@link #getHexGroupSize()}.
 */
public class HexFormatModel implements UniversalDataFormatModel, MutableDataFormatModel {

	public final static String NAME = "Hex";

	private int symbolSize = 2;
	private int groupSize = 1;
	private String fullSymbolErrorStr = "??";

	private static final String GOOD_CHARS = "0123456789abcdefABCDEF";

	public HexFormatModel() {
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public int getUnitByteSize() {
		return groupSize;
	}

	@Override
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	@Override
	public void setByteViewerConfigOptions(ByteViewerConfigOptions options) {
		groupSize = options.getHexGroupSize();
		symbolSize = 2 * groupSize;
		fullSymbolErrorStr = "??".repeat(groupSize);
	}

	@Override
	public String validateByteViewerConfigOptions(ByteViewerConfigOptions candidateOptions) {
		// we can't rely on the caller to pre-check our validity based on
		// groupsize % bytes_per_line because our groupsize will change after the configoptions
		// are set.
		if (candidateOptions.getBytesPerLine() % candidateOptions.getHexGroupSize() != 0) {
			return "Hex (%d bytes) is not a multiple of %d".formatted(
				candidateOptions.getHexGroupSize(), candidateOptions.getBytesPerLine());
		}
		return null;
	}

	public int getHexGroupSize() {
		return groupSize;
	}

	@Override
	public int getByteOffset(ByteBlock block, int pos) {
		return pos < symbolSize ? pos / 2 : groupSize - 1;
	}

	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return byteOffset * 2;
	}

	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index)
			throws ByteBlockAccessException {

		byte[] bytes = new byte[groupSize];
		int bytesRead = block.getBytes(bytes, index, groupSize);
		if (bytesRead == 0) {
			return fullSymbolErrorStr;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytesRead; i++) {
			sb.append("%02x".formatted(Byte.toUnsignedInt(bytes[i])));
		}
		return sb.toString();
	}

	@Override
	public int getUnitDelimiterSize() {
		return 1;
	}

	@Override
	public boolean replaceValue(ByteBlock block, BigInteger index, int charPosition, char c)
			throws ByteBlockAccessException {

		if (GOOD_CHARS.indexOf(c) == -1) {
			return false;
		}
		if (charPosition < 0 || charPosition >= symbolSize) {
			return false;
		}

		int byteNo = getByteOffset(block, charPosition);
		index = index.add(BigInteger.valueOf(byteNo));

		byte b = block.getByte(index);
		char[] charArray = { c };
		byte cb = Byte.parseByte(new String(charArray), 16);

		if (charPosition % 2 == 0) {
			// its the high order byte
			b &= 0x0f;
			cb <<= 4;
			b += cb;
		}
		else {
			b &= 0xf0;
			b += cb;
		}
		block.setByte(index, b);
		return true;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("ByteViewerPlugin", "Hex");
	}

}
