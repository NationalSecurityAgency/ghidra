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

import java.nio.charset.StandardCharsets;
import java.util.Objects;

import ghidra.framework.options.SaveState;
import ghidra.util.charset.CharsetInfo;
import ghidra.util.charset.CharsetInfoManager;

/**
 * Configuration values for byte viewer data models, as well as the bytes_per_line of the
 * byte viewer itself.
 */
public class ByteViewerConfigOptions {
	static final int DEFAULT_BYTES_PER_LINE = 16;

	private static final String HEX_VIEW_GROUPSIZE_OPTION_NAME = "Hex View Groupsize";
	private static final String CHARSET_OPTION_NAME = "Charset Name";
	private static final String COMPACTCHARS_OPTION_NAME = "Compact Chars";
	private static final String USE_CHAR_ALIGNMENT_OPTION_NAME = "Use Char Alignment";
	private static final String BYTES_PER_LINE_OPTION_NAME = "Bytes Per Line";
	private static final String OFFSET_NAME = "Offset";

	private int bytesPerLine = DEFAULT_BYTES_PER_LINE;
	private int offset;
	private boolean compactChars = true;
	private boolean useCharAlignment = true;
	private CharsetInfo csi = CharsetInfoManager.getInstance().get(StandardCharsets.US_ASCII);
	private int hexGroupSize = 1;

	public ByteViewerConfigOptions() {
		// nothing
	}

	@Override
	public ByteViewerConfigOptions clone() {
		ByteViewerConfigOptions clone = new ByteViewerConfigOptions();
		clone.bytesPerLine = bytesPerLine;
		clone.compactChars = compactChars;
		clone.useCharAlignment = useCharAlignment;
		clone.csi = csi;
		clone.hexGroupSize = hexGroupSize;
		clone.offset = offset;
		return clone;
	}

	public void read(SaveState saveState) {
		hexGroupSize = saveState.getInt(HEX_VIEW_GROUPSIZE_OPTION_NAME, 1);

		String charsetName = saveState.getString(CHARSET_OPTION_NAME, CharsetInfoManager.USASCII);
		csi = CharsetInfoManager.getInstance().get(charsetName, StandardCharsets.US_ASCII);

		compactChars = saveState.getBoolean(COMPACTCHARS_OPTION_NAME, true);
		useCharAlignment = saveState.getBoolean(USE_CHAR_ALIGNMENT_OPTION_NAME, true);

		bytesPerLine = saveState.getInt(BYTES_PER_LINE_OPTION_NAME, DEFAULT_BYTES_PER_LINE);
		offset = saveState.getInt(OFFSET_NAME, 0);
	}

	public void write(SaveState saveState) {
		saveState.putInt(HEX_VIEW_GROUPSIZE_OPTION_NAME, hexGroupSize);
		saveState.putString(CHARSET_OPTION_NAME, csi.getName());
		saveState.putBoolean(COMPACTCHARS_OPTION_NAME, compactChars);
		saveState.putBoolean(USE_CHAR_ALIGNMENT_OPTION_NAME, useCharAlignment);
		saveState.putInt(BYTES_PER_LINE_OPTION_NAME, bytesPerLine);
		saveState.putInt(OFFSET_NAME, offset);
	}

	public boolean areOptionsEqual(ByteViewerConfigOptions other) {
		return bytesPerLine == other.bytesPerLine && compactChars == other.compactChars &&
			Objects.equals(csi, other.csi) && hexGroupSize == other.hexGroupSize &&
			offset == other.offset && useCharAlignment == other.useCharAlignment;
	}

	public boolean areLayoutParamsChanged(ByteViewerConfigOptions other) {
		return offset != other.getOffset() || hexGroupSize != other.getHexGroupSize() ||
			bytesPerLine != other.getBytesPerLine() ||
			useCharAlignment != other.isUseCharAlignment();
	}

	public boolean areDislayWidthsChanged(ByteViewerConfigOptions other) {
		return getHexGroupSize() != other.getHexGroupSize() ||
			isCompactChars() != other.isCompactChars() ||
			(useCharAlignment && csi.getAlignment() != other.csi.getAlignment());
	}

	public int getBytesPerLine() {
		return bytesPerLine;
	}

	public void setBytesPerLine(int newBytesPerLine) {
		bytesPerLine = newBytesPerLine;
		offset = Math.clamp(offset, 0, bytesPerLine - 1);
		hexGroupSize = Math.clamp(hexGroupSize, 1, bytesPerLine);
	}

	public int getOffset() {
		return offset;
	}

	public int calcNormalizedOffset(int newOffset) {
		if (newOffset < 0) {
			newOffset = bytesPerLine - 1;
		}
		else if (newOffset >= bytesPerLine) {
			newOffset = newOffset % bytesPerLine;
		}
		return newOffset;
	}

	public void setOffset(int newOffset) {
		offset = calcNormalizedOffset(newOffset);
	}

	public int getHexGroupSize() {
		return hexGroupSize;
	}

	public void setHexGroupSize(int newHexGroupSize) {
		hexGroupSize = newHexGroupSize;
	}

	public CharsetInfo getCharsetInfo() {
		return csi;
	}

	public void setCharsetInfo(CharsetInfo newCSI) {
		this.csi = newCSI;
	}

	public void setCompactChars(boolean newCompactChars) {
		compactChars = newCompactChars;
	}

	public boolean isCompactChars() {
		return compactChars;
	}

	public boolean isUseCharAlignment() {
		return useCharAlignment;
	}

	public void setUseCharAlignment(boolean newUseCharAlignment) {
		useCharAlignment = newUseCharAlignment;
	}

}
