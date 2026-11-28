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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.util.HelpLocation;

public class DoubleFormatModel implements UniversalDataFormatModel {

	private final int symbolSize;
	
	public DoubleFormatModel() {
		symbolSize = 24;
	}
	@Override
	public int getUnitByteSize() {
		return 8;
	}

	@Override
	public String getName() {
		return "Double";
	}

	@Override
	public HelpLocation getHelpLocation() {
		//TODO  Would need a Double section
		return new HelpLocation("ByteViewerPlugin", "formats");
	}

	@Override
	public int getDataUnitSymbolSize() {
		return symbolSize;
	}

	/**
	 * Get the byte used to generate the character at a given position
	 * TODO  is this possible/reasonable in double?
	 */
	@Override
	public int getByteOffset(ByteBlock block, int position) {
		return 0;
	}

	/**
	 * Get the column position from the byte offset of a unit
	 * TODO  is this possible/reasonable in double?
	 */
	@Override
	public int getColumnPosition(ByteBlock block, int byteOffset) {
		return 0;
	}

	/**
	 * Convert a 8 byte long to a double and return its string
	 */
	@Override
	public String getDataRepresentation(ByteBlock block, BigInteger index) throws ByteBlockAccessException {
		ByteBuffer b = ByteBuffer.allocate(8);
		b.putLong(block.getLong(index));
		b.rewind();
		b.order(block.isBigEndian() ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);
		double d = b.getDouble();
		return Double.toString(d);
	}

	@Override
	public boolean isEditable() {
		return false;
	}

	@Override
	public boolean replaceValue(ByteBlock block, BigInteger index, int pos, char c) throws ByteBlockAccessException {
		return false;
	}

	@Override
	public int getGroupSize() {
		return 1;
	}

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
		return bytesPerLine % getUnitByteSize() == 0;
	}

	@Override
	public void dispose() {
	}

}
