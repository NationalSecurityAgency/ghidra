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
		return true;
	}

	@Override
	public void dispose() {
	}

}
