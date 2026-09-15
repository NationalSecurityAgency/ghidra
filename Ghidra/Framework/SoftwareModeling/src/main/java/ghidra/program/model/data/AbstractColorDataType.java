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
package ghidra.program.model.data;

import java.awt.Color;
import java.math.BigInteger;
import java.util.List;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.DataConverter;
import ghidra.util.Msg;

/**
 * {@link AbstractColorDataType} provides an abstract color datatype whose value corresponds to an 
 * approriate Color decode of the bytes at a memory location.  This datatype is a fixed-length
 * unsigned integer type which is rendered with a Color block when applied as {@link Data}.
 * <P>
 * The {@link #getValue(MemBuffer, Settings, int)} method returns {@link ColorIcon} instance.
 * <P>
 * A fixed-length RGB datatype will adopt a predefined default encoding, however a Typedef may 
 * be formed from the RGB datatype which will allow an alternative encoding to be specified 
 * via a default Setting (See {@link #getTypeDefSettingsDefinitions()}).
 */
public abstract class AbstractColorDataType extends AbstractUnsignedIntegerDataType {

	private static Settings rgbValueSettings = new SettingsImpl();
	static {
		PADDING.setPadded(rgbValueSettings, true);
	}

	/**
	 * Abstract color datatype whose value corresponds to an approriate Color decode
	 * of the bytes at a memory location.
	 * @param name datatype name
	 * @param dtm datatype manager
	 */
	public AbstractColorDataType(String name, DataTypeManager dtm) {
		super(name, dtm);
	}

	@Override
	public AbstractIntegerDataType getOppositeSignednessDataType() {
		Msg.error(this, "Unsupported method use for " + getClass().getName(),
			new UnsupportedOperationException());
		return this;
	}

	@Override
	public final Class<?> getValueClass(Settings settings) {
		return ColorIcon.class;
	}

	@Override
	public final String getRepresentation(MemBuffer buf, Settings settings, int length) {

		int size = getLength();
		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return "??";
		}

		// Full RGB value always displayed as Padded Hex but must respect Endianess setting
		BigInteger value = DataConverter.getInstance(ENDIAN.isBigEndian(settings, buf))
				.getBigInteger(bytes, size, true);
		String valueRep = getRepresentation(value, rgbValueSettings, 8 * size, false);

		// Representation:  <encoding>: <valueRep> {<componentValueList>}
		StringBuilder strbuf = new StringBuilder();
		strbuf.append(getEncodingName(settings));
		strbuf.append(" ");
		strbuf.append(valueRep);
		strbuf.append(" {");
		int cnt = 0;
		for (ComponentValue compValue : getComponentValues(buf, settings)) {
			if (cnt++ != 0) {
				strbuf.append(",");
			}
			strbuf.append(compValue.getRepresentation(settings));
		}
		strbuf.append("}");
		return strbuf.toString();
	}

	protected abstract String getEncodingName(Settings settings);

	protected abstract List<ComponentValue> getComponentValues(MemBuffer buf, Settings settings);

	@Override
	public ColorIcon getValue(MemBuffer buf, Settings settings, int length) {
		int size = getLength();
		if (size < 1 || size > 8) {
			throw new AssertionError("Unsupported length: " + size);
		}
		byte[] bytes = new byte[size];
		if (buf.getBytes(bytes, 0) != size) {
			return null; // insufficient bytes available
		}
		return new ColorIcon(decodeColor(buf, settings));
	}

	/**
	 * Generate the {@link Color} which corresponds to the memory bytes.
	 * Implementation must factor Endianess setting into value used.
	 * @param buf memory bytes buffer
	 * @param settings datatype settings
	 * @return Color to be rendered
	 */
	protected abstract Color decodeColor(MemBuffer buf, Settings settings);

	protected record ComponentValue(String name, int value, int bitLength) {
		String getRepresentation(Settings settings) {

			BigInteger bigValue = BigInteger.valueOf(Integer.toUnsignedLong(value));

			// CHAR format will default to HEX format
			return name + ":" +
				AbstractIntegerDataType.getRepresentation(bigValue, settings, bitLength, false);
		}
	}

	protected static int getFieldValue(long fullValue, int rightShift, int finalMask) {
		return (int) (fullValue >>> rightShift) & finalMask;
	}

	protected static int scaleFieldValue(int value, int bitSize) {
		return (value * 255) / ((1 << bitSize) - 1);
	}
}
