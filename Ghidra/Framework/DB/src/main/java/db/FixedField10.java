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
package db;

import java.io.IOException;

import db.buffers.DataBuffer;
import generic.util.UnsignedDataUtils;
import ghidra.util.BigEndianDataConverter;

/**
 * <code>FixedField10</code> provide an unsigned 10-byte fixed-length field value.
 * The most-significant byte corresponds to index-0 (i.e., data[0]).
 */
public class FixedField10 extends FixedField {

	/**
	 * Minimum long field value
	 */
	public static FixedField10 MIN_VALUE = new FixedField10(0L, (short) 0, true);

	/**
	 * Maximum long field value
	 */
	public static FixedField10 MAX_VALUE = new FixedField10(-1L, (short) -1, true);

	/**
	 * Zero fixed10 field value
	 */
	public static final FixedField10 ZERO_VALUE = new FixedField10(null, true);

	/**
	 * Instance intended for defining a {@link Table} {@link Schema}
	 */
	@SuppressWarnings("hiding")
	public static final FixedField10 INSTANCE = ZERO_VALUE;

	// This implementation uses both a data byte array and short+long variables
	// for data storage.  While the short+long is always available, the data 
	// byte array is only set when needed or supplied during construction.
	// The use of the short+long is done to speed-up comparison with other
	// FixedField10 instances or directly from a DataBuffer.
	private short lo2;
	private long hi8;

	/**
	 * Construct a 10-byte fixed-length field with an initial value of 0.
	 */
	public FixedField10() {
		super(null, false);
	}

	/**
	 * Construct a 10-byte fixed-length field with an initial value of data.
	 * @param data initial 10-byte binary value
	 * @throws IllegalArgumentException thrown if data is not 10-bytes in length
	 */
	public FixedField10(byte[] data) {
		this(data, false);
	}

	/**
	 * Construct a 10-byte fixed-length binary field with an initial value of data.
	 * @param data initial 10-byte binary value
	 * @param immutable true if field value is immutable
	 * @throws IllegalArgumentException thrown if data is not 10-bytes in length
	 */
	public FixedField10(byte[] data, boolean immutable) {
		super(null, immutable);
		setBinaryData(data);
	}

	FixedField10(long hi8, short lo2, boolean immutable) {
		super(null, immutable);
		this.hi8 = hi8;
		this.lo2 = lo2;
	}

	@Override
	boolean isNull() {
		return hi8 == 0 && lo2 == 0;
	}

	@Override
	public int compareTo(Field o) {
		if (!(o instanceof FixedField10)) {
			throw new UnsupportedOperationException("may only compare similar Field types");
		}
		FixedField10 f = (FixedField10) o;
		if (hi8 != f.hi8) {
			return UnsignedDataUtils.unsignedLessThan(hi8, f.hi8) ? -1 : 1;
		}
		if (lo2 != f.lo2) {
			return UnsignedDataUtils.unsignedLessThan(lo2, f.lo2) ? -1 : 1;
		}
		return 0;
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		long otherHi8 = buffer.getLong(offset);
		if (hi8 != otherHi8) {
			return UnsignedDataUtils.unsignedLessThan(hi8, otherHi8) ? -1 : 1;
		}
		short otherLo2 = buffer.getShort(offset + 8);
		if (lo2 != otherLo2) {
			return UnsignedDataUtils.unsignedLessThan(lo2, otherLo2) ? -1 : 1;
		}
		return 0;
	}

	@Override
	public FixedField copyField() {
		return new FixedField10(hi8, lo2, false);
	}

	@Override
	public FixedField newField() {
		return new FixedField10();
	}

	@Override
	FixedField getMinValue() {
		return MIN_VALUE;
	}

	@Override
	FixedField getMaxValue() {
		return MAX_VALUE;
	}

	@Override
	public byte[] getBinaryData() {
		if (data != null) {
			return data;
		}
		data = new byte[10];
		BigEndianDataConverter.INSTANCE.putLong(data, 0, hi8);
		BigEndianDataConverter.INSTANCE.putShort(data, 8, lo2);
		return data;
	}

	@Override
	public void setBinaryData(byte[] data) {
		this.data = data;
		if (data == null) {
			hi8 = 0;
			lo2 = 0;
			return;
		}
		if (data.length != 10) {
			throw new IllegalArgumentException("Invalid FixedField10 length: " + data.length);
		}
		hi8 = BigEndianDataConverter.INSTANCE.getLong(data, 0);
		lo2 = BigEndianDataConverter.INSTANCE.getShort(data, 8);
	}

	@Override
	byte getFieldType() {
		return FIXED_10_TYPE;
	}

	@Override
	int write(Buffer buf, int offset) throws IOException {
		if (data != null) {
			return buf.put(offset, data);
		}
		offset = buf.putLong(offset, hi8);
		return buf.putShort(offset, lo2);
	}

	@Override
	int read(Buffer buf, int offset) throws IOException {
		checkImmutable();
		data = null; // be lazy
		hi8 = buf.getLong(offset);
		lo2 = buf.getShort(offset + 8);
		return offset + 10;
	}

	@Override
	int readLength(Buffer buf, int offset) throws IOException {
		return 10;
	}

	@Override
	int length() {
		return 10;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = (int) (hi8 ^ (hi8 >>> 32));
		result = prime * result + lo2;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FixedField10 other = (FixedField10) obj;
		if (hi8 != other.hi8) {
			return false;
		}
		if (lo2 != other.lo2) {
			return false;
		}
		return true;
	}

	@Override
	public String getValueAsString() {
		return "{" + BinaryField.getValueAsString(getBinaryData()) + "}";
	}

}
