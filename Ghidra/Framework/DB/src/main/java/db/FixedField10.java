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
import ghidra.util.BigEndianDataConverter;

/**
 * <code>FixedField10</code> provide an unsigned 10-byte fixed-length field value.
 * The most-significant byte corresponds to index-0 (i.e., data[0]).
 */
public class FixedField10 extends FixedField {

	/**
	 * Zero fixed10 field value
	 */
	public static final FixedField10 ZERO_VALUE = new FixedField10(0L, (short) 0, true);

	/**
	 * Minimum long field value
	 */
	public static FixedField10 MIN_VALUE = ZERO_VALUE;

	/**
	 * Maximum long field value
	 */
	public static FixedField10 MAX_VALUE = new FixedField10(-1L, (short) -1, true);

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
	 * @param data initial 10-byte binary value.  A null corresponds to zero value 
	 * and does not affect the null-state (see {@link #setNull()} and {@link #isNull()}).
	 * @throws IllegalArgumentException thrown if data is not 10-bytes in length
	 */
	public FixedField10(byte[] data) {
		this(data, false);
	}

	/**
	 * Construct a 10-byte fixed-length binary field with an initial value of data.
	 * @param data initial 10-byte binary value.  A null corresponds to zero value 
	 * and does not affect the null-state (see {@link #setNull()} and {@link #isNull()}).
	 * @param immutable true if field value is immutable
	 * @throws IllegalArgumentException thrown if data is not 10-bytes in length
	 */
	public FixedField10(byte[] data, boolean immutable) {
		super(data, immutable);
		if (data != null) {
			if (data.length != 10) {
				throw new IllegalArgumentException("Invalid FixedField10 data length");
			}
			updatePrimitiveValue(data);
		}
	}

	FixedField10(long hi8, short lo2, boolean immutable) {
		super(null, immutable);
		this.hi8 = hi8;
		this.lo2 = lo2;
	}

	@Override
	public int compareTo(Field o) {
		if (!(o instanceof FixedField10)) {
			throw new UnsupportedOperationException("may only compare similar Field types");
		}
		FixedField10 f = (FixedField10) o;
		int result = Long.compareUnsigned(hi8, f.hi8);
		if (result == 0) {
			result = Short.compareUnsigned(lo2, f.lo2);
		}
		return result;
	}

	@Override
	int compareTo(DataBuffer buffer, int offset) {
		long otherHi8 = buffer.getLong(offset);
		int result = Long.compareUnsigned(hi8, otherHi8);
		if (result == 0) {
			short otherLo2 = buffer.getShort(offset + 8);
			result = Short.compareUnsigned(lo2, otherLo2);
		}
		return result;
	}

	@Override
	public FixedField copyField() {
		if (isNull()) {
			FixedField10 copy = new FixedField10();
			copy.setNull();
			return copy;
		}
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
	public void setBinaryData(byte[] d) {
		if (d == null) {
			setNull();
			return;
		}
		if (d.length != 10) {
			throw new IllegalArgumentException("Invalid FixedField10 data length");
		}
		updatingValue();
		this.data = d;
		updatePrimitiveValue(d);
	}

	void updatePrimitiveValue(byte[] d) {
		hi8 = BigEndianDataConverter.INSTANCE.getLong(d, 0);
		lo2 = BigEndianDataConverter.INSTANCE.getShort(d, 8);
	}

	@Override
	void setNull() {
		super.setNull();
		data = null;
		hi8 = 0;
		lo2 = 0;
	}

	@Override
	byte getFieldType() {
		return FIXED_10_TYPE;
	}

	@Override
	int write(Buffer buf, int offset) throws IndexOutOfBoundsException, IOException {
		if (data != null) {
			return buf.put(offset, data);
		}
		offset = buf.putLong(offset, hi8);
		return buf.putShort(offset, lo2);
	}

	@Override
	int read(Buffer buf, int offset) throws IndexOutOfBoundsException, IOException {
		updatingValue();
		data = null; // be lazy
		hi8 = buf.getLong(offset);
		lo2 = buf.getShort(offset + 8);
		return offset + 10;
	}

	@Override
	int readLength(Buffer buf, int offset) {
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
		if (!(obj instanceof FixedField10)) {
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
