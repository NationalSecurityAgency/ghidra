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
package agent.dbgeng.dbgeng;

import java.lang.annotation.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import agent.dbgeng.dbgeng.DebugValue.DebugValueType;
import agent.dbgeng.dbgeng.DebugValue.ForDebugValueType;
import ghidra.util.NumericUtilities;

/**
 * Data copied from a {@code DEBUG_VALUE} as defined in {dbgeng.h}.
 */
@ForDebugValueType(DebugValueType.INVALID)
public interface DebugValue {
	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.TYPE)
	public static @interface ForDebugValueType {
		DebugValueType value();
	}

	public static enum DebugValueType {
		INVALID(0), //
		INT8(Byte.SIZE), //
		INT16(Short.SIZE), //
		INT32(Integer.SIZE), //
		INT64(Long.SIZE), //
		FLOAT32(Float.SIZE), //
		FLOAT64(Double.SIZE), //
		FLOAT80(80), //
		FLOAT82(82), //
		FLOAT128(128), //
		VECTOR64(64), //
		VECTOR128(128), //
		;

		private static final Class<? extends DebugValue>[] CLASSES;

		static {
			@SuppressWarnings("unchecked")
			Class<? extends DebugValue>[] supressed = new Class[DebugValueType.values().length];
			CLASSES = supressed;
			for (Class<?> cls : DebugValue.class.getDeclaredClasses()) {
				if (!DebugValue.class.isAssignableFrom(cls)) {
					continue;
				}
				Class<? extends DebugValue> dvCls = cls.asSubclass(DebugValue.class);
				DebugValueType type = getDebugValueTypeForClass(dvCls);
				CLASSES[type.ordinal()] = dvCls;
			}
		}

		public static DebugValueType getDebugValueTypeForClass(Class<? extends DebugValue> cls) {
			ForDebugValueType annot = cls.getAnnotation(ForDebugValueType.class);
			if (annot == null) {
				throw new AssertionError(
					"INTERNAL: Missing ForDebugValueType annotation on " + cls);
			}
			return annot.value();
		}

		public final int bitLength;
		public final int byteLength;

		private DebugValueType(int bitLength) {
			this.bitLength = bitLength;
			this.byteLength = (bitLength + 7) / 8;
		}

		public Class<? extends DebugValue> getDebugValueClass() {
			return CLASSES[ordinal()];
		}

		public DebugValue decodeBytes(byte[] bytes) throws IllegalArgumentException {
			try {
				return CLASSES[ordinal()].getConstructor(byte[].class).newInstance(bytes);
			}
			catch (InstantiationException | IllegalAccessException | IllegalArgumentException
					| NoSuchMethodException | SecurityException e) {
				throw new AssertionError(e);
			}
			catch (InvocationTargetException e) {
				if (e.getCause() instanceof IllegalArgumentException) {
					throw (IllegalArgumentException) e.getCause();
				}
				throw new AssertionError(e);
			}
		}
	}

	@ForDebugValueType(DebugValueType.INT8)
	public static class DebugInt8Value implements DebugValue {
		private final byte value;

		public DebugInt8Value(byte value) {
			this.value = value;
		}

		public DebugInt8Value(byte[] bytes) {
			if (bytes.length != 1) {
				throw new IllegalArgumentException("Must have exactly 1 byte");
			}
			this.value = bytes[0];
		}

		public byte byteValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			return new byte[] { value };
		}

		@Override
		public String toString() {
			return "byte " + Integer.toHexString(value) + "h";
		}
	}

	@ForDebugValueType(DebugValueType.INT16)
	public static class DebugInt16Value implements DebugValue {
		private final short value;

		public DebugInt16Value(short value) {
			this.value = value;
		}

		public DebugInt16Value(byte[] bytes) {
			if (bytes.length != Short.BYTES) {
				throw new IllegalArgumentException("Must have exactly " + Short.BYTES + " bytes");
			}
			ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
			this.value = buf.getShort();
		}

		public short shortValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			ByteBuffer buf = ByteBuffer.allocate(Short.BYTES).order(ByteOrder.BIG_ENDIAN);
			buf.putShort(value);
			return buf.array();
		}

		@Override
		public String toString() {
			return "word " + Integer.toHexString(value) + "h";
		}
	}

	@ForDebugValueType(DebugValueType.INT32)
	public static class DebugInt32Value implements DebugValue {
		private final int value;

		public DebugInt32Value(int value) {
			this.value = value;
		}

		public DebugInt32Value(byte[] bytes) {
			if (bytes.length != Integer.BYTES) {
				throw new IllegalArgumentException("Must have exactly " + Integer.BYTES + " bytes");
			}
			ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
			this.value = buf.getInt();
		}

		public int intValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			ByteBuffer buf = ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN);
			buf.putInt(value);
			return buf.array();
		}

		@Override
		public String toString() {
			return "dword " + Integer.toHexString(value) + "h";
		}
	}

	@ForDebugValueType(DebugValueType.INT64)
	public static class DebugInt64Value implements DebugValue {
		private final long value;

		public DebugInt64Value(long value) {
			this.value = value;
		}

		public DebugInt64Value(byte[] bytes) {
			if (bytes.length != Long.BYTES) {
				throw new IllegalArgumentException("Must have exactly " + Long.BYTES + " bytes");
			}
			ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
			this.value = buf.getLong();
		}

		public long longValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			ByteBuffer buf = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN);
			buf.putLong(value);
			return buf.array();
		}

		@Override
		public String toString() {
			return "qword " + Long.toHexString(value) + "h";
		}
	}

	@ForDebugValueType(DebugValueType.FLOAT32)
	public static class DebugFloat32Value implements DebugValue {
		private final float value;

		public DebugFloat32Value(float value) {
			this.value = value;
		}

		public DebugFloat32Value(byte[] bytes) {
			if (bytes.length != Float.BYTES) {
				throw new IllegalArgumentException("Must have exactly " + Float.BYTES + " bytes");
			}
			ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
			this.value = buf.getFloat();
		}

		public float floatValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			ByteBuffer buf = ByteBuffer.allocate(Float.BYTES).order(ByteOrder.BIG_ENDIAN);
			buf.putFloat(value);
			return buf.array();
		}

		@Override
		public String toString() {
			return "f32 " + value;
		}
	}

	@ForDebugValueType(DebugValueType.FLOAT64)
	public static class DebugFloat64Value implements DebugValue {
		private final double value;

		public DebugFloat64Value(double value) {
			this.value = value;
		}

		public DebugFloat64Value(byte[] bytes) {
			if (bytes.length != Double.BYTES) {
				throw new IllegalArgumentException("Must have exactly " + Double.BYTES + " bytes");
			}
			ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
			this.value = buf.getDouble();
		}

		public double doubleValue() {
			return value;
		}

		@Override
		public byte[] encodeAsBytes() {
			ByteBuffer buf = ByteBuffer.allocate(Double.BYTES).order(ByteOrder.BIG_ENDIAN);
			buf.putDouble(value);
			return buf.array();
		}

		@Override
		public String toString() {
			return "f64 " + value;
		}
	}

	/**
	 * Extended-precision float
	 */
	@ForDebugValueType(DebugValueType.FLOAT80)
	public static class DebugFloat80Value implements DebugValue {
		private final byte[] bytes;

		public DebugFloat80Value(byte[] bytes) {
			if (bytes.length != 10) {
				throw new IllegalArgumentException("Must have exactly 10 bytes");
			}
			this.bytes = Arrays.copyOf(bytes, 10);
		}

		public byte[] bytes() {
			return bytes;
		}

		@Override
		public byte[] encodeAsBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			return "f80 " + NumericUtilities.convertBytesToString(bytes);
		}
	}

	/**
	 * Specific to IA-64 (Itanium) floating-point registers
	 * 
	 * 17-bit exponent, 64-bit fraction. Not sure how it's aligned in memory, though.
	 */
	@ForDebugValueType(DebugValueType.FLOAT82)
	public static class DebugFloat82Value implements DebugValue {
		private final byte[] bytes;

		public DebugFloat82Value(byte[] bytes) {
			if (bytes.length != 11) {
				throw new IllegalArgumentException("Must have exactly 11 bytes");
			}
			this.bytes = Arrays.copyOf(bytes, 11);
		}

		public byte[] bytes() {
			return bytes;
		}

		@Override
		public byte[] encodeAsBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			return "f82 " + NumericUtilities.convertBytesToString(bytes);
		}
	}

	/**
	 * Quadruple-precision float
	 */
	@ForDebugValueType(DebugValueType.FLOAT128)
	public static class DebugFloat128Value implements DebugValue {
		private final byte[] bytes;

		public DebugFloat128Value(byte[] bytes) {
			if (bytes.length != 16) {
				throw new IllegalArgumentException("Must have exactly 16 bytes");
			}
			this.bytes = Arrays.copyOf(bytes, 16);
		}

		public byte[] bytes() {
			return bytes;
		}

		@Override
		public byte[] encodeAsBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			return "f128 " + NumericUtilities.convertBytesToString(bytes);
		}
	}

	@ForDebugValueType(DebugValueType.VECTOR64)
	public static class DebugVector64Value implements DebugValue {
		private final byte[] bytes;

		public DebugVector64Value(byte[] bytes) {
			if (bytes.length != 8) {
				throw new IllegalArgumentException("Must have exactly 8 bytes");
			}
			this.bytes = Arrays.copyOf(bytes, 8);
		}

		public byte[] vi4() {
			return bytes;
		}

		@Override
		public byte[] encodeAsBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			return "vec64 " + NumericUtilities.convertBytesToString(bytes);
		}
	}

	@ForDebugValueType(DebugValueType.VECTOR128)
	public static class DebugVector128Value implements DebugValue {
		private final byte[] bytes;

		public DebugVector128Value(byte[] bytes) {
			if (bytes.length != 16) {
				throw new IllegalArgumentException(
					"Must have exactly 16 bytes. got " + bytes.length);
			}
			this.bytes = Arrays.copyOf(bytes, 16);
		}

		public byte[] vi8() {
			return bytes;
		}

		@Override
		public byte[] encodeAsBytes() {
			return bytes;
		}

		@Override
		public String toString() {
			return "vec128 " + NumericUtilities.convertBytesToString(bytes);
		}
	}

	default DebugValueType getValueType() {
		return DebugValueType.getDebugValueTypeForClass(getClass());
	}

	/**
	 * TODO: Document me
	 * 
	 * Encodes the value as an array of bytes in big-endian order
	 * 
	 * @return the encoded value
	 */
	public byte[] encodeAsBytes();
}
