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
package ghidra.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Deque;
import java.util.LinkedList;

import org.junit.Test;

public class AnnotatedSaveableTest {
	public static class AllFieldTypesSaveable extends AnnotatedSaveable {
		@SaveableField
		private boolean primitiveBoolean;

		@SaveableField
		private Boolean objectBoolean;

		@SaveableField
		private byte primitiveByte;

		@SaveableField
		private Byte objectByte;

		@SaveableField
		private byte[] arrOfByte;

		@SaveableField
		private double primitiveDouble;

		@SaveableField
		private Double objectDouble;

		@SaveableField
		private double[] arrOfDouble;

		@SaveableField
		private float primitiveFloat;

		@SaveableField
		private Float objectFloat;

		@SaveableField
		private float[] arrOfFloat;

		@SaveableField
		private int primitiveInt;

		@SaveableField
		private Integer objectInt;

		@SaveableField
		private int[] arrOfInt;

		@SaveableField
		private long primitiveLong;

		@SaveableField
		private Long objectLong;

		@SaveableField
		private long[] arrOfLong;

		@SaveableField
		private short primitiveShort;

		@SaveableField
		private Short objectShort;

		@SaveableField
		private short[] arrOfShort;

		@SaveableField
		private String objectString;

		@SaveableField
		private String[] arrOfString;

		@Override
		public int getSchemaVersion() {
			return 0;
		}
	}

	class FakeObjectStorage implements ObjectStorage {
		final Deque<Object> objects = new LinkedList<>();

		@Override
		public void putInt(int value) {
			objects.offer(value);
		}

		@Override
		public void putByte(byte value) {
			objects.offer(value);
		}

		@Override
		public void putShort(short value) {
			objects.offer(value);
		}

		@Override
		public void putLong(long value) {
			objects.offer(value);
		}

		@Override
		public void putString(String value) {
			objects.offer(value);
		}

		@Override
		public void putBoolean(boolean value) {
			objects.offer(value);
		}

		@Override
		public void putFloat(float value) {
			objects.offer(value);
		}

		@Override
		public void putDouble(double value) {
			objects.offer(value);
		}

		@Override
		public int getInt() {
			return (Integer) objects.poll();
		}

		@Override
		public byte getByte() {
			return (Byte) objects.poll();
		}

		@Override
		public short getShort() {
			return (Short) objects.poll();
		}

		@Override
		public long getLong() {
			return (Long) objects.poll();
		}

		@Override
		public boolean getBoolean() {
			return (Boolean) objects.poll();
		}

		@Override
		public String getString() {
			return (String) objects.poll();
		}

		@Override
		public float getFloat() {
			return (Float) objects.poll();
		}

		@Override
		public double getDouble() {
			return (Double) objects.poll();
		}

		@Override
		public void putInts(int[] value) {
			objects.offer(value);
		}

		@Override
		public void putBytes(byte[] value) {
			objects.offer(value);
		}

		@Override
		public void putShorts(short[] value) {
			objects.offer(value);
		}

		@Override
		public void putLongs(long[] value) {
			objects.offer(value);
		}

		@Override
		public void putFloats(float[] value) {
			objects.offer(value);
		}

		@Override
		public void putDoubles(double[] value) {
			objects.offer(value);
		}

		@Override
		public void putStrings(String[] value) {
			objects.offer(value);
		}

		@Override
		public int[] getInts() {
			return (int[]) objects.poll();
		}

		@Override
		public byte[] getBytes() {
			return (byte[]) objects.poll();
		}

		@Override
		public short[] getShorts() {
			return (short[]) objects.poll();
		}

		@Override
		public long[] getLongs() {
			return (long[]) objects.poll();
		}

		@Override
		public float[] getFloats() {
			return (float[]) objects.poll();
		}

		@Override
		public double[] getDoubles() {
			return (double[]) objects.poll();
		}

		@Override
		public String[] getStrings() {
			return (String[]) objects.poll();
		}
	}

	@Test
	public void testAllFieldTypes() {
		AllFieldTypesSaveable saveable = new AllFieldTypesSaveable();
		saveable.primitiveBoolean = true;
		saveable.primitiveByte = 1;
		saveable.primitiveDouble = 2.0;
		saveable.primitiveFloat = 3.0f;
		saveable.primitiveInt = 4;
		saveable.primitiveLong = 5;
		saveable.primitiveShort = 6;
		saveable.objectBoolean = false;
		saveable.objectByte = 7;
		saveable.objectDouble = 8.0;
		saveable.objectFloat = 9.0f;
		saveable.objectInt = 10;
		saveable.objectLong = 11L;
		saveable.objectShort = 12;
		saveable.objectString = "13";
		saveable.arrOfByte = new byte[] {};
		saveable.arrOfDouble = new double[] { 14.0, 15.0 };
		saveable.arrOfFloat = new float[] { 16.0f };
		saveable.arrOfInt = new int[] { 17, 18, 19 };
		saveable.arrOfLong = new long[] { 20L, 21L };
		saveable.arrOfShort = new short[] { 22 };
		saveable.arrOfString = new String[] { "23", "24" };

		FakeObjectStorage storage = new FakeObjectStorage();
		saveable.save(storage);

		AllFieldTypesSaveable restored = new AllFieldTypesSaveable();
		restored.restore(storage);

		assertEquals(restored.primitiveBoolean, true);
		assertEquals(restored.primitiveByte, (byte) 1);
		assertEquals(restored.primitiveDouble, 2.0, 0);
		assertEquals(restored.primitiveFloat, 3.0f, 0);
		assertEquals(restored.primitiveInt, 4);
		assertEquals(restored.primitiveLong, 5L);
		assertEquals(restored.primitiveShort, (short) 6);

		assertEquals(restored.objectBoolean, Boolean.FALSE);
		assertEquals(restored.objectByte, Byte.valueOf((byte) 7));
		assertEquals(restored.objectDouble, Double.valueOf(8.0));
		assertEquals(restored.objectFloat, Float.valueOf(9.0f));
		assertEquals(restored.objectInt, Integer.valueOf(10));
		assertEquals(restored.objectLong, Long.valueOf(11));
		assertEquals(restored.objectShort, Short.valueOf((short) 12));
		assertEquals(restored.objectString, "13");

		assertArrayEquals(restored.arrOfByte, new byte[] {});
		assertArrayEquals(restored.arrOfDouble, new double[] { 14.0, 15.0 }, 0);
		assertArrayEquals(restored.arrOfFloat, new float[] { 16.0f }, 0);
		assertArrayEquals(restored.arrOfInt, new int[] { 17, 18, 19 });
		assertArrayEquals(restored.arrOfLong, new long[] { 20L, 21L });
		assertArrayEquals(restored.arrOfShort, new short[] { 22 });
		assertArrayEquals(restored.arrOfString, new String[] { "23", "24" });
	}

	@Test
	public void testFieldsAlphabetized() {
		AllFieldTypesSaveable saveable = new AllFieldTypesSaveable();
		assertArrayEquals(saveable.getObjectStorageFields(),
			new Class<?>[] { byte[].class, double[].class, float[].class, int[].class, long[].class,
				short[].class, String[].class, Boolean.class, Byte.class, Double.class, Float.class,
				Integer.class, Long.class, Short.class, String.class, boolean.class, byte.class,
				double.class, float.class, int.class, long.class, short.class, });
	}
}
