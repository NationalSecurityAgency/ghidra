/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.ObjectStorage;

import java.util.ArrayList;

/**
 * <code>ObjectStorageAdapterDB</code> provides an ObjectStorage 
 * implementation for use by Saveable objects.  This allows Saveable objects 
 * to save or restore their state using a fixed set of primitives and primitive arrays. 
 * This implementation provides various data access methods for storing/retrieving data.
 * In addition, support is provided for utilizing a Record object for data storage
 * using a suitable schema.
 */
public class ObjectStorageAdapterDB implements ObjectStorage {
	
	private ArrayList<Field> fieldList = new ArrayList<Field>();
	private int col = 0;
	private boolean readOnly = false;
	
	/**
	 * Construct an empty writable storage adapter.
	 */
	public ObjectStorageAdapterDB() {
	}
	
	/**
	 * Construct a read-only storage adapter from an
	 * existing record.
	 * @param rec data record
	 */
	public ObjectStorageAdapterDB(Record rec) {
		readOnly = true;
		Field[] fields = rec.getFields();
		for (int i = 0; i < fields.length; i++) {
			fieldList.add(fields[i]);
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#putInt(int)
	 */
	public void putInt(int value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new IntField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putByte(byte)
	 */
	public void putByte(byte value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new ByteField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putShort(short)
	 */
	public void putShort(short value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new ShortField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putLong(long)
	 */
	public void putLong(long value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new LongField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putString(java.lang.String)
	 */
	public void putString(String value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new StringField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putBoolean(boolean)
	 */
	public void putBoolean(boolean value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BooleanField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putFloat(float)
	 */
	public void putFloat(float value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putDouble(double)
	 */
	public void putDouble(double value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#getInt()
	 */
	public int getInt() {
		try {
			return fieldList.get(col++).getIntValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getByte()
	 */
	public byte getByte() {
		try {
			return fieldList.get(col++).getByteValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getShort()
	 */
	public short getShort() {
		try {
			return fieldList.get(col++).getShortValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getLong()
	 */
	public long getLong() {
		try {
			return fieldList.get(col++).getLongValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getBoolean()
	 */
	public boolean getBoolean() {
		try {
			return fieldList.get(col++).getBooleanValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getString()
	 */
	public String getString() {
		try {
			return fieldList.get(col++).getString();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getFloat()
	 */
	public float getFloat() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getFloatValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getDouble()
	 */
	public double getDouble() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getDoubleValue();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#putInts(int[])
	 */
	public void putInts(int[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putBytes(byte[])
	 */
	public void putBytes(byte[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putShorts(short[])
	 */
	public void putShorts(short[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putLongs(long[])
	 */
	public void putLongs(long[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putFloats(float[])
	 */
	public void putFloats(float[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putDoubles(double[])
	 */
	public void putDoubles(double[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#putStrings(java.lang.String[])
	 */
	public void putStrings(String[] value) {
		if (readOnly)
			throw new IllegalStateException();
		fieldList.add(new BinaryCodedField(value));
	}

	/*
	 * @see ghidra.util.ObjectStorage#getInts()
	 */
	public int[] getInts() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getIntArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getBytes()
	 */
	public byte[] getBytes() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getByteArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getShorts()
	 */
	public short[] getShorts() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getShortArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getLongs()
	 */
	public long[] getLongs() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getLongArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getFloats()
	 */
	public float[] getFloats() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getFloatArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getDoubles()
	 */
	public double[] getDoubles() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getDoubleArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/*
	 * @see ghidra.util.ObjectStorage#getStrings()
	 */
	public String[] getStrings() {
		try {
			BinaryCodedField codedField = new BinaryCodedField((BinaryField)fieldList.get(col++));
			return codedField.getStringArray();
		}
		catch (IndexOutOfBoundsException e) {
			throw new IllegalFieldAccessException();
		}
	}

	/**
	 * Get the Schema associated with the stored data.
	 * @param version version to be assigned to schema instance
	 * @return Schema
	 */
	public Schema getSchema(int version) {
		Class<?>[] fieldClasses = new Class<?>[fieldList.size()];
		String[] fieldNames = new String[fieldClasses.length];
		for (int i = 0; i < fieldClasses.length; i++) {
			fieldClasses[i] = fieldList.get(i).getClass();
			fieldNames[i] = Integer.toString(i);
		}
		return new Schema(version, "key", fieldClasses, fieldNames);
	}

	/**
	 * Save data into a Record.
	 * @param rec database record.
	 */
	public void save(Record rec) {
		int cnt = fieldList.size();
		for (int i = 0; i < cnt; i++) {
			rec.setField(i, fieldList.get(i));
		}
	}

}
