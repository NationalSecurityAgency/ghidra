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
package ghidra.util.map;

import ghidra.util.ObjectStorage;
import ghidra.util.datastruct.DataTable;

/**
 * Convenience adapter implementation for saving and restoring Strings and 
 * Java primitives or arrays of Strings and primitives for a row of a data table.
 * The order in which the puts are done must the same order in which the gets are done.
 */
public class ObjectStorageAdapter implements ObjectStorage {
	private DataTable table;
	private int row;
	private int col;
	/**
	 * Constructor for ObjectStorageAdapter.
	 */
	public ObjectStorageAdapter(DataTable table, int row) {
		this.table = table;
		this.row = row;	
		this.col = 0;
	}

	/**
	 * @see ObjectStorage#putInt(int)
	 */
	@Override
	public void putInt(int value) {
		table.putInt(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putByte(byte)
	 */
	@Override
	public void putByte(byte value) {
		table.putByte(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putShort(short)
	 */
	@Override
	public void putShort(short value) {
		table.putShort(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putLong(long)
	 */
	@Override
	public void putLong(long value) {
		table.putLong(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putString(String)
	 */
	@Override
	public void putString(String value) {
		table.putString(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putBoolean(boolean)
	 */
	@Override
	public void putBoolean(boolean value) {
		table.putBoolean(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putFloat(float)
	 */
	@Override
	public void putFloat(float value) {
		table.putFloat(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putDouble(double)
	 */
	@Override
	public void putDouble(double value) {
		table.putDouble(row, col++, value);
	}

	/**
	 * @see ObjectStorage#getInt()
	 */
	@Override
	public int getInt() {
		return table.getInt(row, col++);
	}

	/**
	 * @see ObjectStorage#getByte()
	 */
	@Override
	public byte getByte() {
		return table.getByte(row, col++);
	}

	/**
	 * @see ObjectStorage#getShort()
	 */
	@Override
	public short getShort() {
		return table.getShort(row, col++);
	}

	/**
	 * @see ObjectStorage#getLong()
	 */
	@Override
	public long getLong() {
		return table.getLong(row, col++);
	}

	/**
	 * @see ObjectStorage#getBoolean()
	 */
	@Override
	public boolean getBoolean() {
		return table.getBoolean(row, col++);
	}

	/**
	 * @see ObjectStorage#getString()
	 */
	@Override
	public String getString() {
		return table.getString(row, col++);
	}

	/**
	 * @see ObjectStorage#getFloat()
	 */
	@Override
	public float getFloat() {
		return table.getFloat(row, col++);
	}

	/**
	 * @see ObjectStorage#getDouble()
	 */
	@Override
	public double getDouble() {
		return table.getDouble(row, col++);
	}

	/**
	 * @see ObjectStorage#putInts(int[])
	 */
	@Override
	public void putInts(int[] value) {
		table.putIntArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putBytes(byte[])
	 */
	@Override
	public void putBytes(byte[] value) {
		table.putByteArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putShorts(short[])
	 */
	@Override
	public void putShorts(short[] value) {
		table.putShortArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putLongs(long[])
	 */
	@Override
	public void putLongs(long[] value) {
		table.putLongArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putFloats(float[])
	 */
	@Override
	public void putFloats(float[] value) {
		table.putFloatArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#putDoubles(double[])
	 */
	@Override
	public void putDoubles(double[] value) {
		table.putDoubleArray(row, col++, value);
	}

	/**
	 * @see ObjectStorage#getInts()
	 */
	@Override
	public int[] getInts() {
		return table.getIntArray(row, col++);
	}

	/**
	 * @see ObjectStorage#getBytes()
	 */
	@Override
	public byte[] getBytes() {
		return table.getByteArray(row, col++);
	}
	
	/**
	 * @see ObjectStorage#getShorts()
	 */
	@Override
	public short[] getShorts() {
		return table.getShortArray(row, col++);
	}

	/**
	 * @see ObjectStorage#getLongs()
	 */
	@Override
	public long[] getLongs() {
		return table.getLongArray(row, col++);
	}


	/**
	 * @see ObjectStorage#getFloats()
	 */
	@Override
	public float[] getFloats() {
		return table.getFloatArray(row, col++);
	}

	/**
	 * @see ObjectStorage#getDoubles()
	 */
	@Override
	public double[] getDoubles() {
		return table.getDoubleArray(row, col++);
	}

	/**
	 * @see ObjectStorage#getStrings()
	 */
	@Override
	public String[] getStrings() {
		return table.getStringArray(row, col++);
	}

	/**
	 * @see ObjectStorage#putStrings(String[])
	 */
	@Override
	public void putStrings(String[] value) {
		table.putStringArray(row, col++, value);
	}

}
