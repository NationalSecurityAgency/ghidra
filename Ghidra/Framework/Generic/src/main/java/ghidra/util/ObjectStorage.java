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
package ghidra.util;

/**
 * 
 * Methods for saving and restoring Strings and Java primitives or arrays of
 * Strings and primitives. The order in which the puts are done must the
 * same order in which the gets are done.
 * 
 * 
 *
 */
public interface ObjectStorage {

	/**
	 * Store an integer value.
	 * @param value The value in the name,value pair.
	 */
	public void putInt(int value);

	/**
	 * Store a byte value.
	 * @param value The value in the name,value pair.
	 */
	public void putByte(byte value);

	/**
	 * Store a short value.
	 * @param value The value in the name,value pair.
	 */
	public void putShort(short value);

	/**
	 * Store a long value.
	 * @param value The value in the name,value pair.
	 */
	public void putLong(long value);

	/**
	 * Store a String value.
	 * @param value The value in the name,value pair.
	 */
	public void putString(String value);

	/**
	 * Store a boolean value.
	 * @param value The value in the name,value pair.
	 */
	public void putBoolean(boolean value);
	
	/**
	 * Store a float value.
	 * @param value The value in the name,value pair.
	 */
	public void putFloat(float value);

	/**
	 * Store a double value.
	 * @param value The value in the name,value pair.
	 */
	public void putDouble(double value);

	/**
	 * Gets the int value.
	 */
	public int getInt();

	/**
	 * Gets the byte value.
	 */
	public byte getByte();
	
	/**
	 * Gets the short value.
	 */
	public short getShort();
	/**
	 * Gets the long value.
	 */
	public long getLong();

	/**
	 * Gets the boolean value.
	 */
	public boolean getBoolean();
	/**
	 * Gets the String value.
	 */
	public String getString();

	/**
	 * Gets the float value.
	 */
	public float getFloat();

	/**
	 * Gets the double value.
	 */
	public double getDouble();

	/**
	 * Store an integer array.
	 */
	public void putInts(int[] value);

	/**
	 * Store a byte array.
	 */
	public void putBytes(byte[] value);

	/**
	 * Store a short array.
	 */
	public void putShorts(short[] value);
	
	/**
	 * Store a long array.
	 */
	public void putLongs(long[] value);
	

	/**
	 * Store a float array.
	 */
	public void putFloats(float[] value);
	
	/**
	 * Store a double array value.
	 */
	public void putDoubles(double[] value);

	/**
	 * Store a String[] value.
	 */
	public void putStrings(String[] value);

	/**
	 * Gets the int array.
	 */
	public int[] getInts();

	/**
	 * Gets the byte array.
	 */
	public byte[] getBytes();

	/**
	 * Gets the short array.
	 */
	public short[] getShorts();

	/**
	 * Gets the long array.
	 */
	public long[] getLongs();
	    
	/**
	 * Gets the float array.
	 */
	public float[] getFloats();

	/**
	 * Gets the double array.
	 */
	public double[] getDoubles();
	
	/**
	 * Gets the array of Strings
	 */
	public String[] getStrings();

}
