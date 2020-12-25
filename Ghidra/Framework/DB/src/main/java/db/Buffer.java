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

/**
 * <code>Buffer</code> provides a general purpose storage buffer interface
 * providing various data access methods.
 */
public interface Buffer {

	/**
	 * Get the buffer ID for this buffer.
	 * @return int
	 */
	public int getId();

	/**
	 * Get the length of the buffer in bytes.  The length reflects the number of
	 * bytes which have been allocated to the buffer.
	 * @return length of allocated buffer.
	 */
	public int length();

	/**
	 * Get the byte data located at the specified offset and store into the
	 * bytes array provided. 
	 * @param offset byte offset from start of buffer.
	 * @param bytes byte array to store data
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void get(int offset, byte[] bytes) throws IOException;

	/**
	 * Get the byte data located at the specified offset and store into the data
	 * array  at the specified data offset.
	 * @param offset byte offset from the start of the buffer.
	 * @param data byte array to store the data.
	 * @param dataOffset offset into the data buffer
	 * @param length amount of data to read
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset, dataOffset,
	 * or length is specified.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void get(int offset, byte[] data, int dataOffset, int length) throws IOException;

	/**
	 * Get the byte data located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @param length number of bytes to be read and returned
	 * @return the byte array.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified or the end of the buffer was encountered while reading the
	 * data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public byte[] get(int offset, int length) throws IOException;

	/**
	 * Get the 8-bit byte value located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @return the byte value at the specified offset.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public byte getByte(int offset) throws IOException;

	/**
	 * Get the 32-bit integer value located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @return the integer value at the specified offset.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified or the end of the buffer was encountered while reading the
	 * value.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int getInt(int offset) throws IOException;

	/**
	 * Get the 16-bit short value located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @return the short value at the specified offset.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified or the end of the buffer was encountered while reading the
	 * value.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public short getShort(int offset) throws IOException;

	/**
	 * Get the 64-bit long value located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @return the long value at the specified offset.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified or the end of the buffer was encountered while reading the
	 * value.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public long getLong(int offset) throws IOException;

	/**
	 * Put a specified number of bytes from the array provided into the buffer
	 * at the specified offset.  The number of bytes stored is specified by the
	 * length specified.
	 * @param offset byte offset from start of buffer.
	 * @param data the byte data to be stored.
	 * @param dataOffset the starting offset into the data.
	 * @param length the number of bytes to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int put(int offset, byte[] data, int dataOffset, int length) throws IOException;

	/**
	 * Put the bytes provided into the buffer at the specified offset. The
	 * number of bytes stored is determined by the length of the bytes
	 * array.
	 * @param offset byte offset from start of buffer.
	 * @param bytes the byte data to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int put(int offset, byte[] bytes) throws IOException;

	/**
	 * Put the 8-bit byte value into the buffer at the specified offset. 
	 * @param offset byte offset from start of buffer.
	 * @param b the byte value to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int putByte(int offset, byte b) throws IOException;

	/**
	 * Put the 32-bit integer value into the buffer at the specified offset. 
	 * @param offset byte offset from start of buffer.
	 * @param v the integer value to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int putInt(int offset, int v) throws IOException;

	/**
	 * Put the 16-bit short value into the buffer at the specified offset. 
	 * @param offset byte offset from start of buffer.
	 * @param v the short value to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int putShort(int offset, short v) throws IOException;

	/**
	 * Put the 64-bit long value into the buffer at the specified offset. 
	 * @param offset byte offset from start of buffer.
	 * @param v the long value to be stored.
	 * @return the next available offset into the buffer, or -1 if the buffer is
	 * full.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public int putLong(int offset, long v) throws IOException;

}
