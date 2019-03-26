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
package ghidra.util.datastruct;

import java.io.Serializable;

/**
 * Array of String[] that grows as needed.
 */
public class StringArrayArray implements Array, Serializable {
	private final static long serialVersionUID = 1;

	private ByteArrayArray byteStore;
	/**
	 * Constructor for StringArrayArray.
	 */
	public StringArrayArray() {
		super();
		byteStore = new ByteArrayArray();
	}

	/**
	 * Stores the string array at the given index.
	 * @param index the index to store the array
	 * @param value the array to store
	 */
	public void put(int index, String[] value) {
		if (value == null) {
			remove(index);
		}
		byte[] bytes = stringArrayToBytes(value);
		byteStore.put(index, bytes);	
	}

	/**
	 * Retrieves the String array stored at the given index.
	 * @param index the index at which to retrieve the array.
	 * @return String[] the String array at the index.
	 */
	public String[] get(int index) {
		byte[] bytes = byteStore.get(index);
		if (bytes == null) {
			return null;
		}
		return bytesToStringArray(bytes);
	}

	/**
	 * @see Array#copyDataTo(int, DataTable, int, int)
	 */
	public void copyDataTo(int index,
							DataTable table,
							int toIndex,
							int toCol) {
		table.putStringArray(toIndex, toCol, get(index));
 
	}

	/**
	 * @see Array#getLastNonEmptyIndex()
	 */
	public int getLastNonEmptyIndex() {
		return byteStore.getLastNonEmptyIndex();
	}

	/**
	 * @see Array#remove(int)
	 */
	public void remove(int index) {
		byteStore.remove(index);
	}

	private byte[] stringArrayToBytes(String[] value) {
		int len = 4;  // 4 bytes to store the number of strings in the array
		for(int i=0;i<value.length;i++) {
			len += 2;  // 2 bytes to store the length of each string
			if (value[i] != null) {
				len += value[i].length();  // plus the bytes for the string.
			}
		}
		byte[] bytes = new byte[len];
		int n = value.length;
		bytes[0] = (byte)(n >> 24);
		bytes[1] = (byte)(n >> 16);
		bytes[2] = (byte)(n >> 8);			
		bytes[3] = (byte)n;
		int pos = 4;
		for(int i=0;i<n;i++) {
			if (value[i] == null) {
				bytes[pos++] = (byte)-1;
				bytes[pos++] = (byte)-1;
			}
			else {
				int strlen = value[i].length();
			
				bytes[pos++] = (byte)(strlen >> 8);
				bytes[pos++] = (byte)(strlen);
				System.arraycopy(value[i].getBytes(),0,bytes,pos,strlen);
				pos += strlen;
			}
		}
		return bytes;
	}
	private String[] bytesToStringArray(byte[] bytes) {
		int numStrings = ((bytes[0] & 0xff) << 24) +
					      ((bytes[1] & 0xff) << 16) +			
					      ((bytes[2] & 0xff) << 8) + 
					      (bytes[3] & 0xff);

		String[] strings = new String[numStrings];
		
		int pos = 4;
		for(int i=0;i<numStrings;i++) {
			int strlen = (bytes[pos] << 8) + ((bytes[pos+1]) & 0xff);	
			if (strlen >= 0) {
				strings[i] = new String(bytes,pos+2,strlen);
 				pos += strlen;
			}
			pos += 2;
		}
		return strings;							  
	}

}
