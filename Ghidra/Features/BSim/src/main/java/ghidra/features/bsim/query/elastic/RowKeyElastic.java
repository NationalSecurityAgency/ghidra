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
package ghidra.features.bsim.query.elastic;

import generic.hash.SimpleCRC32;
import ghidra.features.bsim.query.description.*;

/**
 * A "document id" that uniquely indexes documents, within the ElasticSearch database,
 * that describe executables {@link ExecutableRecord} and functions {@link FunctionDescription}
 * This plays the same role as the row id for executable and function rows in an SQL
 * database.
 */
public class RowKeyElastic extends RowKey {
	protected int valueA, valueB, valueC;		// Raw key data - 3 * 32 = 96 bits

	private static int hexString2Int(String val,int start) {
		int res = 0;
		for(int i=0;i<8;++i) {
			res <<= 4;
			char c = val.charAt(i+start);
			if (c <= '9') {
				res += (c-'0');
			}
			else {
				res += (c-'a') + 10;
			}
		}
		return res;
	}

	/**
	 * Initialize a key from a 64-bit long value
	 * @param val is (least significant) 64-bits of the key
	 */
	public RowKeyElastic(long val) {
		valueA = 0;					// Most significant 32-bits are 0
		valueB = (int)(val >>> 32);
		valueC = (int)val;
	}

	/**
	 * Create 96-bit, given 3 32-bit integers
	 * @param a is most significant 32-bits
	 * @param b is middle 32-bits
	 * @param c is least significant 32-bits
	 */
	public RowKeyElastic(int a,int b,int c) {
		valueA = a;
		valueB = b;
		valueC = c;
	}

	/**
	 * Construct key from String representation of an md5 hash.
	 * The key is initialized from the last 96-bits of the hash
	 * @param md5 is the hash
	 */
	public RowKeyElastic(String md5) {
		valueA = hexString2Int(md5,8);
		valueB = hexString2Int(md5,16);
		valueC = hexString2Int(md5,24);
	}

	/**
	 * Key initialized to zero
	 */
	public RowKeyElastic() {
		valueA = 0;
		valueB = 0;
		valueC = 0;
	}

	@Override
	public long getLong() {
		long res = valueB;
		res = (res << 32) | (valueC & 0xffffffffL);
		return res;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		RowKeyElastic o = (RowKeyElastic)obj;
		return (valueA == o.valueA) && (valueB == o.valueB) && (valueC == o.valueC);
	}

	@Override
	public int hashCode() {
		int res = valueA;
		res = res * 113 + valueB;
		res = res * 113 + valueC;
		return res;
	}

	@Override
	public int compareTo(RowKey obj) {
		RowKeyElastic o = (RowKeyElastic)obj;
		if (valueA != o.valueA) {
			long valA = valueA & 0xffffffffL;
			long ovalA = o.valueA & 0xffffffffL;
			return (valA < ovalA) ? -1 : 1;
		}
		if (valueB != o.valueB) {
			long valB = valueB & 0xffffffffL;
			long ovalB = o.valueB & 0xffffffffL;
			return (valB < ovalB) ? -1 : 1;
		}
		if (valueC != o.valueC) {
			long valC = valueC & 0xffffffffL;
			long ovalC = o.valueC & 0xffffffffL;
			return (valC < ovalC) ? -1 : 1;
		}
		return 0;
	}

	/**
	 * Emit the key as a base64 string of 16-characters.
	 * Used to encode executable document ids
	 * @return the String encoding
	 */
	public String generateExeIdString() {
		StringBuilder buf = new StringBuilder();
		int curInt = valueA;
		int chunk;
		chunk = (curInt >> 26) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 20) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 14) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 8) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 2) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = ((curInt & 3) << 4);
		curInt = valueB;
		chunk = chunk | curInt >>> 28;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 22) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 16) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 10) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 4) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = ((curInt & 0xf) << 2);
		curInt = valueC;
		chunk = chunk | curInt >>> 30;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 24) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 18) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 12) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = (curInt >> 6) & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		chunk = curInt & 0x3f;
		buf.append(Base64Lite.encode[chunk]);
		return buf.toString();
	}

	/**
	 * Generate an encoded document id from 64 bits of this key + additional bits
	 * derived from a name string.  This encodes the document id of a library function given
	 * just the function Name and the RowKey (this) of the containing library executable. 
	 * The final String encodes 80-bits of id in 14 characters.
	 * @param buffer is the StringBuilder to encode the id to
	 * @param funcName is a function name that is hashed into the final encoded id
	 */
	public void generateLibraryFunctionId(StringBuilder buffer,String funcName) {
		int hi = valueB;
		int lo = valueC;
		lo &= 0xffff0000;
		for(int i=0;i<funcName.length();++i) {
			int tmp = lo >>> 24;
			lo = SimpleCRC32.hashOneByte(lo, funcName.charAt(i));
			hi = SimpleCRC32.hashOneByte(hi, tmp);
		}
		long res = hi;
		res <<= 32;
		res |= lo & 0xffffffffL;
		int extra = valueC & 0xffff;
		buffer.append(Base64Lite.encode[(extra >> 10)& 0x3f]);
		buffer.append(Base64Lite.encode[(extra >> 4)& 0x3f]);
		buffer.append(Base64Lite.encode[extra & 0xf]);
		Base64Lite.encodeLongBase64Padded(buffer, res);		
	}

	/**
	 * Generate an id string for a FunctionDescription.  If the function is not from a library,
	 * just use the counter id already set for the function and emit it as a decimal string.
	 * If it is from a library, emit an id, 4 bytes of which is from the md5 placeholder hash of the library,
	 * the rest of the id is a base64 encoding of a hash generated from:
	 *   the remainder of the md5 placeholder hash of the library
	 *   the name of the function
	 * @param buffer holds the emitted id string
	 * @param func is the function being labeled
	 */
	public void generateFunctionId(StringBuilder buffer,FunctionDescription func) {
		ExecutableRecord exeRec = func.getExecutableRecord();
		if (!exeRec.isLibrary()) {
			buffer.append(func.getId().getLong());
			return;
		}
		generateLibraryFunctionId(buffer, func.getFunctionName());
	}

	/**
	 * Parse an encoded document id of an executable back into a key
	 * @param id is the encoded String
	 * @return the decoded RowKey
	 */
	public static RowKeyElastic parseExeIdString(String id) {
		int valueA,valueB,valueC;
		valueA = Base64Lite.decode[id.charAt(0)];
		valueA <<= 6;
		valueA |= Base64Lite.decode[id.charAt(1)];
		valueA <<= 6;
		valueA |= Base64Lite.decode[id.charAt(2)];
		valueA <<= 6;
		valueA |= Base64Lite.decode[id.charAt(3)];
		valueA <<= 6;
		valueA |= Base64Lite.decode[id.charAt(4)];
		valueB = Base64Lite.decode[id.charAt(5)];
		valueA = (valueA << 2) | (valueB>>4);
		valueB <<= 6;
		valueB |= Base64Lite.decode[id.charAt(6)];
		valueB <<= 6;
		valueB |= Base64Lite.decode[id.charAt(7)];
		valueB <<= 6;
		valueB |= Base64Lite.decode[id.charAt(8)];
		valueB <<= 6;
		valueB |= Base64Lite.decode[id.charAt(9)];
		valueC = Base64Lite.decode[id.charAt(10)];
		valueB = (valueB << 4) | (valueC >> 2);
		valueC <<= 6;
		valueC |= Base64Lite.decode[id.charAt(11)];		
		valueC <<= 6;
		valueC |= Base64Lite.decode[id.charAt(12)];		
		valueC <<= 6;
		valueC |= Base64Lite.decode[id.charAt(13)];		
		valueC <<= 6;
		valueC |= Base64Lite.decode[id.charAt(14)];		
		valueC <<= 6;
		valueC |= Base64Lite.decode[id.charAt(15)];
		return new RowKeyElastic(valueA,valueB,valueC);
	}

	/**
	 * Parse an encoded document id of a function back into a key
	 * This handles both the normal function form: 64-bits encoded as decimal and
	 * the library function form: 80-bits encoded in base64
	 * @param val is the encoded String
	 * @return the decoded RowKey
	 */
	public static RowKeyElastic parseFunctionId(String val) {
		if (val.length() != 14) {
			return new RowKeyElastic(Long.parseLong(val));
		}
		int extra = Base64Lite.decode[val.charAt(0)];
		extra <<= 6;
		extra |= Base64Lite.decode[val.charAt(1)];
		extra <<= 6;
		extra |= Base64Lite.decode[val.charAt(2)];
		long low = Base64Lite.decodeLongBase64(val.substring(3));
		return new RowKeyElastic(extra,(int)(low>>>32),(int)low);
	}
}
