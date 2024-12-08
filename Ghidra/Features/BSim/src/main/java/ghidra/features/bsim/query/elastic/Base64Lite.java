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

import java.util.Arrays;

/**
 * Lightweight Base64 encoder for writing chars directly to StringBuilders and giving
 * direct access to the encode and decode arrays
 *
 */
public class Base64Lite {
	// URL and Filename safe alphabet, RFC 4648 Table 2
	public static final char[] encode = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
        };
    public static final int[] decode= new int[128];
    static {
        Arrays.fill(decode, -1);			// -1 for any invalid character position
        for (int i = 0; i < encode.length; i++)
            decode[encode[i]] = i;
    }

    /**
     * Encode a long value in base64 to a StringBuilder "stream".
     * Omit initial 'A' characters if the high-order bits of the value are zero
     * @param buf is the buffer to write to
     * @param val is the long value to encode
     */
    public static void encodeLongBase64(StringBuilder buf,long val) {
    	boolean seenNonZero = false;
    	if (val == 0) {
    		buf.append(encode[0]);
    		return;
    	}
    	for(int i=60;i>=0;i-=6) {
    		int chunk = (int)(val >> i) & 0x3f;
    		if (chunk == 0 && seenNonZero) {
    			buf.append(encode[chunk]);
    		}
    		else {
    			buf.append(encode[chunk]);
    			seenNonZero = true;
    		}
    	}
    }

    /**
     * Encode a long value in base64 to the StringBuilder "stream" padding out with 'A' characters
     * so that exactly 11 characters are always written to the stream
     * @param buf is the buffer to write to
     * @param val is the long value to encode
     */
    public static void encodeLongBase64Padded(StringBuilder buf,long val) {
    	for(int i=60;i>=0;i-=6) {
    		int chunk = (int)(val >> i) & 0x3f;
    		buf.append(encode[chunk]);
    	}
    }
 
    /**
     * Encode a long value in base64 to a String. Omit initial 'A' characters if the high-order bits of the value are zero
     * @param val is the long to encode
     * @return the encoded String
     */
    public static String encodeLongBase64(long val) {
    	char[] buffer = new char[11];
    	if (val == 0) {
    		buffer[0] = encode[0];
    		return new String(buffer,0,1);
    	}
    	int pos = 0;
    	boolean seenNonZero = false;
    	for(int i=60;i>=0;i-=6) {
    		int chunk = (int)(val >> i) & 0x3f;
    		if (chunk == 0 && seenNonZero) {
    			buffer[pos++] = encode[chunk];
    		}
    		else {
    			buffer[pos++] = encode[chunk];
    			seenNonZero = true;
    		}
    	}
    	return new String(buffer,0,pos);
    }

    /**
     * Decode (up to 11) base64 characters to produce a long
     * @param val is the String to decode
     * @return the decode long
     */
    public static long decodeLongBase64(String val) {
    	long res = 0;
    	for(int i=0;i<val.length();++i) {
    		int chunk = decode[val.charAt(i)];
    		if (chunk < 0)
    			throw new NumberFormatException("Bad base64 encoding");
    		res <<= 6;
    		res |= chunk;
    	}
    	return res;
    }
}
