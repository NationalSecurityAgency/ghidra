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
package ghidra.app.decompiler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Class for accumulating bytes into an automatically expanding buffer with an explicit upper limit to the size
 *
 */
public class LimitedByteBuffer {
	byte value[];
	int count;			// Current number of characters
	int absmax;			// Absolute maximum number of characters
	
	/**
	 * Create the buffer specifying its initial and limiting capacity
	 * @param initial is the number of bytes to be initially allocated for the buffer
	 * @param amax is the absolute maximum number of bytes the buffer is allowed to expand to before throwing exceptions
	 */
	public LimitedByteBuffer(int initial,int amax) {
		value = new byte[initial];
		count = 0;
		absmax = amax;
	}
	
    /**
     * Append a byte into the buffer.  The buffer's internal storage is expanded as necessary, but only up to
     * the specified maximum. If this append exceeds that maximum, then an exception is thrown
     * @param b is the byte to append
     * @throws IOException
     */
    public void append(byte b) throws IOException {
        int newCount = count + 1;
        if (newCount > value.length) {
        	if (newCount > absmax) {
        		int maxResultSizeMBytes = absmax >> 20;
    			throw new IOException("Decompiler results exceeded payload limit of " +
    					maxResultSizeMBytes + " MBytes");
        	}
        	int newcapacity = value.length * 2;
        	if (newcapacity < 0)
        		newcapacity = Integer.MAX_VALUE;
        	if (newcapacity > absmax)
        		newcapacity = absmax;
        	value = Arrays.copyOf(value, newcapacity);
        }
        value[count++] = b;
    }

    /**
     * Generate an InputStream from the bytes that have been appended to the buffer
     * The buffer is NOT copied
     * @return the new InputStream
     */
    public ByteArrayInputStream getInputStream() {
    	return new ByteArrayInputStream(value,0,count);
    }
    
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
    	return new String(value,0,count);
    }
}
