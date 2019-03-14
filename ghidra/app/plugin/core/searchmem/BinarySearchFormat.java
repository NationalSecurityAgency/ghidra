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
package ghidra.app.plugin.core.searchmem;

import java.util.*;

import javax.swing.event.ChangeListener;

import ghidra.util.HTMLUtilities;

public class BinarySearchFormat extends SearchFormat {
	private static final String VALID_CHARS = "01x?.";
	private String statusText;
	
	public BinarySearchFormat(ChangeListener listener) {
		super("Binary", listener);
	}

	@Override
    public String getToolTip() {
		return HTMLUtilities.toHTML(
				"Interpret value as a sequence of binary digits.\n"+
				"Spaces will start the next byte.  Bit sequences less\n"+
				"than 8 bits are padded with 0's to the left. \n"+
				"Enter 'x', '.' or '?' for a wildcard bit");
	}

	@Override
    public SearchData getSearchData(String input) {
        StringTokenizer st = new StringTokenizer(input);
        int n = st.countTokens();
        byte[] bytes = new byte[n];
        byte[] mask = new byte[n];
        
        int index = 0;
        while (st.hasMoreTokens()) {
            String token = st.nextToken();
            
            if (!isValidBinary(token)) {
                return SearchData.createInvalidInputSearchData(statusText);
            }
            bytes[index] = getByte(token);
            mask[index] = getMask(token);
            index++;
        }
        return SearchData.createSearchData(input, bytes, mask);
	}

	private boolean isValidBinary(String str) {
        if (str.length() > 8) {
        	statusText = "Max group size exceeded. Enter <space> to add more.";
            return false;
        }
        statusText = "";
        for(int i=0;i<str.length();i++) {
            if (VALID_CHARS.indexOf(str.charAt(i)) < 0) {
                return false;
            }
        }
        return true;
    }
	
	private byte getByte(String token) {
		byte b = 0;
		for(int i=0;i<token.length();i++) {
			b <<= 1;
			char c = token.charAt(i);
			if (c == '1') {
				b |= 1;
			}
		}
		return b;
	}
	
	/**
	 * Return a mask byte that has a bit set to 1 for each bit that is not a wildcard.  Any bits
	 * that aren't specified (i.e. token.lenght &lt; 8) are treated as valid test bits. 
	 * @param token the string of bits to determine a mask for.
	 */
	private byte getMask(String token) {
		byte b = 0;
		for(int i=0;i<8;i++) {
			b <<= 1;
			if (i < token.length()) {
				char c = token.charAt(i);
				if (c == '1' || c == '0') {
					b |= 1;
				}
			}
			else {
				b |= 1;
			}
			
		}
		
		return b;
	}
	@Override
    public boolean usesEndieness() {
		return false;
	}
	
}
