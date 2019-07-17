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
package ghidra.app.plugin.core.searchmem;

public class SearchData {

	private String inputString;
	protected String errorMessage;
	private byte[] bytes;
	private byte[] mask;
	private boolean isValidInputData;
	private boolean isValidSearchData;

	// valid input and search data with mask
	protected SearchData( String inputString, byte[] searchBytes, byte[] mask ) {
		this.isValidInputData = true;
		this.isValidSearchData = true;
		this.inputString = inputString;
		this.bytes = searchBytes == null ? new byte[0] : searchBytes;
		this.mask = mask;
	}
	
	// valid input, bad search data
	private SearchData( String errorMessage, boolean isValidInputData ) {
		this.isValidInputData = isValidInputData;
		this.isValidSearchData = false;
		bytes = new byte[0];
		this.errorMessage = errorMessage;
	}

	public static SearchData createSearchData(String inputString,
			byte[] searchBytes, byte[] mask) {
		return new SearchData(inputString, searchBytes, mask);
	}

	public static SearchData createIncompleteSearchData(String errorMessage) {
		return new SearchData(errorMessage, true);
	}

	public static SearchData createInvalidInputSearchData(String errorMessage) {
		return new SearchData(errorMessage, false);
	}
	
	public byte[] getBytes() {
		return bytes;
	}
	public byte[] getMask() {
		return mask;
	}
	public boolean isValidInputData() {
		return isValidInputData;
	}
	public boolean isValidSearchData() {
		return isValidSearchData;
	}
	public String getInputString() {
		return inputString;
	}
	public String getStatusMessage() {
		return errorMessage;
	}
	public String getHexString() {
		StringBuffer buf = new StringBuffer();
		for(int i=0;i<bytes.length;i++) {
			String hexString = Integer.toHexString(bytes[i] & 0xff);
			if ( hexString.length() == 1 ) {
				buf.append( "0" );
			}
			buf.append( hexString );
			buf.append(" ");
		}
		return buf.toString();
	}
}
