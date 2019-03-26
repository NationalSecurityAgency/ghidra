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
package ghidra.app.util;

import java.util.Arrays;

import ghidra.program.model.address.Address;

public class RefRepeatComment {
	private Address address;
	private String[] commentLines;

	RefRepeatComment(Address address, String[] commentLines) {
		this.address = address;
		this.commentLines = commentLines;
	}

	public Address getAddress() {
		return address;
	}

	public String[] getCommentLines() {
		return commentLines;
	}

	public int getCommentLineCount() {
		return commentLines.length;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		result = prime * result + Arrays.hashCode(commentLines);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RefRepeatComment other = (RefRepeatComment) obj;
		if (address == null) {
			if (other.address != null) {
				return false;
			}
		}
		else if (!address.equals(other.address)) {
			return false;
		}
		if (!Arrays.equals(commentLines, other.commentLines)) {
			return false;
		}
		return true;
	}

}
