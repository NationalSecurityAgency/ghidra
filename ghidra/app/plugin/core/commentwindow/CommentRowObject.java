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
package ghidra.app.plugin.core.commentwindow;

import ghidra.program.model.address.Address;

class CommentRowObject implements Comparable<CommentRowObject> {

	private final Address address;
	private final int commentType;

	CommentRowObject(Address address, int commentType) {
		this.address = address;
		this.commentType = commentType;
	}

	Address getAddress() {
		return address;
	}

	int getCommentType() {
		return commentType;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		result = prime * result + commentType;
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
		CommentRowObject other = (CommentRowObject) obj;
		if (address == null) {
			if (other.address != null) {
				return false;
			}
		}
		else if (!address.equals(other.address)) {
			return false;
		}
		if (commentType != other.commentType) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(CommentRowObject o) {

		int result = address.compareTo(o.address);
		if (result == 0) {
			result = commentType - o.commentType;
		}
		return result;
	}
}
