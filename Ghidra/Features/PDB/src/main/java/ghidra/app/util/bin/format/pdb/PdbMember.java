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
package ghidra.app.util.bin.format.pdb;

import ghidra.util.exception.CancelledException;

/**
 * <code>PdbMember</code> convey PDB member information used for datatype
 * reconstruction.
 */
public abstract class PdbMember {

	final String memberName;
	final String memberDataTypeName;
	final int memberOffset;
	final String memberComment;

	/**
	 * Construct <code>PdbMember</code>.
	 * @param memberName member name
	 * @param memberDataTypeName member datatype
	 * @param memberOffset member offset within composite
	 * @param memberComment optional member comment (may be null)
	 */
	protected PdbMember(String memberName, String memberDataTypeName, int memberOffset,
			String memberComment) {
		this.memberName = memberName;
		this.memberDataTypeName = memberDataTypeName;
		this.memberOffset = memberOffset;
		this.memberComment = memberComment;
	}

	@Override
	public String toString() {
		return "name=" + memberName + ", type=" + memberDataTypeName + ", offset=" + memberOffset;
	}

	/**
	 * Get the member's name which will correspond to the field name.
	 * @return member field name
	 */
	public String getName() {
		return memberName;
	}

	/**
	 * Get the member's datatype name (may be namespace qualified)
	 * @return member's datatype name
	 */
	public String getDataTypeName() {
		return memberDataTypeName;
	}

	/**
	 * Get the member's byte offset within the root composite.
	 * @return member's byte offset
	 */
	public int getOffset() {
		return memberOffset;
	}

	/**
	 * Get the optional member comment 
	 * @return member comment (may be null)
	 */
	public String getComment() {
		return memberComment;
	}

	/**
	 * Get this member's associated data type which has already been cloned for the 
	 * target program's data type manager.  This indicates a dependency callback
	 * and may be used to trigger resolution for composites.  When resolving dependencies
	 * care must be take to avoid circular dependencies which could occur under certain
	 * error conditions.
	 * @return data-type which corresponds to the specified member's data-type name or null
	 * if unable to resolve.
	 * @throws CancelledException if operation cancelled
	 */
	protected abstract WrappedDataType getDataType() throws CancelledException;

}
