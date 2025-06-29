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
package ghidra.program.util;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;

/**
 * The <CODE>RefRepeatCommentFieldLocation</CODE> class contains specific location information
 * within the Referenced Repeatable comments of an EOL comment field of a CodeUnitLocation object.
 */
public class RefRepeatCommentFieldLocation extends CommentFieldLocation {
	private int currentCommentRow;
	private Address refRepeatAddress;

	/**
	 * Construct a new RefRepeatCommentFieldLocation.
	 * 
	 * @param program the program of the location
	 * @param addr the address of the codeunit.
	 * @param componentPath the componentPath of the codeUnit
	 * @param comment comment text for the particular comment indicated by the address, subtype, and reference address.
	 * @param row the line within the Eol comment.
	 * @param charOffset the character position on the line within the comment line.
	 * @param currentCommentRow the row index relative to the beginning of the particular 
	 * referenced repeatable comment that is displayed at this location in the Eol comment field.
	 * @param refRepeatAddress the referred to address for the referenced repeatable comment that
	 * is being displayed at this location.
	 */
	public RefRepeatCommentFieldLocation(Program program, Address addr, int[] componentPath,
			String[] comment, int row, int charOffset, int currentCommentRow,
			Address refRepeatAddress) {
		super(program, addr, componentPath, comment, CommentType.EOL, row, charOffset);
		this.currentCommentRow = currentCommentRow;
		this.refRepeatAddress = refRepeatAddress;
	}

	/**
	 * Default constructor needed for restoring
	 * an end-of-line field location from XML.
	 */
	public RefRepeatCommentFieldLocation() {
		super();
	}

	public Address getReferencedRepeatableAddress() {
		return refRepeatAddress;
	}

	public int getCurrentCommentRow() {
		return currentCommentRow;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + currentCommentRow;
		result = prime * result + ((refRepeatAddress == null) ? 0 : refRepeatAddress.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		RefRepeatCommentFieldLocation other = (RefRepeatCommentFieldLocation) obj;
		if (currentCommentRow != other.currentCommentRow)
			return false;
		if (refRepeatAddress == null) {
			if (other.refRepeatAddress != null)
				return false;
		}
		else if (!refRepeatAddress.equals(other.refRepeatAddress))
			return false;
		return true;
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		currentCommentRow = obj.getInt("_COMMENT_ROW", 0);
		String refRepeatAddrStr = obj.getString("_REF_REPEAT_ADDRESS", null);
		if (refRepeatAddrStr != null) {
			refRepeatAddress = ProgramUtilities.parseAddress(p, refRepeatAddrStr);
		}
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putInt("_COMMENT_ROW", currentCommentRow);
		if (refRepeatAddress != null) {
			obj.putString("_REF_REPEAT_ADDRESS", refRepeatAddress.toString());
		}
	}

	@Override
	public String toString() {
		return super.toString() + ", RefRepeatAddr = " + refRepeatAddress + ", Comment Row = " +
			currentCommentRow;
	}
}
