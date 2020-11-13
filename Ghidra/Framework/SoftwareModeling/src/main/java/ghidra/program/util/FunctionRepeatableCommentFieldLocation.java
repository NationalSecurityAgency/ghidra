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

import java.util.Arrays;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * The <CODE>FunctionRepeatableCommentFieldLocation</CODE> class provides specific information
 * about the Function Repeatable Comment field within a program location.
 */
public class FunctionRepeatableCommentFieldLocation extends FunctionLocation {

	private String[] commentArray;

	/**
	 * Construct a new FunctionRepeatableCommentFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param functionAddr the function address
	 * @param comment the function comment array String at this location.
	 * @param row row number (index into the comment array)
	 * @param charOffset character position within the comment, indexed by row
	 */
	public FunctionRepeatableCommentFieldLocation(Program program, Address locationAddr,
			Address functionAddr, String[] comment, int row, int charOffset) {
		super(program, locationAddr, functionAddr, row, 0, charOffset);
		this.commentArray = comment;
	}

	/**
	 * Construct a new FunctionRepeatableCommentFieldLocation object.
	 * 
	 * @param program the program of the location
	 * @param functionAddr the function address (must not be an EXTERNAL function)
	 * @param comment the function comment array String at this location.
	 * @param row row number (index into the comment array)
	 * @param col character position within the comment, indexed by row
	 */
	public FunctionRepeatableCommentFieldLocation(Program program, Address functionAddr,
			String[] comment, int row, int col) {
		this(program, functionAddr, functionAddr, comment, row, col);
	}

	/**
	 * Default constructor needed for restoring
	 * a program location from XML
	 */
	public FunctionRepeatableCommentFieldLocation() {
	}

	/**
	 * Return the function comment string at this location.
	 */
	public String[] getComment() {
		return commentArray;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + Arrays.hashCode(commentArray);
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
		FunctionRepeatableCommentFieldLocation other = (FunctionRepeatableCommentFieldLocation) obj;
		if (!Arrays.equals(commentArray, other.commentArray))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_COMMENT", commentArray);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		commentArray = obj.getStrings("_COMMENT", null);
	}

}
