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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;

/**
 * The <CODE>EolCommentFieldLocation</CODE> class contains specific location information
 * within the EOL comment field of a CodeUnitLocation object.
 */
public class PostCommentFieldLocation extends CommentFieldLocation {

	/**
	 * Construct a new PostCommentFieldLocation.
	 * 
	 * @param program the program of the location
	 * @param addr the address of the codeunit.
	 * @param componentPath the componentPath of the codeUnit
	 * @param comment comment text for the particular comment indicated by the address, subtype, and reference address.
	 * @param displayableCommentRow the line within the Post comment as displayed.
	 * @param charOffset the character position on the line within the comment line.
	 */
	public PostCommentFieldLocation(Program program, Address addr, int[] componentPath,
			String[] comment, int displayableCommentRow, int charOffset) {
		super(program, addr, componentPath, comment, CodeUnit.POST_COMMENT, displayableCommentRow,
			charOffset);
	}

	/**
	 * Default constructor needed for restoring
	 * an end-of-line field location from XML.
	 */
	public PostCommentFieldLocation() {
		super();
	}

}
