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
package ghidra.program.util;

import ghidra.program.model.listing.CodeUnit;

public class CommentType {

	/**
	 * Get the comment type from the current location. If the cursor
	 * is not over a comment, then just return EOL as the default.
	 * @param cu
	 * @param loc
	 * @param defaultCommentType
	 * @return comment type
	 */
	public static int getCommentType(CodeUnit cu, ProgramLocation loc, int defaultCommentType) {
		if (loc instanceof CommentFieldLocation) {
			CommentFieldLocation cfLoc = (CommentFieldLocation) loc;
			return cfLoc.getCommentType();
		}
		else if (loc instanceof PlateFieldLocation) {
			return CodeUnit.PLATE_COMMENT;
		}
		else if (loc instanceof FunctionRepeatableCommentFieldLocation) {
			return CodeUnit.REPEATABLE_COMMENT;
		}
		else if (cu != null) {
			if (cu.getComment(CodeUnit.PRE_COMMENT) != null) {
				return CodeUnit.PRE_COMMENT;
			}
			if (cu.getComment(CodeUnit.POST_COMMENT) != null) {
				return CodeUnit.POST_COMMENT;
			}
			if (cu.getComment(CodeUnit.EOL_COMMENT) != null) {
				return CodeUnit.EOL_COMMENT;
			}
			if (cu.getComment(CodeUnit.PLATE_COMMENT) != null) {
				return CodeUnit.PLATE_COMMENT;
			}
			if (cu.getComment(CodeUnit.REPEATABLE_COMMENT) != null) {
				return CodeUnit.REPEATABLE_COMMENT;
			}
		}
		return defaultCommentType;
	}

	public static boolean isCommentAllowed(CodeUnit cu, ProgramLocation loc) {
		if (cu == null) {
			return false;
		}
		// changed ref SCR #8041
//		if (cu instanceof Data) {
//			Data d = (Data) cu;
//			if (d.getNumComponents() > 0) {
//				return false;
//			}
//		}
		return true;
	}

}
