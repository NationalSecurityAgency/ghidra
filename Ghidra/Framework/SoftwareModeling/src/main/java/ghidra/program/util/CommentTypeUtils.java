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

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;

public class CommentTypeUtils {

	/**
	 * Get the comment type from the current location. If the cursor
	 * is not over a comment, then just return EOL as the default.
	 * @param cu
	 * @param loc
	 * @param defaultCommentType
	 * @return comment type or defaultCommentType if location does not correspond 
	 * to a comment
	 */
	public static CommentType getCommentType(CodeUnit cu, ProgramLocation loc,
			CommentType defaultCommentType) {
		if (loc instanceof CommentFieldLocation) {
			CommentFieldLocation cfLoc = (CommentFieldLocation) loc;
			CommentType type = cfLoc.getCommentType();
			if (type != null) {
				return type;
			}
		}
		else if (loc instanceof PlateFieldLocation) {
			return CommentType.PLATE;
		}
		else if (loc instanceof FunctionRepeatableCommentFieldLocation) {
			return CommentType.REPEATABLE;
		}
		else if (cu != null) {
			if (cu.getComment(CommentType.PRE) != null) {
				return CommentType.PRE;
			}
			if (cu.getComment(CommentType.POST) != null) {
				return CommentType.POST;
			}
			if (cu.getComment(CommentType.EOL) != null) {
				return CommentType.EOL;
			}
			if (cu.getComment(CommentType.PLATE) != null) {
				return CommentType.PLATE;
			}
			if (cu.getComment(CommentType.REPEATABLE) != null) {
				return CommentType.REPEATABLE;
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
