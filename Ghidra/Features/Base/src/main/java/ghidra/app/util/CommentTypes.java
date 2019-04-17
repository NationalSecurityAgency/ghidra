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
package ghidra.app.util;

import ghidra.program.model.listing.CodeUnit;

/**
 * Class with a convenience method to get an array of the CodeUnit
 * comment types. The method is useful to loop through the comment types
 * once you have a code unit.
 */
public class CommentTypes {

    private static int[] COMMENT_TYPES;
    private static int NUMBER_OF_COMMENT_TYPES=5;
    
    CommentTypes() {
    }
    static {
    	COMMENT_TYPES = new int[NUMBER_OF_COMMENT_TYPES];
		COMMENT_TYPES[0] = CodeUnit.PRE_COMMENT;
		COMMENT_TYPES[1] = CodeUnit.POST_COMMENT;
		COMMENT_TYPES[2] = CodeUnit.EOL_COMMENT;
		COMMENT_TYPES[3] = CodeUnit.PLATE_COMMENT;		
		COMMENT_TYPES[4] = CodeUnit.REPEATABLE_COMMENT;		
    }
	/**
	 * Get an array containing the comment types on a code unit.
	 */
	public static int[] getTypes() {
		return COMMENT_TYPES;
	}
} 
