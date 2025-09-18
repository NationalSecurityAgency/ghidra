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
package ghidra.program.model.listing;

/**
 * Types of comments that be placed at an address or on a {@link CodeUnit}
 */
public enum CommentType {

	//
	// IMPORTANT: The ordinals of the defined comment types must be preserved since
	// these values are used for comment storage.  Any new comment types must be added 
	// to the bottom of the list.
	//
	EOL, 		// comments that appear at the end of the line
	PRE, 		// comments that appear before the code unit
	POST, 		// comments that appear after the code unit
	PLATE, 		// comments that appear before the code unit with a decorated border
	REPEATABLE	// comments that appear at locations that refer to the address
				// where this comment is defined
	;

	/**
	 * Get the comment type which corresponds to the specified ordinal value.
	 * <P>
	 * NOTE: This method is intended for conversion of old legacy commentType integer
	 * values to the enum type.
	 * 
	 * @param commentType comment type value
	 * @return comment type enum which corresponds to specified ordinal
	 * @throws IllegalArgumentException if invalid comment type ordinal specified
	 * 
	 */
	public static CommentType valueOf(int commentType) throws IllegalArgumentException {
		try {
			return CommentType.values()[commentType];
		}
		catch (ArrayIndexOutOfBoundsException e) {
			throw new IllegalArgumentException("Invalid comment type: " + commentType, e);
		}
	}

}
