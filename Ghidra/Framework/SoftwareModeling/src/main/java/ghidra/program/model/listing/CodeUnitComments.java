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
 * Container for all the comments at an address
 */
public class CodeUnitComments {
	private String[] comments;

	public CodeUnitComments(String[] comments) {
		if (comments.length != CommentType.values().length) {
			throw new IllegalArgumentException("comment array size does not match enum size!");
		}
		this.comments = comments;
	}

	/**
	 * Get the comment for the given comment type
	 * @param type the {@link CommentType} to retrieve
	 * @return the comment of the given type or null if no comment of that type exists
	 */
	public String getComment(CommentType type) {
		return comments[type.ordinal()];
	}

}
