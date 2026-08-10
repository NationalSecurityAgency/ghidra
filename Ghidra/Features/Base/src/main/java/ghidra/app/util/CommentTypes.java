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
package ghidra.app.util;

import ghidra.program.model.listing.CommentType;

/**
 * Class with a convenience method to get an array of the CodeUnit
 * comment types. The method is useful to loop through the comment types
 * once you have a code unit.
 * 
 * @deprecated the {@link CommentType enum should be used in place of integers}
 */
@Deprecated(forRemoval = true, since = "11.4")
public class CommentTypes {

	@Deprecated(forRemoval = true, since = "11.4")
	CommentTypes() {
	}

	/**
	 * {@return an array containing the comment types on a code unit}
	 */
	@Deprecated(forRemoval = true, since = "11.4")
	public static int[] getTypes() {
		CommentType[] types = CommentType.values();
		int[] ret = new int[types.length];
		for (int i = 0; i < types.length; i++) {
			ret[i] = types[i].ordinal();
		}
		return ret;
	}
}
