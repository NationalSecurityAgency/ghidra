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

import java.util.List;

/**
 * Interface for managing function tags. Tags are simple objects consisting of a name and an 
 * optional comment, which can be applied to functions.
 * 
 * See ghidra.program.database.function.FunctionTagAdapter 
 * See ghidra.program.database.function.FunctionTagMappingAdapter 
 */
public interface FunctionTagManager {

	/**
	 * Returns the function tag with the given name
	 * 
	 * @param name the tag name
	 * @return the function tag, or null if not found
	 */
	public FunctionTag getFunctionTag(String name);

	/**
	 * Returns the function tag with the given database id
	 * 
	 * @param id the tags database id
	 * @return the function tag, or null if not found
	 */
	public FunctionTag getFunctionTag(long id);

	/**
	 * Returns all function tags in the database
	 * 
	 * @return list of function tags
	 */
	public List<? extends FunctionTag> getAllFunctionTags();

	/**
	 * Returns true if the given tag is assigned to a function
	 * 
	 * @param name the tag name
	 * @return true if assigned to a function
	 */
	public boolean isTagAssigned(String name);

	/**
	 * Creates a new function tag with the given attributes if one does
	 * not already exist. Otherwise, returns the existing tag.
	 * 
	 * @param name the tag name
	 * @param comment the comment associated with the tag (optional)
	 * @return the new function tag
	 */
	public FunctionTag createFunctionTag(String name, String comment);

	/**
	 * Returns the number of times the given tag has been applied to a function
	 * @param tag the tag
	 * @return the count
	 */
	public int getUseCount(FunctionTag tag);
}
