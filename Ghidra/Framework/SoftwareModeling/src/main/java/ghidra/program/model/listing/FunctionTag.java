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
 * Represents a function tag object that can be associated with 
 * functions. This maps to the  {@code FunctionTagAdapter} table.
 */
public interface FunctionTag extends Comparable<FunctionTag> {

	/**
	 * Returns the id of the item
	 * @return the id of the item
	 */
	public long getId();

	/**
	 * Returns the tag name
	 * @return the tag name
	 */
	public String getName();

	/**
	 * Returns the tag comment
	 * @return the tag comment
	 */
	public String getComment();

	/**
	 * Sets the name of the tag
	 * @param name the tag name
	 */
	public void setName(String name);

	/**
	 * Sets the comment for this tag
	 * @param comment the tag comment
	 */
	public void setComment(String comment);

	/**
	 * Deletes this tag from the program 
	 */
	public void delete();
}
