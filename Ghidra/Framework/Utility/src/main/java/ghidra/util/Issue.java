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
package ghidra.util;

import java.util.List;

// Interface used to document an issue that arises during some action, operation, or task.  Typically,
// issues will be reported within a task using the TaskMonitor.

public interface Issue {

	/**
	 * Returns the category for this issue.  Categories may use '.' as separators to present 
	 * a hierarchical category structure.
	 * @return the category for this issue.
	 */
	public String getCategory();

	/**
	 * Returns a detailed description of the issue.
	 * @return a detailed description of the issue.
	 */
	public String getDescription();

	/**
	 * Returns a Location object that describes where the issue occurred.
	 * @return a Location object that describes where the issue occurred. May return null
	 * if the issue is not related to a specific location.
	 */
	public Location getPrimaryLocation();

	/**
	 * Returns a list of locations related to the issue that are not the primary issue location.
	 * @return a list of locations related to the issue that are not the primary issue location.  
	 * This list may be empty, but not null.
	 */
	public List<Location> getSecondaryLocations();

	/**
	 * Returns a list of possible Fixup objects for this issue.
	 * @return a list of possible Fixup objects for this issue. This list may be empty, but not null.
	 */
	public List<Fixup> getPossibleFixups();

}
