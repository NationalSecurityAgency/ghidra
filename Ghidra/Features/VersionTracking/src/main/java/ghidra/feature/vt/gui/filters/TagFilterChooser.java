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
package ghidra.feature.vt.gui.filters;

import ghidra.feature.vt.api.main.VTMatchTag;

import java.util.Map;

interface TagFilterChooser {

	/**
	 * Returns a map of tag string values to tags that are <b>excluded</b>.  That is, the given
	 * map of tags are those which the client filter should exclude from view.
	 * 
	 * @param allTags All known existing tags.  This will be used to determine which tags should 
	 *                be excluded
	 * @param currentExcludedTags The current collection of excluded tags.  This will be used to
	 *                            seed the excluded tag choices for this chooser.
	 */
	public Map<String, VTMatchTag> getExcludedTags(Map<String, VTMatchTag> allTags,
			Map<String, VTMatchTag> currentExcludedTags);
}
