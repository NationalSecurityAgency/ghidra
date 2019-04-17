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
package docking.widgets.filter;

public interface TextFilter {
	public boolean matches(String text);

	public String getFilterText();

	/**
	 * Returns true if this filter is a more specific filter of the given filter.  This is 
	 * specific to the implementation.   Some filters cannot be sub-filters of another filter, 
	 * such as the 'matches exactly' filter.  Contrastingly, a 'starts with' filter can have
	 * a sub-filter; for example, for a 'starts with' filter, 'cat' is a sub-filter of 'ca', as
	 * 'cat' starts with 'ca'. 
	 * 
	 * @param filter the potential parent filter
	 * @return true if this filter is a more specific filter of the given filter.
	 */
	public boolean isSubFilterOf(TextFilter filter);
}
