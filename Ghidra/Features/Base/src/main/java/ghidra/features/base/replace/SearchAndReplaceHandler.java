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
package ghidra.features.base.replace;

import java.util.HashSet;
import java.util.Set;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for discoverable SearchAndReplaceHandlers. A SearchAndReplaceHandler is responsible
 * for searching one or more specific program elements (referred to as {@link SearchType}) for a
 * given search pattern and generating the appropriate {@link QuickFix}. 
 * <P>
 * Typically, one handler will handle related search elements for efficiency. For example, the 
 * DataTypesSearchAndReplaceHandler is responsible for datatype names, field names, field comments,
 * etc. The idea is to only loop through all the datatypes once, regardless of what aspect of a 
 * datatype you are searching for.
 */
public abstract class SearchAndReplaceHandler implements ExtensionPoint {
	private Set<SearchType> types = new HashSet<>();

	/**
	 * Method to perform the search for the pattern and options as specified by the given 
	 * SearchAndReplaceQuery. As matches are found, appropriate {@link QuickFix}s are added to
	 * the given accumulator.
	 * @param program the program being searched
	 * @param query contains the search pattern, replacement pattern, and options related to the 
	 * query.
	 * @param accumulator the accumulator that resulting QuickFix items are added to as they are 
	 * found.
	 * @param monitor a {@link TaskMonitor} for reporting progress and checking if the search has
	 * been cancelled.
	 * @throws CancelledException thrown if the operation has been cancelled via the taskmonitor
	 */
	public abstract void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException;

	/**
	 * Returns the set of {@link SearchType}s this handler supports.
	 * @return the set of {@link SearchType}s this handler supports.
	 */
	public Set<SearchType> getSearchAndReplaceTypes() {
		return types;
	}

	protected void addType(SearchType type) {
		types.add(type);
	}
}
