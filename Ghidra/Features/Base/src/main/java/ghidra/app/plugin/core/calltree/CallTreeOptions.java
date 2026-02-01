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
package ghidra.app.plugin.core.calltree;

import ghidra.framework.options.SaveState;

/**
 * Settings for the {@link CallTreePlugin}.  This class is immutable.
 */
public class CallTreeOptions {

	private static final String DEFAULT_RECURSE_DEPTH = "5";

	private static final String RECURSE_DEPTH_KEY = "RECURSE_DEPTH";
	private static final String FILTER_DUPLICATES_KEY = "FILTER_DUPLICATES";
	private static final String FILTER_REFERENCES_KEY = "FILTER_REFERENCES";
	private static final String FILTER_THUNKS_KEY = "FILTER_THUNKS";
	private static final String SHOW_NAMESPACE_KEY = "SHOW_NAMESPACE";

	private boolean filterDuplicates = true;
	private boolean filterReferences = false;
	private boolean filterThunks = false;
	private boolean showNamespace = false;
	private int recurseDepth = Integer.parseInt(DEFAULT_RECURSE_DEPTH);

	CallTreeOptions() {
		// default constructor
	}

	CallTreeOptions(SaveState saveState) {
		filterDuplicates = saveState.getBoolean(FILTER_DUPLICATES_KEY, true);
		filterReferences = saveState.getBoolean(FILTER_REFERENCES_KEY, true);
		filterThunks = saveState.getBoolean(FILTER_THUNKS_KEY, false);
		showNamespace = saveState.getBoolean(SHOW_NAMESPACE_KEY, false);
		recurseDepth = saveState.getInt(RECURSE_DEPTH_KEY, recurseDepth);
	}

	void save(SaveState saveState) {
		saveState.putBoolean(FILTER_DUPLICATES_KEY, filterDuplicates);
		saveState.putBoolean(FILTER_REFERENCES_KEY, filterReferences);
		saveState.putBoolean(FILTER_THUNKS_KEY, filterThunks);
		saveState.putBoolean(SHOW_NAMESPACE_KEY, showNamespace);
		saveState.putInt(RECURSE_DEPTH_KEY, recurseDepth);
	}

	private CallTreeOptions copy() {
		CallTreeOptions newOptions = new CallTreeOptions();
		newOptions.filterDuplicates = filterDuplicates;
		newOptions.filterThunks = filterThunks;
		newOptions.showNamespace = showNamespace;
		newOptions.recurseDepth = recurseDepth;
		return newOptions;
	}

	public int getRecurseDepth() {
		return recurseDepth;
	}

	public boolean allowsDuplicates() {
		return !filterDuplicates;
	}

	/**
	 * This value is based on the {@code filterReferences} value.  When filtering references, we 
	 * only allow call references to be shown.
	 * @return true if allowing all reference types
	 */
	public boolean allowsNonCallReferences() {
		return !filterReferences;
	}

	public boolean allowsThunks() {
		return !filterThunks;
	}

	public boolean showNamespace() {
		return showNamespace;
	}

	public CallTreeOptions withRecurseDepth(int depth) {
		CallTreeOptions copy = copy();
		copy.recurseDepth = depth;
		return copy;
	}

	public CallTreeOptions withFilterDuplicates(boolean filter) {
		CallTreeOptions copy = copy();
		copy.filterDuplicates = filter;
		return copy;
	}

	public CallTreeOptions withFilterReferences(boolean filter) {
		CallTreeOptions copy = copy();
		copy.filterReferences = filter;
		return copy;
	}

	public CallTreeOptions withFilterThunks(boolean filter) {
		CallTreeOptions copy = copy();
		copy.filterThunks = filter;
		return copy;
	}

	public CallTreeOptions withShowNamespace(boolean show) {
		CallTreeOptions copy = copy();
		copy.showNamespace = show;
		return copy;
	}
}
