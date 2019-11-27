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
package ghidra.app.plugin.core.datamgr.tree;

/**
 * Class to maintain the state of whether or not the Data Type Manager Tree is showing
 * pointers and/or arrays.  
 * 
 * Note: Not sure if this needs to be synchronized or not.  The set methods are called
 * from the awt thread, but the getter methods are often called by a background worker
 * thread. The theory is that we don't need to synchronize this because if the state
 * of this object changes, the tree will later be rebuilt in a follow-up task.
 */
public class ArrayPointerFilterState {
	private boolean filterArrays;
	private boolean filterPointers;

	/**
	 * Returns true if the tree should NOT show arrays
	 * @return  true if the tree should NOT show arrays
	 */
	public boolean filterArrays() {
		return filterArrays;
	}

	/**
	 * Sets whether the tree should show arrays.
	 * @param filterArrays if true the tree will NOT show arrays.
	 */
	public void setFilterArrays(boolean filterArrays) {
		this.filterArrays = filterArrays;
	}

	/**
	 * Returns true if the tree should NOT show pointers
	 * @return  true if the tree should NOT show pointers
	 */
	public boolean filterPointers() {
		return filterPointers;
	}

	/**
	 * Sets whether the tree should show pointers.
	 * @param filterPointers if true the tree will NOT show pointers.
	 */
	public void setFilterPointers(boolean filterPointers) {
		this.filterPointers = filterPointers;
	}

}
