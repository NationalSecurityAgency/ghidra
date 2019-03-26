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
package ghidra.app.merge;

import ghidra.util.task.TaskMonitor;

/**
 * Interface for resolving domain object merge conflicts.
 */
public interface MergeResolver {

	/**
	 * Get the name of this MergeResolver.
	 */
	public String getName();

	/**
	 * Get the description of what this MergeResolver does.
	 */
	public String getDescription();	

	/**
	 * Notification that the apply button was hit.
	 *
	 */
	public void apply();
	 
	/**
	 * Notification that the merge process was canceled.
	 *
	 */
	public void cancel();
	
	/**
	 * Perform the merge process.
	 * @param monitor monitor that allows the user to cancel the merge
	 * operation
	 * @throws Exception if the merge encounters an error and the merge process
	 * should not continue.
	 */
	public void merge(TaskMonitor monitor) throws Exception;

	/**
	 * Gets identifiers for the merge phases handled by this MergeResolver.
	 * If the merge has no sub-phases then return an array with a single string array. 
	 * Each inner String array indicates a path for a single merge phase.
	 * Each outer array element represents a phase whose progress we wish to indicate.
	 * <br>Examples:
	 * <br>So for a simple phase which has no sub-phases return 
	 * <code>
	 * new String[][] {new String[] {"Phase A"}}
	 * </code>
	 * <br>So for a phase with 2 sub-phases return 
	 * <code>
	 * new String[][] { new String[] {"Phase A"}, 
	 *                  new String[] {"Phase A", "Sub-Phase 1},
	 *                  new String[] {"Phase A", "Sub-Phase 2} }
	 * </code>.
	 * @return an array of phases.
	 */
	public String[][] getPhases();
}
