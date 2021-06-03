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
package ghidra.app.merge;

public interface MergeProgressModifier {

	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param progressMessage a message indicating what is currently occurring in this phase.
	 * Null indicates to use the default message.
	 */
	public void updateProgress(final String progressMessage);
	
	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param currentProgressPercentage the progress percentage completed for the current phase.
	 * This should be a value from 0 to 100.
	 */
	public void updateProgress(final int currentProgressPercentage);
	
	/**
	 * Updates the current phase progress area in the default merge panel.
	 * @param currentProgressPercentage the progress percentage completed for the current phase.
	 * This should be a value from 0 to 100.
	 * @param progressMessage a message indicating what is currently occurring in this phase.
	 */
	public void updateProgress(final int currentProgressPercentage, final String progressMessage);
	
	/**
	 * The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase begins.
	 * The string array should match one that the returned by MergeResolver.getPhases().
	 * @param mergePhase identifier for the merge phase to change to in progress status.
	 * @see MergeResolver
	 */
	public void setInProgress(String[] mergePhase);
	
	/**
	 * The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase completes.
	 * The string array should match one that the returned by MergeResolver.getPhases().
	 * @param mergePhase identifier for the merge phase to change to completed status.
	 * @see MergeResolver
	 */
	public void setCompleted(String[] mergePhase);

}
