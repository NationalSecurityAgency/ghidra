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
package docking.widgets.table.threaded;

/**
 * A listener to be notified of {@link ThreadedTableModel} loading changes.
 */
public interface ThreadedTableModelListener {

	/**
	 * Called when the model has new data to be loaded, but has not yet started the load process.
	 */
	public void loadPending();

	/**
	 * Called when the table begins to load new data.
	 */
	public void loadingStarted();

	/**
	 * Called when the table is done loading data.
	 * 
	 * @param wasCancelled true if the load was cancelled.
	 */
	public void loadingFinished(boolean wasCancelled);
}
