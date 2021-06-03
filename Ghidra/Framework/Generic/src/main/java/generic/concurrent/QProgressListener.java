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
package generic.concurrent;

/**
 * Interface for listeners who want progress and transient message information from QWorkers while
 * processing items.
 */
public interface QProgressListener<I> {

	/**
	 * Notification that progress has changed during the processing of an item.
	 * @param id the id of the item being processed.  Since multiple items can be processed concurrently,
	 * the id can be used to "demultiplex" the progress and messages being generated.
	 * @param item the item that was being processed when the worker changed the max progress.
	 * @param currentProgress the current value of the progress for this task.
	 */
	void progressChanged(long id, I item, long currentProgress);

	/**
	 * Notification that a new task has been generated to process an item.
	 * @param id the id of the item being processed.
	 * @param item the item that was being processed when the worker changed the max progress.
	 */
	void taskStarted(long id, I item);

	/**
	 * Notification that a new task has completed processing for an item.
	 * @param id the id of the item that has completed processing.
	 * @param item the item that was being processed when the worker changed the max progress.
	 * @param totalCount the total number of items that have been submitted to the ConcurrentQ
	 * @param completedCount the total number of items that completed processing.
	 */
	void taskEnded(long id, I item, long totalCount, long completedCount);

	/**
	 * Notification that the progress mode has changed from/to indeterminate mode
	 * @param id the id of the item that has completed processing.
	 * @param item the item that was being processed when the worker changed the max progress.
	 * @param indeterminate
	 */
	void progressModeChanged(long id, I item, boolean indeterminate);

	/**
	 * 
	 * @param id the id of the item that has completed processing.
	 * @param item the item that was being processed when the worker changed the max progress.
	 * @param message
	 */
	void progressMessageChanged(long id, I item, String message);

	/**
	 * Notification the the max progress value has changed.
	 * @param id the id of the item that has completed processing.
	 * @param item the item that was being processed when the worker changed the max progress.
	 * @param maxProgress the max value of the progress for this task.
	 */
	void maxProgressChanged(long id, I item, long maxProgress);

}
