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
package generic.concurrent;

/** 
 * Callback for when items have completed processing.  It is also called if an item is cancelled
 * or had an error condition.
 *
 * @param <I> The type for the items being processed.
 * @param <R> The type for result object returned from the QWorkers process method.
 */
public interface QItemListener<I, R> {

	/**
	 * Callback for when a item has completed processing, regardless of whether or not the item
	 * process normally, was cancelled, or encountered an error during processing.
	 * @param result the QResult object.
	 */
	public void itemProcessed(QResult<I, R> result);

}
