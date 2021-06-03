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

import ghidra.util.task.TaskMonitor;

/**
 * Interface that defines the callback to work on the items given to the 
 * {@link ConcurrentQ#add(Object) ConcurrentQ.add(I)} methods.  Each item that is processed will be handed to the
 * {@link #process(Object, TaskMonitor) process(I, TaskMonitor)} method of the implementing class.
 * 
 * @param <I> The type of the items to be processed.
 * @param <R> The type of objects resulting from processing an item; if you don't care about the
 *            return value, then make this value whatever you want, like <code>Object</code> or the 
 *            same value as {@link I} and return null from {@link #process(Object, TaskMonitor) process(I, TaskMonitor)}.
 */
public interface QCallback<I, R> {

	/**
	 * Processes the given item in background thread provided by a GThreadPool.
	 * @param item the item to process.
	 * @param monitor a monitor that can be used to check for cancellation and to report progress and
	 * transient messages.
	 * @return The return value resulting from processing the item.
	 */
	public R process(I item, TaskMonitor monitor) throws Exception;

}
