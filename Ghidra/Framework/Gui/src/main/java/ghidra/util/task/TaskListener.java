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
package ghidra.util.task;

/**
 * Listener that is notified when a thread completes its task.
 */
public interface TaskListener {
 
	/**
	 * Notification that the task completed.
	 * @param task the task that was running and is now completed
	 */
    public void taskCompleted(Task task);
    
    /**
     * Notification that the task was canceled.
     * @param task the task that was running and was canceled
     */
    public void taskCancelled(Task task);
}
