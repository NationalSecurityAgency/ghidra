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
package ghidra.util;

import ghidra.util.task.Task;

public interface TrackedTaskListener {

    /** 
     * A callback for when a Task is starting to be tracked.
     * @param task The task being tracked.
     */
    public void taskAdded( Task task );
    
    /**
     * A callback when a task is no longer being tracked.
     * @param task The task that is no longer tracked.
     */
    public void taskRemoved( Task task );
}
