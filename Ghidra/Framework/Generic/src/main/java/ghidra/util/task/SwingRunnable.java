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
package ghidra.util.task;

/**
*
* Runnable that has a method that may need to be run in the Swing AWT thread. 
* Pass a SwingRunnable to the RunManager if follow on work needs to be done
* after the <code>run()</code> method completes.
* 
* @see RunManager#runNext(MonitoredRunnable, String)
* @see RunManager#runNext(MonitoredRunnable, String, int)
*  
*/

public interface SwingRunnable extends MonitoredRunnable {

	/**
	 * Callback on the swing thread.
	 */
	public void swingRun(boolean isCancelled);

}
