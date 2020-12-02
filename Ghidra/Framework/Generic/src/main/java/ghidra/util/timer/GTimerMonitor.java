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
package ghidra.util.timer;

/**
 * Monitor object returned from a GTimer.schedule() call
 */
public interface GTimerMonitor {

	/**
	 * A dummy implementation of this interface
	 */
	public static GTimerMonitor DUMMY =
		new GTimerMonitor() {

			@Override
			public boolean wasCancelled() {
				return false;
			}

			@Override
			public boolean didRun() {
				return false;
			}

			@Override
			public boolean cancel() {
				return false;
			}
		};

	/**
	 * Cancels the scheduled runnable associated with this GTimerMonitor if it has not already run.
	 * @return true if the scheduled runnable was cancelled before it had a chance to execute.
	 */
	public boolean cancel();

	/**
	 * Return true if the scheduled runnable has completed.
	 * @return true if the scheduled runnable has completed.
	 */
	public boolean didRun();

	/**
	 * Return true if the scheduled runnable was cancelled before it had a chance to run.
	 * @return true if the scheduled runnable was cancelled before it had a chance to run.
	 */
	public boolean wasCancelled();
}
