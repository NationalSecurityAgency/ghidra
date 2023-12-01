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
package ghidra.debug.api.progress;

public interface ProgressListener {
	enum Disposal {
		/**
		 * The monitor was properly closed
		 */
		CLOSED,
		/**
		 * The monitor was <em>not</em> closed. Instead, it was cleaned by the garbage collector.
		 */
		CLEANED;
	}

	void monitorCreated(MonitorReceiver monitor);

	void monitorDisposed(MonitorReceiver monitor, Disposal disposal);

	void messageUpdated(MonitorReceiver monitor, String message);

	void progressUpdated(MonitorReceiver monitor, long progress);

	/**
	 * Some other attribute has been updated
	 * 
	 * <ul>
	 * <li>cancelled</li>
	 * <li>cancel enabled</li>
	 * <li>indeterminate</li>
	 * <li>maximum</li>
	 * <li>show progress value in percent string</li>
	 * </ul>
	 * 
	 * @param monitor the monitor
	 */
	void attributeUpdated(MonitorReceiver monitor);
}
