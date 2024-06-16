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
package ghidra.app.plugin.core.debug.gui.console;

import java.util.Objects;

import docking.DefaultActionContext;
import ghidra.debug.api.progress.MonitorReceiver;

public class MonitorRowConsoleActionContext extends DefaultActionContext {
	private MonitorReceiver monitor;

	public MonitorRowConsoleActionContext(MonitorReceiver monitor) {
		this.monitor = monitor;
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(monitor);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof MonitorRowConsoleActionContext that)) {
			return false;
		}
		if (!Objects.equals(this.monitor, that.monitor)) {
			return false;
		}
		return true;
	}

	public MonitorReceiver getMonitor() {
		return monitor;
	}
}
