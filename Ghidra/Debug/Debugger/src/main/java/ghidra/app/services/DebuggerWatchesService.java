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
package ghidra.app.services;

import java.util.Collection;

import ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesPlugin;
import ghidra.app.plugin.core.debug.gui.watch.WatchRow;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * A service interface for controlling the Watches window
 */
@ServiceInfo(
	defaultProvider = DebuggerWatchesPlugin.class,
	description = "Service for managing watches")
public interface DebuggerWatchesService {
	/**
	 * Add a watch
	 * 
	 * @param expression the Sleigh expression
	 * @return the new row
	 */
	WatchRow addWatch(String expression);

	/**
	 * Remove a watch
	 * 
	 * @param watch the row to remove
	 */
	void removeWatch(WatchRow watch);

	/**
	 * Get the current watches
	 * 
	 * @return the unmodifiable collection of watches
	 */
	Collection<WatchRow> getWatches();
}
