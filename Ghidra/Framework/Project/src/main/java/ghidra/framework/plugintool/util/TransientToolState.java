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
package ghidra.framework.plugintool.util;

import ghidra.framework.plugintool.Plugin;

import java.util.*;

public class TransientToolState {
	private List<PluginState> states;
	/**
	 * Construct a TransientPluginState
	 * @param plugins array of plugins to get transient state for
	 */
	public TransientToolState(List<Plugin> plugins) {
		states = new ArrayList<PluginState>();
		Iterator<Plugin> it = plugins.iterator();
		while(it.hasNext()) {
			Plugin plugin = it.next();
			Object state = plugin.getTransientState();
			if (state != null) {
				states.add(new PluginState(plugin, state));
			}
		}
    }
    /**
     * Restore the tool's state.
     */
	public void restoreTool() {
		Iterator<PluginState> it = states.iterator();
		while(it.hasNext()) {
			PluginState ps = it.next();
			ps.restore();
		}
	}
	
	private static class PluginState {
		private Plugin plugin;
		private Object state;
		PluginState(Plugin p, Object state) {
			this.plugin = p;
			this.state = state;
		}
		void restore() {
			if (!plugin.isDisposed()) {
				plugin.restoreTransientState(state);
			}
		}
	}
}
