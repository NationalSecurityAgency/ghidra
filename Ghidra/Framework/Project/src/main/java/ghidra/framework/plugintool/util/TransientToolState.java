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
package ghidra.framework.plugintool.util;

import java.util.*;

import ghidra.framework.plugintool.PluginWithTransientState;
import ghidra.framework.plugintool.Plugin;

public class TransientToolState {
	private List<PluginState<?>> states;

	/**
	 * Construct a TransientPluginState
	 * 
	 * @param plugins array of plugins to get transient state for
	 */
	public TransientToolState(List<Plugin> plugins) {
		states = new ArrayList<>();
		for (Plugin plugin : plugins) {
			if (!(plugin instanceof PluginWithTransientState<?> hasState)) {
				continue;
			}
			PluginState<?> state = PluginState.gather(hasState);
			if (state == null) {
				continue;
			}
			if (state != null) {
				states.add(state);
			}
		}
	}

	/**
	 * Restore the tool's state.
	 */
	public void restoreTool() {
		Iterator<PluginState<?>> it = states.iterator();
		while (it.hasNext()) {
			PluginState<?> ps = it.next();
			ps.restore();
		}
	}

	private static class PluginState<T> {
		private PluginWithTransientState<T> plugin;
		private T state;

		PluginState(PluginWithTransientState<T> plugin, T state) {
			this.plugin = plugin;
			this.state = state;
		}

		static <T> PluginState<T> gather(PluginWithTransientState<T> plugin) {
			T state = plugin.getTransientState();
			if (state == null) {
				return null;
			}
			return new PluginState<>(plugin, state);
		}

		void restore() {
			if (!plugin.isDisposed()) {
				plugin.restoreTransientState(state);
			}
		}
	}
}
