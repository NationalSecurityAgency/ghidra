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
package ghidra.app.plugin.core.debug.gui.action;

import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.utils.MiscellaneousUtils;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

public interface AutoReadMemorySpec extends ExtensionPoint {
	class Private {
		private final Map<String, AutoReadMemorySpec> specsByName = new TreeMap<>();
		private final ChangeListener classListener = this::classesChanged;

		private Private() {
			ClassSearcher.addChangeListener(classListener);
		}

		private synchronized void classesChanged(ChangeEvent evt) {
			MiscellaneousUtils.collectUniqueInstances(AutoReadMemorySpec.class, specsByName,
				AutoReadMemorySpec::getConfigName);
		}
	}

	Private PRIVATE = new Private();

	public static class AutoReadMemorySpecConfigFieldCodec
			implements ConfigFieldCodec<AutoReadMemorySpec> {
		@Override
		public AutoReadMemorySpec read(SaveState state, String name,
				AutoReadMemorySpec current) {
			String specName = state.getString(name, null);
			return fromConfigName(specName);
		}

		@Override
		public void write(SaveState state, String name, AutoReadMemorySpec value) {
			state.putString(name, value.getConfigName());
		}
	}

	static AutoReadMemorySpec fromConfigName(String name) {
		synchronized (PRIVATE) {
			return PRIVATE.specsByName.get(name);
		}
	}

	static Map<String, AutoReadMemorySpec> allSpecs() {
		synchronized (PRIVATE) {
			return Map.copyOf(PRIVATE.specsByName);
		}
	}

	String getConfigName();

	String getMenuName();

	Icon getMenuIcon();

	/**
	 * Perform the automatic read, if applicable
	 * 
	 * <p>
	 * Note, the implementation should perform all the error handling. The returned future is for
	 * follow-up purposes only, and should always complete normally.
	 * 
	 * @param tool the tool containing the provider
	 * @param coordinates the provider's current coordinates
	 * @param visible the provider's visible addresses
	 * @return a future that completes when the memory has been read
	 */
	CompletableFuture<?> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible);
}
