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
package ghidra.debug.api.action;

import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigFieldCodec;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;

/**
 * An interface for specifying how to automatically read target memory.
 */
public interface AutoReadMemorySpec {

	/**
	 * Codec for saving/restoring the auto-read specification
	 */
	public static class AutoReadMemorySpecConfigFieldCodec
			implements ConfigFieldCodec<AutoReadMemorySpec> {
		@Override
		public AutoReadMemorySpec read(SaveState state, String name,
				AutoReadMemorySpec current) {
			String specName = state.getString(name, null);
			return AutoReadMemorySpecFactory.fromConfigName(specName);
		}

		@Override
		public void write(SaveState state, String name, AutoReadMemorySpec value) {
			state.putString(name, value.getConfigName());
		}
	}

	/**
	 * Get the configuration name
	 * 
	 * <p>
	 * This is the value stored in configuration files to identify this specification
	 * 
	 * @return the configuration name
	 */
	String getConfigName();

	/**
	 * A human-readable name for this specification
	 * 
	 * <p>
	 * This is the text displayed in menus
	 * 
	 * @return the menu name, or null to omit from menus
	 */
	String getMenuName();

	/**
	 * Get the icon for this specification
	 * 
	 * @return the icon
	 */
	Icon getMenuIcon();

	/**
	 * Get the "effective" specification.
	 * <p>
	 * This allows a specification to defer to some other (possibly hidden) specification, depending
	 * on the coordinates.
	 * 
	 * @param coordinates the current coordinates
	 * @return the specification
	 */
	AutoReadMemorySpec getEffective(DebuggerCoordinates coordinates);

	/**
	 * Perform the automatic read, if applicable
	 * 
	 * <p>
	 * Note, the implementation should perform all the error handling. The returned future is for
	 * follow-up purposes only, and should always complete normally. It should complete with true if
	 * any memory was actually loaded. Otherwise, it should complete with false.
	 * 
	 * <p>
	 * <b>NOTE:</b> This returns the future, rather than being synchronous, because not all specs
	 * will actually need to create a background task. If this were synchronous, the caller would
	 * have to invoke it from a background thread, requiring it to create that thread whether or not
	 * this method actually does anything.
	 * 
	 * @param tool the tool containing the provider
	 * @param coordinates the provider's current coordinates
	 * @param visible the provider's visible addresses
	 * @return a future that completes when the memory has been read
	 */
	CompletableFuture<Boolean> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible);
}
