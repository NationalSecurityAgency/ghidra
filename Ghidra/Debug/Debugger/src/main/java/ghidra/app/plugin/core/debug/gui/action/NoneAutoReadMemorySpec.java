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

import java.util.concurrent.CompletableFuture;

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;

public class NoneAutoReadMemorySpec implements AutoReadMemorySpec {
	public static final String CONFIG_NAME = "READ_NONE";

	@Override
	public String getConfigName() {
		return CONFIG_NAME;
	}

	@Override
	public String getMenuName() {
		return AutoReadMemoryAction.NAME_NONE;
	}

	@Override
	public Icon getMenuIcon() {
		return AutoReadMemoryAction.ICON_NONE;
	}

	@Override
	public CompletableFuture<Void> readMemory(PluginTool tool, DebuggerCoordinates coordinates,
			AddressSetView visible) {
		return AsyncUtils.NIL;
	}
}
