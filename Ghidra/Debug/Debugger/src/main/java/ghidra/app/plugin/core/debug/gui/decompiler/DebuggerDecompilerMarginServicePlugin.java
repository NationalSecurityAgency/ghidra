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
package ghidra.app.plugin.core.debug.gui.decompiler;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.DecompilerMarginService;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Swing;

@PluginInfo(
	shortDescription = "Debugger icon margin in the Decompiler",
	description = "Displays the icons of Debugger plugins, e.g., breakpoints and the tracked " +
		"location, in a single margin of the Decompiler",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	servicesProvided = {
		DebuggerDecompilerMarginService.class,
	})
public class DebuggerDecompilerMarginServicePlugin extends Plugin
		implements DebuggerDecompilerMarginService {

	// package access for testing
	final DebuggerDecompilerIconMarginProvider marginProvider;
	final List<DecompilerMarginIconSource> sources = new CopyOnWriteArrayList<>();

	// @AutoServiceConsumed via method
	DecompilerMarginService decompilerMarginService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	public DebuggerDecompilerMarginServicePlugin(PluginTool tool) {
		super(tool);
		this.marginProvider = new DebuggerDecompilerIconMarginProvider(this);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);
	}

	@Override
	protected void dispose() {
		setDecompilerMarginService(null);
		super.dispose();
	}

	@AutoServiceConsumed
	private void setDecompilerMarginService(DecompilerMarginService decompilerMarginService) {
		if (this.decompilerMarginService != null) {
			this.decompilerMarginService.removeMarginProvider(marginProvider);
		}
		this.decompilerMarginService = decompilerMarginService;
		if (this.decompilerMarginService != null) {
			this.decompilerMarginService.addMarginProvider(marginProvider);
		}
	}

	@Override
	public void addIconSource(DecompilerMarginIconSource source) {
		sources.add(source);
		iconsChanged();
	}

	@Override
	public void removeIconSource(DecompilerMarginIconSource source) {
		sources.remove(source);
		iconsChanged();
	}

	@Override
	public void iconsChanged() {
		Swing.runIfSwingOrRunLater(marginProvider::repaint);
	}

	List<ClangLine> getLines() {
		if (decompilerMarginService == null) {
			return List.of();
		}
		return decompilerMarginService.getDecompilerPanel().getLines();
	}
}
