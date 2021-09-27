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

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.GoToAction;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.program.TraceProgramView;

public abstract class DebuggerGoToTrait {
	protected DockingAction action;

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected final DebuggerGoToDialog goToDialog;

	public DebuggerGoToTrait(PluginTool tool, Plugin plugin, ComponentProvider provider) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;

		goToDialog = new DebuggerGoToDialog(this);
	}

	protected abstract boolean goToAddress(Address address);

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		current = coordinates;
	}

	public DockingAction installAction() {
		action = GoToAction.builder(plugin)
				.enabledWhen(ctx -> current.getView() != null)
				.onAction(this::activatedGoTo)
				.buildAndInstallLocal(provider);
		action.setEnabled(false);
		return action;
	}

	private void activatedGoTo(ActionContext context) {
		TraceProgramView view = current.getView();
		if (view == null) {
			return;
		}
		Language language = view.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			return;
		}
		goToDialog.show((SleighLanguage) language);
	}

	public CompletableFuture<Boolean> goToSleigh(String spaceName, String expression) {
		Language language = current.getView().getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalStateException("Current trace does not use Sleigh");
		}
		SleighLanguage slang = (SleighLanguage) language;
		AddressSpace space = language.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			throw new IllegalArgumentException("No such address space: " + spaceName);
		}
		SleighExpression expr = SleighProgramCompiler.compileExpression(slang, expression);
		return goToSleigh(space, expr);
	}

	public CompletableFuture<Boolean> goToSleigh(AddressSpace space, SleighExpression expression) {
		AsyncPcodeExecutor<byte[]> executor = TracePcodeUtils.executorForCoordinates(current);
		CompletableFuture<byte[]> result = expression.evaluate(executor);
		return result.thenApply(offset -> {
			Address address = space.getAddress(
				Utils.bytesToLong(offset, offset.length, expression.getLanguage().isBigEndian()));
			return goToAddress(address);
		});
	}
}
