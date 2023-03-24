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
import ghidra.async.AsyncUtils;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.*;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.guest.TracePlatform;

public abstract class DebuggerGoToTrait {
	/**
	 * @see DebuggerGoToTrait#goTo(String, String)
	 */
	public record GoToResult(Address address, Boolean success) {
	}

	protected DockingAction action;

	protected final PluginTool tool;
	protected final Plugin plugin;
	protected final ComponentProvider provider;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	public DebuggerGoToTrait(PluginTool tool, Plugin plugin, ComponentProvider provider) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;
	}

	protected abstract GoToInput getDefaultInput();

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
		DebuggerGoToDialog goToDialog = new DebuggerGoToDialog(this);
		TracePlatform platform = current.getPlatform();
		goToDialog.show((SleighLanguage) platform.getLanguage(), getDefaultInput());
	}

	/**
	 * Go to the given address
	 * 
	 * <p>
	 * If parsing or evaluation fails, an exception is thrown, or the future completes
	 * exceptionally. If the address is successfully computed, then a result will be returned. The
	 * {@link GoToResult#address()} method gives the parsed or computed address. The
	 * {@link GoToResult#success()} method indicates whether the cursor was successfully set to that
	 * address.
	 * 
	 * @param spaceName the name of the address space
	 * @param offset a simple offset or Sleigh expression
	 * @return the result
	 */
	public CompletableFuture<GoToResult> goTo(String spaceName, String offset) {
		TracePlatform platform = current.getPlatform();
		Language language = platform.getLanguage();
		AddressSpace space = language.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			throw new IllegalArgumentException("No such address space: " + spaceName);
		}
		try {
			Address address = space.getAddress(offset);
			if (address == null) {
				address = language.getAddressFactory().getAddress(offset);
			}
			if (address != null) {
				return CompletableFuture
						.completedFuture(new GoToResult(address, goToAddress(address)));
			}
		}
		catch (AddressFormatException e) {
			// Fall-through to try Sleigh
		}
		return goToSleigh(spaceName, offset);
	}

	protected CompletableFuture<GoToResult> goToSleigh(String spaceName, String expression) {
		TracePlatform platform = current.getPlatform();
		Language language = platform.getLanguage();
		if (!(language instanceof SleighLanguage)) {
			throw new IllegalStateException("Current trace does not use Sleigh");
		}
		AddressSpace space = language.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			throw new IllegalArgumentException("No such address space: " + spaceName);
		}
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, current, expression);
		return goToSleigh(platform, space, expr);
	}

	protected CompletableFuture<GoToResult> goToSleigh(TracePlatform platform, AddressSpace space,
			PcodeExpression expression) {
		PcodeExecutor<byte[]> executor = DebuggerPcodeUtils.executorForCoordinates(tool, current);
		CompletableFuture<byte[]> result =
			CompletableFuture.supplyAsync(() -> expression.evaluate(executor));
		return result.thenApplyAsync(offset -> {
			Address address = space.getAddress(
				Utils.bytesToLong(offset, offset.length, expression.getLanguage().isBigEndian()));
			return new GoToResult(address, goToAddress(platform.mapGuestToHost(address)));
		}, AsyncUtils.SWING_EXECUTOR);
	}
}
