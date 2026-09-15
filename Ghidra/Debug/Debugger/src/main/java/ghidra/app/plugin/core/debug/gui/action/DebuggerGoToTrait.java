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
import ghidra.app.plugin.core.debug.gui.DebuggerResources.GoToAction;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.action.GoToInput;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.SleighUtils.LitIdMode;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.*;
import ghidra.trace.model.guest.TracePlatform;

public abstract class DebuggerGoToTrait {
	/**
	 * The result of a Go-To call.
	 * 
	 * @see DebuggerGoToTrait#goTo(String, String, LitIdMode)
	 * @param address the target address, perhaps computed
	 * @param success whether or not it was successful
	 */
	public record GoToResult(Address address, Boolean success) {}

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

	protected abstract Address getCurrentAddress();

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
		goToDialog.show(platform.getAddressFactory(), getDefaultInput());
	}

	protected String adjustOffset(String offset) {
		offset = offset.strip();
		if (offset.startsWith("+")) {
			return ".+(%s)".formatted(offset.substring(1));
		}
		if (offset.startsWith("-")) {
			return ".-(%s)".formatted(offset.substring(1));
		}
		return offset;
	}

	protected Address tryAddress(AddressFactory factory, String spaceName, String offset) {
		AddressSpace space = factory.getAddressSpace(spaceName);
		if (space == null) {
			throw new IllegalArgumentException("No such address space: " + spaceName);
		}

		try {
			Address address = space.getAddress(offset);
			if (address == null) {
				address = factory.getAddress(offset);
			}
			return address;
		}
		catch (AddressFormatException e) {
			return null;
		}
	}

	public void validate(AddressFactory factory, String spaceName, String offset, LitIdMode mode) {
		offset = adjustOffset(offset);
		/**
		 * NOTE: Even though the SleighParser can how handle bare addresses, we still want to
		 * support the case where the user types (or quickly pastes) an address with an explicit
		 * space given.
		 */
		Address address = tryAddress(factory, spaceName, offset);
		if (address != null) {
			return;
		}
		SleighUtils.parseSleighExpression(offset, mode);
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
	 * @param mode the mode for parsing integer literals and ids
	 * @return the result
	 */
	public CompletableFuture<GoToResult> goTo(String spaceName, String offset, LitIdMode mode) {
		TracePlatform platform = current.getPlatform();
		offset = adjustOffset(offset);

		Address address = tryAddress(platform.getAddressFactory(), spaceName, offset);
		if (address != null) {
			return CompletableFuture
					.completedFuture(new GoToResult(address, goToAddress(address)));
		}
		return goToSleigh(spaceName, offset, mode);
	}

	protected CompletableFuture<GoToResult> goToSleigh(String spaceName, String expression,
			LitIdMode mode) {
		TracePlatform platform = current.getPlatform();
		if (!(platform.getLanguage() instanceof SleighLanguage)) {
			throw new IllegalStateException("Current trace does not use Sleigh");
		}
		AddressSpace space = platform.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			throw new IllegalArgumentException("No such address space: " + spaceName);
		}
		PcodeExpression expr = DebuggerPcodeUtils.compileExpression(tool, current,
			getCurrentAddress(), expression, mode);
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
