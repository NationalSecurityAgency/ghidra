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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import static ghidra.async.AsyncUtils.sequence;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.services.ConsoleService;
import ghidra.async.AsyncFence;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class DisplayMethodsAction extends DockingAction {
	private static final String GROUP = null; // TODO: What group?

	private PluginTool tool;
	protected DebuggerObjectsProvider provider;
	private ConsoleService consoleService;

	public DisplayMethodsAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("DisplayMethods", owner);
		this.tool = tool;
		this.provider = provider;

		String[] path = new String[] { "Display methods" };
		setPopupMenuData(new MenuData(path, GROUP));
		setHelpLocation(new HelpLocation(owner, "display_methods"));
		provider.addLocalAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object obj = context.getContextObject();
		ObjectContainer sel = provider.getSelectedContainer(obj);
		return sel != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Object contextObject = context.getContextObject();
		ObjectContainer container = provider.getSelectedContainer(contextObject);
		if (container != null) {
			doAction(container);
		}
	}

	protected void doAction(ObjectContainer container) {
		consoleService = provider.getConsoleService();
		if (consoleService == null) {
			Msg.showError(this, tool.getToolFrame(), "DisplayMethods Error",
				"ConsoleService not found: Please add a console service provider to your tool");
			return;
		}
		ObjectContainer clone = ObjectContainer.clone(container);
		getAttributes(clone);
	}

	private CompletableFuture<Void> getAttributes(ObjectContainer container) {
		AtomicReference<Map<String, ?>> attributes = new AtomicReference<>();
		return sequence(TypeSpec.VOID).then(seq -> {
			AsyncFence fence = new AsyncFence();
			TargetObject to = container.getTargetObject();
			fence.include(to.fetchAttributes().thenAccept(attributes::set));
			fence.ready().handle(seq::next);
		}).then(seq -> {
			finishGetAttributes(container, attributes);
			seq.exit();
		}).finish();
	}

	protected void finishGetAttributes(ObjectContainer container,
			AtomicReference<Map<String, ?>> methods) {
		consoleService.println("Methods for " + container.getTargetObject().getName() + ":");
		Map<String, ?> map = methods.get();
		for (String key : map.keySet()) {
			Object object = map.get(key);
			if (object instanceof TargetObject) {
				TargetObject to = (TargetObject) object;
				if (to instanceof TargetMethod) {
					consoleService.println(key);
				}
			}
		}
	}

}
