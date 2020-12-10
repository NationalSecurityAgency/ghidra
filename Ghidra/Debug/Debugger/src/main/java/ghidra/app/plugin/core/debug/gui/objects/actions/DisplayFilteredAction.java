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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.script.AskDialog;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;

public abstract class DisplayFilteredAction extends DockingAction {

	protected PluginTool tool;
	protected DebuggerObjectsProvider provider;
	protected boolean isTree = false;
	private String lastCmd;

	public DisplayFilteredAction(String name, PluginTool tool, String owner,
			DebuggerObjectsProvider provider) {
		super(name, owner);
		this.tool = tool;
		this.provider = provider;
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
			AskDialog<String> dialog =
				new AskDialog<String>("Filter", "Filter", AskDialog.STRING, lastCmd);
			if (dialog.isCanceled()) {
				return;
			}

			lastCmd = dialog.getValueAsString();
			List<String> path = new ArrayList<>();
			path.addAll(container.getTargetObject().getPath());
			path.add(lastCmd);

			doAction(container, path);
		}
	}

	protected abstract void doAction(ObjectContainer container, List<String> path);

	protected CompletableFuture<Void> getOffspring(ObjectContainer container,
			final List<String> path) {
		TargetObject to = container.getTargetObject();
		DebuggerObjectModel model = to.getModel();
		model.fetchModelObject(path, true).thenAccept(obj -> {
			container.setTargetObject(obj);
			finishGetOffspring(container, path);
		});
		return CompletableFuture.completedFuture(null);
	}

	protected void finishGetOffspring(ObjectContainer container, final List<String> path) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				try {
					DebuggerObjectsProvider p = new DebuggerObjectsProvider(provider.getPlugin(),
						provider.getModel(), container, isTree);
					container.propagateProvider(p);
					p.update(container);
				}
				catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}
