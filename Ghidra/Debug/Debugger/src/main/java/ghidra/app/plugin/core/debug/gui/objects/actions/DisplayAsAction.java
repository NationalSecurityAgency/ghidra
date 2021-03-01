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

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.async.AsyncFence;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;

public abstract class DisplayAsAction extends DockingAction {

	protected PluginTool tool;
	protected DebuggerObjectsProvider provider;
	protected boolean isTree = false;

	public DisplayAsAction(String name, PluginTool tool, String owner,
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
			doAction(container);
		}
	}

	protected abstract void doAction(ObjectContainer container);

	protected CompletableFuture<Void> getOffspring(ObjectContainer container) {
		AtomicReference<Map<String, ? extends TargetObject>> elements = new AtomicReference<>();
		AtomicReference<Map<String, ?>> attributes = new AtomicReference<>();
		return sequence(TypeSpec.VOID).then(seq -> {
			AsyncFence fence = new AsyncFence();
			TargetObject to = container.getTargetObject();
			fence.include(to.fetchElements()
					.thenAccept(elements::set));
			fence.include(to.fetchAttributes()
					.thenAccept(attributes::set));
			fence.ready().handle(seq::next);
		}).then(seq -> {
			container.rebuildContainers(elements.get(), attributes.get());
			finishGetOffspring(container);
			seq.exit();
		}).finish();
	}

	protected void finishGetOffspring(ObjectContainer container) {
		SwingUtilities.invokeLater(() -> {
			try {
				DebuggerObjectsProvider p = new DebuggerObjectsProvider(provider.getPlugin(),
					provider.getModel(), container, isTree);
				container.propagateProvider(p);
				p.update(container);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		});
	}

}
