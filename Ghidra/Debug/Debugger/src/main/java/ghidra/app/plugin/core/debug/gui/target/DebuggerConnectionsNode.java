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
package ghidra.app.plugin.core.debug.gui.target;

import java.util.*;

import docking.widgets.tree.SearchableByObjectGTreeNode;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractDebuggerConnectionsNode;
import ghidra.app.services.DebuggerModelService;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.util.Swing;
import ghidra.util.datastruct.CollectionChangeListener;

public class DebuggerConnectionsNode extends AbstractDebuggerConnectionsNode
		implements SearchableByObjectGTreeNode {

	protected class ModelsChangedListener implements CollectionChangeListener<DebuggerObjectModel> {
		@Override
		public void elementAdded(DebuggerObjectModel element) {
			DebuggerModelNode node;
			synchronized (models) {
				if (models.containsKey(element)) {
					return;
				}
				node = new DebuggerModelNode(element, provider);
				models.put(element, node);
			}
			Swing.runIfSwingOrRunLater(() -> {
				addNode(node);
				expand();
			});
		}

		@Override
		public void elementModified(DebuggerObjectModel element) {
			fireNodeChanged(DebuggerConnectionsNode.this, models.get(element));
		}

		@Override
		public void elementRemoved(DebuggerObjectModel element) {
			DebuggerModelNode node;
			synchronized (models) {
				node = models.remove(element);
				if (node == null) {
					return;
				}
			}
			Swing.runIfSwingOrRunLater(() -> {
				removeNode(node);
			});
		}
	}

	private final DebuggerModelService service;
	private final DebuggerTargetsProvider provider;

	private final Map<DebuggerObjectModel, DebuggerModelNode> models = new HashMap<>();
	private final ModelsChangedListener modelsChangedListener = new ModelsChangedListener();

	public DebuggerConnectionsNode(DebuggerModelService service,
			DebuggerTargetsProvider provider) {
		this.service = service;
		this.provider = provider;
		if (service == null) {
			return;
		}
		service.addModelsChangedListener(modelsChangedListener);
		Set<DebuggerModelNode> toAdd = new LinkedHashSet<>();
		synchronized (models) {
			Set<DebuggerObjectModel> current = service.getModels();
			for (DebuggerObjectModel element : current) {
				DebuggerModelNode node = new DebuggerModelNode(element, provider);
				models.put(element, node);
				toAdd.add(node);
			}
		}
		for (DebuggerModelNode node : toAdd) {
			addNode(node);
		}
	}

	@Override
	public void dispose() {
		service.removeModelsChangedListener(modelsChangedListener);
		super.dispose();
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	public DebuggerModelService getTargetService() {
		return service;
	}

	@Override
	public Map<? extends Object, ? extends DebuggerModelNode> getObjectNodeMap() {
		return models;
	}
}
