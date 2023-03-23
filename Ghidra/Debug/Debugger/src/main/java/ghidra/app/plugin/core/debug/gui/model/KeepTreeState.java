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
package ghidra.app.plugin.core.debug.gui.model;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeState;

public class KeepTreeState implements AutoCloseable {
	private final GTree tree;
	private final GTreeState state;

	public static KeepTreeState ifNotNull(GTree tree) {
		if (tree == null) {
			return null;
		}
		return new KeepTreeState(tree);
	}

	public KeepTreeState(GTree tree) {
		this.tree = tree;
		this.state = tree.getTreeState();
	}

	@Override
	public void close() {
		tree.restoreTreeState(state);
	}
}
