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
package docking.options.editor;

import java.util.*;

import javax.swing.JComponent;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.options.Options;

class OptionsRootTreeNode extends OptionsTreeNode {
	private Options[] options;

	OptionsRootTreeNode(String name, Options[] options) {
		super(name, null);
		this.options = options;

	}

	public OptionsRootTreeNode(Options options) {
		super(options);
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		if (options == null) {
			return super.generateChildren();
		}
		List<GTreeNode> list = new ArrayList<GTreeNode>();
		for (Options option : options) {
			list.add(new OptionsTreeNode(option));
		}
		Collections.sort(list);
		return list;
	}

	// overridden because the root has no options to edit
	protected JComponent getEditorComponent() {
		return null;
	}
}
