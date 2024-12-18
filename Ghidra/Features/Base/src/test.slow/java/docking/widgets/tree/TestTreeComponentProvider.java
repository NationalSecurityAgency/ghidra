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
package docking.widgets.tree;

import javax.swing.JComponent;

import docking.*;

class TestTreeComponentProvider extends ComponentProvider {

	private GTree gTree;

	public TestTreeComponentProvider(Tool tool, GTree gTree) {
		super(tool, "Test", "Test");
		this.gTree = gTree;
		setDefaultWindowPosition(WindowPosition.STACK);
		setTabText("Test");
	}

	@Override
	public JComponent getComponent() {
		return gTree;
	}

	@Override
	public String getTitle() {
		return "Test Tree";
	}
}
