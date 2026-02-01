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
package ghidra.app.util.importer;

import java.awt.Component;

import javax.swing.JButton;

import docking.DockingWindowManager;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.LibraryPathsDialog;

/**
 * A dummy {@link Option} used to render a button that will allow the user to edit the global
 * list of library search paths
 */
public class LibrarySearchPathDummyOption extends Option {

	/**
	 * Creates a new {@link LibrarySearchPathDummyOption}
	 * 
	 * @param name The name of the option
	 */
	public LibrarySearchPathDummyOption(String name) {
		super(name, null);
	}

	@Override
	public Component getCustomEditorComponent() {
		JButton button = new JButton("Edit Paths");
		button.addActionListener(e -> {
			DockingWindowManager.showDialog(null, new LibraryPathsDialog());
		});
		return button;
	}

	@Override
	public Class<?> getValueClass() {
		return Object.class;
	}

	@Override
	public Option copy() {
		return new LibrarySearchPathDummyOption(getName());
	}
}
