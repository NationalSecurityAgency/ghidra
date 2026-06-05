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

import java.awt.Component;
import java.awt.Dimension;

import ghidra.framework.options.EditorState;
import ghidra.util.layout.HorizontalLayout;

/**
 * A custom OptionComponent that controls it's own display using the editor component of the
 * given EditorState.
 */
public class CustomOptionComponent extends GenericOptionsComponent {

	private Component editorComponent;

	protected CustomOptionComponent(EditorState editorState) {

		// this layout allows us to easily left-align the single component in this container
		setLayout(new HorizontalLayout(0));

		// this class is designed to let the editor component handle the display and editing
		editorComponent = editorState.getEditorComponent();
		add(editorComponent);
	}

	@Override
	protected Dimension getPreferredAlignmentSize() {
		if (editorComponent instanceof OptionsEditorAlignable alignable) {
			return alignable.getPreferredAlignmentSize();
		}
		return new Dimension(0, 0);
	}

	@Override
	protected void setPreferredAlignmentSize(Dimension dimension) {
		if (editorComponent instanceof OptionsEditorAlignable alignable) {
			alignable.setPreferredAlignmentSize(dimension);
			return;
		}

		super.setPreferredAlignmentSize(dimension);
	}
}
