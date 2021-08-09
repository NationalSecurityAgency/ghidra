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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.border.Border;

import docking.help.Help;
import docking.help.HelpService;
import ghidra.framework.options.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;

/**
 *
 * Panel that shows each property in an Options category or a Group in an
 * Options category.
 */
public class OptionsEditorPanel extends JPanel {

	private EditorStateFactory editorStateFactory;
	private Options options;
	private List<String> optionNames;
	private PropertyChangeListener propertyChangeListener;
	private List<EditorState> editorInfoList;
	private PropertyChangeListener editorPropertyChangeListener =
		new EditorPropertyChangeListener();
	private final String title;

	/**
	 * Creates a panel for editing the given options.
	 * @param title The title of the options panel
	 * @param options The options to display
	 * @param optionNames The list of option names
	 * @param editorStateFactory The EditorStateFactory
	 */
	public OptionsEditorPanel(String title, Options options, List<String> optionNames,
			EditorStateFactory editorStateFactory) {
		if (optionNames.size() == 0) {
			throw new AssertException("No editable options given for this panel.");
		}
		this.options = options;
		this.editorStateFactory = editorStateFactory;
		this.optionNames = optionNames;
		this.title = title;

		create();
	}

	public void dispose() {
		propertyChangeListener = null;
		editorInfoList.clear();
	}

	/**
	 * Create labels and areas for popping up editors.
	 */
	private void create() {
		setLayout(new VerticalLayout(4));

		editorInfoList = new ArrayList<>(optionNames.size());
		List<GenericOptionsComponent> compList = new ArrayList<>();
		createBorder();
		HelpService help = Help.getHelpService();

		for (String optionName : optionNames) {
			EditorState editorState = editorStateFactory.getEditorState(options, optionName,
				editorPropertyChangeListener);
			editorInfoList.add(editorState);

			HelpLocation helpLoc = options.getHelpLocation(optionName);

			GenericOptionsComponent component =
				GenericOptionsComponent.createOptionComponent(editorState);
			add(component);

			if (helpLoc == null) {
				help.excludeFromHelp(component);
			}
			else {
				help.registerHelp(component, helpLoc);
			}

			compList.add(component);
		}
		GenericOptionsComponent.alignLabels(compList);
	}

	private void createBorder() {
		Border emptyBorder = BorderFactory.createEmptyBorder(20, 20, 20, 20);
		Border titleBorder = BorderFactory.createTitledBorder(title);

		Border border = BorderFactory.createCompoundBorder(titleBorder, emptyBorder);
		setBorder(border);
	}

	public void apply() {
		for (EditorState state : editorInfoList) {
			state.applyValue();
		}
	}
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.propertyChangeListener = listener;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class EditorPropertyChangeListener implements PropertyChangeListener {
		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			if (checkForDifferences()) {
				if (propertyChangeListener != null) {
					propertyChangeListener.propertyChange(
						new PropertyChangeEvent(this, "apply.enabled", null, Boolean.TRUE));
				}
			}
		}

		private boolean checkForDifferences() {
			for (EditorState info : editorInfoList) {
				if (info.isValueChanged()) {
					return true;
				}
			}
			return false;
		}
	}

}
