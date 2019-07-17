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

import java.awt.Dimension;
import java.awt.Rectangle;
import java.beans.PropertyChangeListener;
import java.util.List;

import javax.swing.*;

import ghidra.framework.options.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.MiddleLayout;

/**
 * Panel that shows each property in an Options category or a Group in an Options category
 */
public class ScrollableOptionsEditor extends JScrollPane implements OptionsEditor {

	private OptionsEditorPanel optionsPanel;

	/**
	 * Creates a panel for editing the given options
	 * 
	 * @param title The title of the options panel
	 * @param options the options for this panel
	 * @param optionNames the names of the options for this panel
	 * @param editorStateFactory the factory needed by the editor 
	 */
	public ScrollableOptionsEditor(String title, Options options, List<String> optionNames,
			EditorStateFactory editorStateFactory) {

		optionsPanel = new OptionsEditorPanel(title, options, optionNames, editorStateFactory);

		setHorizontalScrollBarPolicy(HORIZONTAL_SCROLLBAR_AS_NEEDED);
		setVerticalScrollBarPolicy(VERTICAL_SCROLLBAR_AS_NEEDED);

		// the outer panel is 'Scrollable' and uses a layout that centers the options panel
		JPanel outerPanel = new ScollableOptionsPanel();
		outerPanel.add(optionsPanel);
		setViewportView(outerPanel);
	}

//==================================================================================================
// OptionsEditor Interface Methods
//==================================================================================================

	@Override
	public void dispose() {
		// stub
	}

	@Override
	public void apply() throws InvalidInputException {
		optionsPanel.apply();
	}

	@Override
	public void cancel() {
		// nothing to do
	}

	@Override
	public void reload() {
		// nothing to do, as this component is reloaded when options are changed
	}

	@Override
	public JComponent getEditorComponent(Options options, EditorStateFactory factory) {
		return this;
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		optionsPanel.setOptionsPropertyChangeListener(listener);
	}

//==================================================================================================
// Scrollable Interface Methods
//==================================================================================================

	private class ScollableOptionsPanel extends JPanel implements Scrollable {

		ScollableOptionsPanel() {
			super(new MiddleLayout());
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			return getPreferredSize();
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return visibleRect.height;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {

			//
			// This method tells the viewport whether this panel should be expanded to fit the
			// size of the viewport.  We wish to do this when the viewport is larger than us.
			// When it is smaller than us, we want to use our size, which will then trigger 
			// scrollbars.
			//			
			Dimension mySize = getPreferredSize();
			Dimension viewSize = ScrollableOptionsEditor.this.getViewport().getSize();
			boolean viewIsLarger = viewSize.height > mySize.height;
			return viewIsLarger;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {

			//
			// This method tells the viewport whether this panel should be expanded to fit the
			// size of the viewport.  We wish to do this when the viewport is larger than us.
			// When it is smaller than us, we want to use our size, which will then trigger 
			// scrollbars.
			//			
			Dimension mySize = getPreferredSize();
			Dimension viewSize = ScrollableOptionsEditor.this.getViewport().getSize();
			boolean viewIsLarger = viewSize.width > mySize.width;
			return viewIsLarger;
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}
	}

}
