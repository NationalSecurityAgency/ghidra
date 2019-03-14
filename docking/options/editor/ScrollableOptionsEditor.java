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
 *
 * Panel that shows each property in an Options category or a Group in an
 * Options category.
 */
public class ScrollableOptionsEditor extends JScrollPane implements OptionsEditor, Scrollable {

	private OptionsEditorPanel optionsPanel;

	/**
	 * Creates a panel for editing the given options.
	 * @param title The title of the options panel
	 * @param optionsList The list of options to display
	 */
	public ScrollableOptionsEditor(String title, Options options, List<String> optionNames,
			EditorStateFactory editorStateFactory) {

		optionsPanel = new OptionsEditorPanel(title, options, optionNames, editorStateFactory);

		setHorizontalScrollBarPolicy(HORIZONTAL_SCROLLBAR_AS_NEEDED);
		setVerticalScrollBarPolicy(VERTICAL_SCROLLBAR_AS_NEEDED);

		JPanel outerPanel = new JPanel(new MiddleLayout());
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

	/**
	 * @throws InvalidInputException 
	 * @see ghidra.framework.options.OptionsEditor#apply()
	 */
	@Override
	public void apply() throws InvalidInputException {
		optionsPanel.apply();
	}

	/**
	 * @see ghidra.framework.options.OptionsEditor#cancel()
	 */
	@Override
	public void cancel() {
		// nothing to do
	}

	@Override
	public void reload() {
		// nothing to do, as this component is reloaded when options are changed
	}

	/**
	 * @see ghidra.framework.options.OptionsEditor#getEditorComponent()
	 */
	@Override
	public JComponent getEditorComponent(Options options, EditorStateFactory factory) {
		return this;
	}

	/**
	 * @see OptionsEditor#setOptionsPropertyChangeListener(PropertyChangeListener)
	 */
	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		optionsPanel.setOptionsPropertyChangeListener(listener);
	}

//==================================================================================================
// Scrollable Interface Methods
//==================================================================================================

	/**
	 * @see javax.swing.Scrollable#getPreferredScrollableViewportSize()
	 */
	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableBlockIncrement(java.awt.Rectangle, int, int)
	 */
	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return visibleRect.height;
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableTracksViewportHeight()
	 */
	@Override
	public boolean getScrollableTracksViewportHeight() {
		return true;
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableTracksViewportWidth()
	 */
	@Override
	public boolean getScrollableTracksViewportWidth() {
		return false;
	}

	/**
	 * @see javax.swing.Scrollable#getScrollableUnitIncrement(java.awt.Rectangle, int, int)
	 */
	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 10;
	}

}
