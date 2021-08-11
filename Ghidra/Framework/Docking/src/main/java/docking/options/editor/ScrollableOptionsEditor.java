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
public class ScrollableOptionsEditor implements OptionsEditor {

	private OptionsEditorPanel optionsPanel;
	private String title;
	private List<String> optionNames;
	private JScrollPane scrollPane;
	private PropertyChangeListener listener;

	/**
	 * Creates a panel for editing options. This version of the constructor allows the client
	 * to specify the option names to put them in some order other than the default alphabetical
	 * ordering.
	 * 
	 * @param title The title of the options panel
	 * @param optionNames the names of the options for this panel
	 */
	public ScrollableOptionsEditor(String title, List<String> optionNames) {
		this.title = title;
		this.optionNames = optionNames;

	}

	/**
	 * Creates a panel for editing options. This version of the constructor will get the
	 * options names from the options object when
	 * {@link #getEditorComponent(Options, EditorStateFactory)} is called.
	 * @param title the title for the panel
	 */
	public ScrollableOptionsEditor(String title) {
		this(title, null);
	}

//==================================================================================================
// OptionsEditor Interface Methods
//==================================================================================================

	@Override
	public void dispose() {
		if (optionsPanel != null) {
			optionsPanel.dispose();
		}
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
		scrollPane = new JScrollPane();
		optionsPanel = new OptionsEditorPanel(title, options, optionNames, factory);
		optionsPanel.setOptionsPropertyChangeListener(listener);

		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);

		// the outer panel is 'Scrollable' and uses a layout that centers the options panel
		JPanel outerPanel = new ScollableOptionsPanel();
		outerPanel.add(optionsPanel);
		scrollPane.setViewportView(outerPanel);

		return scrollPane;
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.listener = listener;
		if (optionsPanel != null) {
			optionsPanel.setOptionsPropertyChangeListener(listener);
		}
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
			Dimension viewSize = scrollPane.getViewport().getSize();
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
			Dimension viewSize = scrollPane.getViewport().getSize();
			boolean viewIsLarger = viewSize.width > mySize.width;
			return viewIsLarger;
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation,
				int direction) {
			return 10;
		}
	}

	// for testing
	public JComponent getComponent() {
		return scrollPane;
	}
}
