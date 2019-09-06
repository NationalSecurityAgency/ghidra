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
package ghidra.app.merge.listing;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Insets;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.ListIterator;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.SwingConstants;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.label.GDLabel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.util.HTMLUtilities;
import ghidra.util.datastruct.LongArrayList;
import ghidra.util.layout.MaximizeSpecificColumnGridLayout;

/**
 * <CODE>VerticalChoicesPanel</CODE> is a conflict panel for the Listing Merge.
 * It lays out rows of information vertically in a table format. 
 * Each row can be a header row, an information row, a single choice row, 
 * or a multiple choice row.
 * <BR>Single choice rows provide a radio button and are used when a single 
 * choice must be made from multiple rows of choices.
 * <BR>Multiple choice rows provide a check box and are used when more than one 
 * choice can be made from multiple rows of choices.
 * <BR>Note: Single choice and multiple choice rows are not intended to be 
 * intermixed on the same panel.
 * <BR>A header label can be set. This appears above the row table. The text
 * for the header label should be HTML.
 */
public class VerticalChoicesPanel extends ConflictPanel {

	private final static long serialVersionUID = 1;
	final static int HEADER = 0;
	final static int INFORMATION = 1;
	final static int RADIO_BUTTON = 2;
	final static int CHECK_BOX = 3;

	private GDHtmlLabel headerLabel;
	private JPanel rowPanel;
	private ArrayList<ArrayList<JComponent>> rowComps;
	private ArrayList<String[]> rows;
	private LongArrayList rowTypes;
	private ButtonGroup group;
	private int columnCount = 1;
	private MaximizeSpecificColumnGridLayout layout;
	private int indent;
	private static final int DEFAULT_TOP = 2;
	private static final int DEFAULT_LEFT = 4;
	private static final int DEFAULT_BOTTOM = 2;
	private static final int DEFAULT_RIGHT = 4;
	private Insets defaultInsets;
	private Insets textVsButtonInsets;
	private Insets textVsCheckBoxInsets;

	/**
	 * Creates an empty <CODE>VerticalChoicesPanel</CODE>
	 */
	public VerticalChoicesPanel() {
		super();
		init();
	}

	/**
	 * @param isDoubleBuffered
	 */
	public VerticalChoicesPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
		init();
	}

	private void init() {
		setBorder(BorderFactory.createTitledBorder("Resolve Conflict"));
		setLayout(new BorderLayout());

		headerLabel = new GDHtmlLabel(" ");
		headerLabel.setHorizontalAlignment(SwingConstants.CENTER);
		add(headerLabel, BorderLayout.NORTH);

		rowComps = new ArrayList<>();
		rows = new ArrayList<>();
		rowTypes = new LongArrayList();
		group = new ButtonGroup();
		layout = new MaximizeSpecificColumnGridLayout(5, 5, columnCount);
		layout.maximizeColumn(0);
		rowPanel = new JPanel(layout);
		add(rowPanel, BorderLayout.CENTER);
		rowPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		GRadioButton rb = new GRadioButton();
		JCheckBox cb = new GCheckBox();
		indent = Math.max(rb.getPreferredSize().width, cb.getPreferredSize().width);

		defaultInsets = new Insets(DEFAULT_TOP, DEFAULT_LEFT, DEFAULT_BOTTOM, DEFAULT_RIGHT);
		int labelHeight = (int) new GDLabel("A").getPreferredSize().getHeight();
		double buttonHeight = new MyRadioButton("A",
			ListingMergeConstants.KEEP_LATEST).getPreferredSize().getHeight();
		int borderHeight;
		borderHeight = (int) ((buttonHeight - labelHeight) / 2);
		if (borderHeight < 0) {
			borderHeight = 0;
		}
		textVsButtonInsets = new Insets(DEFAULT_TOP + borderHeight, DEFAULT_LEFT,
			DEFAULT_BOTTOM + borderHeight, DEFAULT_RIGHT);
		double checkBoxHeight =
			new MyCheckBox("A", ListingMergeConstants.KEEP_LATEST).getPreferredSize().getHeight();
		borderHeight = (int) ((checkBoxHeight - labelHeight) / 2);
		if (borderHeight < 0) {
			borderHeight = 0;
		}
		textVsCheckBoxInsets = new Insets(DEFAULT_TOP + borderHeight, DEFAULT_LEFT,
			DEFAULT_BOTTOM + borderHeight, DEFAULT_RIGHT);

		add(createUseForAllCheckBox(), BorderLayout.SOUTH);
	}

	/**
	 * This sets the text that appears as the border title of this panel.
	 * @param conflictType the type of conflict being resolved.
	 */
	void setTitle(String conflictType) {
		((TitledBorder) getBorder()).setTitle("Resolve " + conflictType + " Conflict");
	}

	/**
	 * This sets the header text that appears above the table.
	 * @param text the text
	 */
	void setHeader(String text) {
		if (text != null && text.length() != 0) {
			headerLabel.setText(ConflictUtility.wrapAsHTML(text));
			add(headerLabel, BorderLayout.NORTH);
		}
		else {
			headerLabel.setText("");
			remove(headerLabel);
		}
		validate();
		invalidate();
	}

	void setRowHeader(String[] items) {
		adjustColumnCount(items.length);
		JComponent[] headerComps = getRowComponents(0);
		if (headerComps != null) {
			// remove the header
			for (int i = 0; i < headerComps.length; i++) {
				rowPanel.remove(headerComps[i]);
			}
			headerComps = null;
			if (rowComps.isEmpty()) {
				rowComps.add(0, new ArrayList<JComponent>());
			}
			else {
				rowComps.set(0, new ArrayList<JComponent>());
			}
		}
		if (rowTypes.isEmpty()) {
			rowTypes.add(HEADER);
		}
		else {
			rowTypes.set(0, (long) HEADER);
		}
		if ((items != null) && (items.length > 0)) {
			if (rows.isEmpty()) {
				rows.add(0, items);
			}
			else {
				rows.set(0, items);
			}
			// create the header.
			headerComps = new JComponent[items.length];
			for (int i = 0; i < headerComps.length; i++) {
				headerComps[i] = new MyLabel(items[i]);
				headerComps[i].setName(getComponentName(0, i));
				setRowComponent(headerComps[i], 0, i, defaultInsets);
				headerComps[i].setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.BLACK));
			}
		}
		rowPanel.validate();
		validate();
		invalidate();
	}

	private void adjustColumnCount(int numberOfColumns) {
		if (numberOfColumns <= 0) {
			numberOfColumns = 1;
		}
		if (columnCount != numberOfColumns) {
			columnCount = numberOfColumns;
			layout = new MaximizeSpecificColumnGridLayout(5, 5, columnCount);
			layout.maximizeColumn(0);
			rowPanel.setLayout(layout);
		}
	}

	/**
	 * Gets the GUI components in order from left to right for the indicated row of the display table.
	 * @param row the row index (0 based).
	 * @return the components.
	 */
	private JComponent[] getRowComponents(int row) {
		if (rowComps.isEmpty()) {
			return new JComponent[0];
		}
		ArrayList<JComponent> list = rowComps.get(row);
		if (list == null || list.size() == 0) {
			return new JComponent[0];
		}
		JComponent[] comps = list.toArray(new JComponent[list.size()]);
		return comps;
	}

	private void setRowComponent(JComponent comp, int row, int column, Insets insets) {
		rowPanel.add(comp);
		int numRows = rowComps.size();
		if (row >= numRows) {
			// Creating brand new row.
			for (int i = numRows; i <= row; i++) {
				rowComps.add(i, new ArrayList<JComponent>());
			}
		}
		ArrayList<JComponent> list = rowComps.get(row);
		for (int i = list.size(); i <= column; i++) {
			list.add(null);
		}
		list.set(column, comp);
	}

	/**
	 * Adds a row with the items in each column. The first item's component is a radio button.
	 * @param items the text for each column.
	 * @param name the name for the radio button component.
	 * @param conflictOption the conflict option value associated with selecting this row's radio button.
	 * @param listener listener to be notified when the radio button is selected.
	 */
	void addRadioButtonRow(final String[] items, final String name, final int conflictOption,
			final ChangeListener listener) {
		adjustColumnCount(items.length);
		final int row = rows.size();
		rowTypes.add(RADIO_BUTTON);
		rows.add(items);
		final MyRadioButton firstComp = new MyRadioButton(items[0], conflictOption);
		group.add(firstComp);
		firstComp.setName(name);
		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (listener != null && ((JRadioButton) e.getSource()).isSelected()) {
					ResolveConflictChangeEvent event =
						new ResolveConflictChangeEvent(firstComp, row, getSelectedOptions());
					listener.stateChanged(event);
				}
			}
		};
		firstComp.addItemListener(itemListener);
		setRowComponent(firstComp, row, 0, defaultInsets);
		for (int i = 1; i < items.length; i++) {
			MyLabel newComp = new MyLabel(items[i]);
			newComp.setName(getComponentName(row, i));
			setRowComponent(newComp, row, i, textVsButtonInsets);
		}
		rowPanel.validate();
		validate();
		invalidate();
	}

	/**
	 * Adds a row with the items in each column. The first item's component is a check box.
	 * @param items the text for each column.
	 * @param name the name for the check box component.
	 * @param conflictOption the conflict option value associated with selecting this row's check box.
	 * @param listener listener to be notified when the check box is selected or not selected.
	 */
	void addCheckBoxRow(final String[] items, final String name, final int conflictOption,
			final ChangeListener listener) {
		adjustColumnCount(items.length);
		int row = rows.size();
		rowTypes.add(CHECK_BOX);
		rows.add(items);
		MyCheckBox firstComp = new MyCheckBox(items[0], conflictOption);
		firstComp.setName(name);
		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (listener != null) {
					listener.stateChanged(null);
				}
			}
		};
		firstComp.addItemListener(itemListener);
		setRowComponent(firstComp, row, 0, defaultInsets);
		for (int i = 1; i < items.length; i++) {
			MyLabel newComp = new MyLabel(items[i]);
			newComp.setName(getComponentName(row, i));
			setRowComponent(newComp, row, i, textVsCheckBoxInsets);
		}
		rowPanel.validate();
		validate();
		invalidate();
	}

	/**
	 * Adds a row to the table that doesn't provide any choices. 
	 * Instead this row just provides information.
	 * 
	 * @param items the text for each column.
	 */
	void addInfoRow(String[] items) {
		adjustColumnCount(items.length);
		int row = rows.size();
		rowTypes.add(INFORMATION);
		rows.add(items);
		MyLabel firstComp = new MyLabel(items[0]);
		firstComp.setBorder(BorderFactory.createEmptyBorder(0, indent, 0, 0));
		firstComp.setName(getComponentName(row, 0));
		setRowComponent(firstComp, row, 0, defaultInsets);
		for (int i = 1; i < items.length; i++) {
			MyLabel newComp = new MyLabel(items[i]);
			newComp.setName(getComponentName(row, i));
			setRowComponent(newComp, row, i, defaultInsets);
		}
		rowPanel.validate();
		validate();
		invalidate();
	}

	/**
	 * Removes header text for this panel and all table/row information.
	 * It also sets the columnCount back to 1.
	 */
	@Override
	public void clear() {
		setHeader(null);
		ListIterator<ArrayList<JComponent>> iter = rowComps.listIterator();
		while (iter.hasNext()) {
			ArrayList<JComponent> compList = iter.next();
			ListIterator<JComponent> compIter = compList.listIterator();
			while (compIter.hasNext()) {
				Component rowComp = compIter.next();
				rowPanel.remove(rowComp);
			}
			compList.clear();
		}
		rowComps.clear();
		rows.clear();
		rowTypes.clear();
		group = new ButtonGroup();
		columnCount = 1;
		rowPanel.validate();
		validate();
		invalidate();
	}

	/**
	 * Gets a generic name for a component in the table.
	 * @param row the row of the table
	 * @param column the column of the table
	 * @return the default name of the indicated component in the table.
	 */
	String getComponentName(int row, int column) {
		return "ChoiceComponentRow" + row + "Col" + column;
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table.
	 */
	@Override
	public boolean allChoicesAreResolved() {
		for (int row = 0; row < rows.size(); row++) {
			JComponent comp = getComponent(row, 0);
			if ((comp instanceof MyRadioButton) && (((MyRadioButton) comp).isSelected())) {
				return true;
			}
			else if ((comp instanceof MyCheckBox) && (((MyCheckBox) comp).isSelected())) {
				return true;
			}
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ChoiceComponent#getNumConflictsResolved()
	 */
	@Override
	public int getNumConflictsResolved() {
		int count = 0;
		for (int row = 0; row < rows.size(); row++) {
			JComponent comp = getComponent(row, 0);
			if ((comp instanceof MyRadioButton) && (((MyRadioButton) comp).isSelected())) {
				count++;
			}
			else if ((comp instanceof MyCheckBox) && (((MyCheckBox) comp).isSelected())) {
				count++;
			}
		}
		return count;
	}

	/**
	 * @return
	 */
	protected int getSelectedOptions() {
		int option = 0;
		for (int row = 0; row < rows.size(); row++) {
			JComponent comp = getComponent(row, 0);
			if ((comp instanceof MyRadioButton) && (((MyRadioButton) comp).isSelected())) {
				option |= ((MyRadioButton) comp).getOption();
			}
			else if ((comp instanceof MyCheckBox) && (((MyCheckBox) comp).isSelected())) {
				option |= ((MyCheckBox) comp).getOption();
			}
		}
		return option;
	}

	/**
	 * @param row
	 * @param i
	 * @return
	 */
	private JComponent getComponent(int row, int column) {
		JComponent[] comps = getRowComponents(row);
		if (column < comps.length) {
			return comps[column];
		}
		return null;
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table and 
	 * made the same choice for every row.
	 */
	@Override
	public boolean allChoicesAreSame() {
		return allChoicesAreResolved();
	}

	private class MyLabel extends GDHtmlLabel {

		/**
		 * @param text the text of this label.
		 */
		public MyLabel(final String text) {
			super(text);
			addComponentListener(new ComponentListener() {

				@Override
				public void componentResized(ComponentEvent e) {
					// Set a tooltip if we can't see all the text.
					String displayedText = getText();
					if (displayedText == null) {
						setToolTipText(null);
						return;
					}
					Border border2 = MyLabel.this.getBorder();
					Insets borderInsets =
						(border2 != null) ? border2.getBorderInsets(MyLabel.this) : null;
					int left2 = (borderInsets != null) ? borderInsets.left : 0;
					int displayedWidth = getWidth() - left2;
					Font displayedFont = getFont();
					FontMetrics fontMetrics =
						(displayedFont != null) ? getFontMetrics(displayedFont) : null;
					int stringWidth =
						(fontMetrics != null) ? fontMetrics.stringWidth(displayedText) : 0;
					setToolTipText(
						(stringWidth > displayedWidth) ? "<html>" + HTMLUtilities.escapeHTML(text)
								: null);
				}

				@Override
				public void componentMoved(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentShown(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentHidden(ComponentEvent e) {
					// Do nothing.
				}
			});
		}
	}

	private class MyRadioButton extends GRadioButton {
		private final static long serialVersionUID = 1;
		private int option;

		/**
		 * @param text the text for this radio button
		 * @param option the option value associated with this radio button.
		 */
		public MyRadioButton(final String text, int option) {
			super(text);
			this.option = option;
			addComponentListener(new ComponentListener() {

				@Override
				public void componentResized(ComponentEvent e) {
					// Set a tooltip if we can't see all the text.
					String displayedText = getText();
					if (displayedText == null) {
						setToolTipText(null);
						return;
					}
					int displayedWidth = getWidth() - indent;
					Font displayedFont = getFont();
					FontMetrics fontMetrics =
						(displayedFont != null) ? getFontMetrics(displayedFont) : null;
					int stringWidth =
						(fontMetrics != null) ? fontMetrics.stringWidth(displayedText) : 0;
					setToolTipText((stringWidth > displayedWidth) ? displayedText : null);
				}

				@Override
				public void componentMoved(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentShown(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentHidden(ComponentEvent e) {
					// Do nothing.
				}
			});
		}

		/**
		 * Gets the option value associated with this button.
		 */
		private int getOption() {
			return option;
		}

	}

	private class MyCheckBox extends GCheckBox {
		private final static long serialVersionUID = 1;
		private int option;

		/**
		 * @param text the text for this check box
		 * @param option the option value associated with this check box.
		 */
		public MyCheckBox(String text, int option) {
			super(text);
			this.option = option;
			addComponentListener(new ComponentListener() {

				@Override
				public void componentResized(ComponentEvent e) {
					// Set a tooltip if we can't see all the text.
					String displayedText = getText();
					if (displayedText == null) {
						setToolTipText(null);
						return;
					}
					int displayedWidth = getWidth() - indent;
					Font displayedFont = getFont();
					FontMetrics fontMetrics =
						(displayedFont != null) ? getFontMetrics(displayedFont) : null;
					int stringWidth =
						(fontMetrics != null) ? fontMetrics.stringWidth(displayedText) : 0;
					setToolTipText((stringWidth > displayedWidth) ? displayedText : null);
				}

				@Override
				public void componentMoved(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentShown(ComponentEvent e) {
					// Do nothing.
				}

				@Override
				public void componentHidden(ComponentEvent e) {
					// Do nothing.
				}
			});
		}

		/**
		 * Gets the option value associated with this check box.
		 */
		private int getOption() {
			return option;
		}

	}

	@Override
	public int getUseForAllChoice() {
		int conflictOption = 0;
		int rowCount = rowComps.size();
		for (int row = 0; row < rowCount; row++) {
			JComponent[] comps = getRowComponents(row);
			for (int i = 0; i < comps.length; i++) {
				JComponent component = comps[i];
				if (component instanceof MyRadioButton &&
					((MyRadioButton) component).isSelected()) {
					conflictOption |= ((MyRadioButton) component).option;
				}
				else if (component instanceof MyCheckBox && ((MyCheckBox) component).isSelected()) {
					conflictOption |= ((MyCheckBox) component).option;
				}
			}
		}
		return conflictOption;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ConflictPanel#removeAllListeners()
	 */
	@Override
	public void removeAllListeners() {
		// Do nothing.
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ConflictPanel#hasChoice()
	 */
	@Override
	public boolean hasChoice() {
		for (Iterator<Long> iterator = rowTypes.iterator(); iterator.hasNext();) {
			long rowType = iterator.next().longValue();
			if (rowType == RADIO_BUTTON || rowType == CHECK_BOX) {
				return true;
			}
		}
		return false;
	}
}
