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
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.label.GLabel;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.MaximizeSpecificColumnGridLayout;

/**
 * <code>VariousChoicesPanel</code> provides a table type of format for resolving
 * multiple conflicts in one panel. Each row that has choices represents the
 * choices for a single conflict. 
 * So each row can have multiple radio buttons or multiple check boxes.
 * At least one choice must be made in each row that provides choices before 
 * this panel will indicate that all choices are resolved.
 */
public class VariousChoicesPanel extends ConflictPanel {

	private final static long serialVersionUID = 1;
	private static final Border UNDERLINE_BORDER =
		BorderFactory.createMatteBorder(0, 0, 1, 0, Color.BLACK);

	private JPanel rowPanel;
	private GDHtmlLabel headerLabel;
	private ArrayList<ChoiceRow> rows;
	private Border radioButtonBorder;
	private Border checkBoxBorder;
	private int columnCount = 1;
	private MaximizeSpecificColumnGridLayout layout;
	private int indent;

	/**
	 * Constructor for a various choices panel.
	 */
	public VariousChoicesPanel() {
		super();
		init();
	}

	/**
	 * Constructor for a various choices panel.
	 * @param isDoubleBuffered
	 */
	public VariousChoicesPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
		init();
	}

	private void init() {
		setBorder(BorderFactory.createTitledBorder("Resolve Conflict"));
		rows = new ArrayList<>();
		layout = new MaximizeSpecificColumnGridLayout(5, 5, columnCount);
		rowPanel = new JPanel(layout);
		rowPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		setLayout(new BorderLayout());
		headerLabel = new GDHtmlLabel(" ");
		headerLabel.setHorizontalAlignment(SwingConstants.CENTER);
		add(headerLabel, BorderLayout.NORTH);
		setHeader(null);
		MyRadioButton rb = new MyRadioButton("W");
		MyCheckBox cb = new MyCheckBox("W");
		MyLabel lbl = new MyLabel("W");
		indent = Math.max(rb.getPreferredSize().width, cb.getPreferredSize().width);
		int radioButtonOffset = (rb.getPreferredSize().height - lbl.getPreferredSize().height) / 2;
		int checkBoxOffset = (cb.getPreferredSize().height - lbl.getPreferredSize().height) / 2;
		radioButtonBorder = BorderFactory.createEmptyBorder(
			(radioButtonOffset > 0 ? radioButtonOffset : 0), 0, 0, 0);
		checkBoxBorder =
			BorderFactory.createEmptyBorder((checkBoxOffset > 0 ? checkBoxOffset : 0), 0, 0, 0);

		add(createUseForAllCheckBox(), BorderLayout.SOUTH);
		adjustUseForAllEnablement();
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

	private void adjustColumnCount(int numberOfColumns) {
		if (numberOfColumns <= 0) {
			numberOfColumns = 1;
		}
		if (columnCount != numberOfColumns) {
			columnCount = numberOfColumns;
			layout = new MaximizeSpecificColumnGridLayout(5, 5, columnCount);
			rowPanel.setLayout(layout);
		}
	}

	/**
	 * Adds a row to the table that doesn't provide any choices. 
	 * Instead this row just provides information.
	 * 
	 * @param title title the is placed at the beginning of the row
	 * @param info the text for each table column in the row
	 * @param underline true indicates each info string should be underlined 
	 * when it appears. (Underlining is done on the header row (row 0) of the table.
	 */
	void addInfoRow(final String title, final String[] info, boolean underline) {
		adjustColumnCount(info.length);
		MyLabel titleComp = new MyLabel(title);
		if (underline) {
			titleComp.setBorder(UNDERLINE_BORDER);
		}
		MyLabel[] labels = new MyLabel[info.length];
		for (int i = 0; i < info.length; i++) {
			labels[i] = new MyLabel(info[i]);
			if (underline) {
				labels[i].setBorder(UNDERLINE_BORDER);
			}
		}
		ChoiceRow noChoiceRow = new ChoiceRow(titleComp, labels);
		addRow(noChoiceRow);
		rowPanel.validate();
		validate();
		invalidate();
		adjustUseForAllEnablement();
	}

	/**
	 * Adds radiobutton choices as a row of the table.
	 * Radiobuttons allow you to select only one choice in the row.
	 * 
	 * @param title title the is placed at the beginning of the row
	 * @param choices the text for each choice in the row
	 * @param listener listener that gets notified whenever the state of 
	 * one of the radiobuttons in this row changes.
	 */
	void addSingleChoice(final String title, final String[] choices,
			final ChangeListener listener) {
		adjustColumnCount(choices.length + 1);
		for (int i = 0; i < choices.length; i++) {
			if (choices[i] == null) {
				choices[i] = "-- none --";
			}
			else if (choices[i].length() == 0) {
				choices[i] = "-- empty --";
			}
		}
		MyLabel titleComp = new MyLabel(title);
		MyRadioButton[] rb = new MyRadioButton[choices.length];
		final int row = rows.size();
		final ChoiceRow choiceRow = new ChoiceRow(titleComp, rb);
		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				adjustUseForAllEnablement();
				if (listener != null) {
					Object source = e.getSource();
					if (((MyRadioButton) source).isSelected()) {
						ResolveConflictChangeEvent re =
							new ResolveConflictChangeEvent(source, row, choiceRow.getChoice());
						listener.stateChanged(re);
					}
				}
			}
		};
		ButtonGroup group = new ButtonGroup();
		for (int i = 0; i < choices.length; i++) {
			rb[i] = new MyRadioButton(choices[i]);
			rb[i].setName("ChoiceComponentRow" + row + "Col" + (i + 1));
			group.add(rb[i]);
			rb[i].addItemListener(itemListener);
		}
		if (choices.length > 0) {
			titleComp.setBorder(radioButtonBorder);
		}
		addRow(choiceRow);
		rowPanel.validate();
		validate();
		invalidate();
		adjustUseForAllEnablement();
	}

	/**
	 * Adds checkbox choices as a row of the table.
	 * Check boxes allow you to select one or more choices in the row.
	 * 
	 * @param title title the is placed at the beginning of the row
	 * @param choices the text for each choice in the row
	 * @param listener listener that gets notified whenever the state of 
	 * one of the checkboxes in this row changes.
	 */
	void addMultipleChoice(final String title, final String[] choices,
			final ChangeListener listener) {
		adjustColumnCount(choices.length + 1);
		MyLabel titleComp = new MyLabel(title);
		MyCheckBox[] cb = new MyCheckBox[choices.length];
		final int row = rows.size();
		final ChoiceRow choiceRow = new ChoiceRow(titleComp, cb);
		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				adjustUseForAllEnablement();
				if (listener != null) {
					ResolveConflictChangeEvent re =
						new ResolveConflictChangeEvent(e.getSource(), row, choiceRow.getChoice());
					listener.stateChanged(re);
				}
			}
		};
		for (int i = 0; i < choices.length; i++) {
			cb[i] = new MyCheckBox(choices[i]);
			cb[i].setName(getComponentName(row, (i + 1)));
			cb[i].addItemListener(itemListener);
		}
		if (choices.length > 0) {
			titleComp.setBorder(checkBoxBorder);
		}
		addRow(choiceRow);
		rowPanel.validate();
		validate();
		invalidate();
		adjustUseForAllEnablement();
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
	 * @param choiceRow
	 */
	private void addRow(ChoiceRow choiceRow) {
		int row = rows.size();
		rows.add(choiceRow);

		rowPanel.add(choiceRow.titleLabel);

		for (int i = 0; i < choiceRow.rb.length; i++) {
			rowPanel.add(choiceRow.rb[i]);
		}
		if (row == 0) {
			add(rowPanel, BorderLayout.CENTER);
		}
	}

	private void removeRow(int rowNum) {
		ChoiceRow cr = rows.get(rowNum);
		rowPanel.remove(cr.titleLabel);
		JComponent[] comps = cr.rb;
		for (int i = 0; i < comps.length; i++) {
			rowPanel.remove(comps[i]);
		}
		rows.remove(rowNum);
	}

	@Override
	public int getUseForAllChoice() {
		if (rows == null || rows.isEmpty()) {
			return 0;
		}
		int firstChoice = -1;
		Iterator<ChoiceRow> iter = rows.iterator();
		while (iter.hasNext()) {
			ChoiceRow cr = iter.next();
			int currentChoice = cr.getChoice();
			if (cr.hasChoices()) {
				if (currentChoice == 0) {
					return 0;
				}
				if (firstChoice == -1) {
					firstChoice = currentChoice;
				}
				else if (currentChoice != firstChoice) {
					return 0;
				}
			}
		}
		return (firstChoice != -1) ? firstChoice : 0;
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table.
	 */
	@Override
	public boolean allChoicesAreResolved() {
		Iterator<ChoiceRow> iter = rows.iterator();
		while (iter.hasNext()) {
			ChoiceRow cr = iter.next();
			if (cr.hasChoices() && cr.getChoice() == 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table and 
	 * made the same choice for every row.
	 */
	@Override
	public boolean allChoicesAreSame() {
		if (rows == null || rows.isEmpty()) {
			return false;
		}
		int firstChoice = -1;
		Iterator<ChoiceRow> iter = rows.iterator();
		while (iter.hasNext()) {
			ChoiceRow cr = iter.next();
			int currentChoice = cr.getChoice();
			if (cr.hasChoices()) {
				if (currentChoice == 0) {
					return false;
				}
				if (firstChoice == -1) {
					firstChoice = currentChoice;
				}
				else if (currentChoice != firstChoice) {
					return false;
				}
			}
		}
		return (firstChoice != -1);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ChoiceComponent#getNumConflictsResolved()
	 */
	@Override
	public int getNumConflictsResolved() {
		int count = 0;
		Iterator<ChoiceRow> iter = rows.iterator();
		while (iter.hasNext()) {
			ChoiceRow cr = iter.next();
			if (cr.getChoice() != 0) {
				count++;
			}
		}
		return count;
	}

	@Override
	public void removeAllListeners() {
		Iterator<ChoiceRow> iter = rows.iterator();
		while (iter.hasNext()) {
			ChoiceRow cr = iter.next();
			removeListeners(cr);
		}
	}

	private void removeListeners(ChoiceRow cr) {
		for (int i = 0; i < cr.rb.length; i++) {
			JComponent comp = cr.rb[i];
			if (comp instanceof MyRadioButton) {
				MyRadioButton rb = (MyRadioButton) comp;
				ItemListener[] listeners = rb.getItemListeners();
				for (int j = listeners.length - 1; j >= 0; j--) {
					rb.removeItemListener(listeners[j]);
				}
			}
			if (comp instanceof MyCheckBox) {
				MyCheckBox cb = (MyCheckBox) comp;
				ItemListener[] listeners = cb.getItemListeners();
				for (int j = listeners.length - 1; j >= 0; j--) {
					cb.removeItemListener(listeners[j]);
				}

			}
		}
	}

	/**
	 * Removes header text for this panel and all table/row information.
	 */
	@Override
	public void clear() {
		removeAllListeners();
		int numRows = rows.size();
		for (int i = numRows - 1; i >= 0; i--) {
			removeRow(i);
		}
		setHeader(null);
		columnCount = 1;
		rowPanel.validate();
		validate();
		invalidate();
		adjustUseForAllEnablement();
	}

	/**
	 * Adjusts the enablement of the Use For All checkbox based on whether choices have been made 
	 * for all the conflicts currently on the screen and whether the same choice was made for all 
	 * conflicts on the screen.
	 */
	public void adjustUseForAllEnablement() {
		boolean enable = allChoicesAreSame();
		if (!enable) {
			setUseForAll(false);
		}
		useForAllCB.setEnabled(enable);
	}

	class ChoiceRow {
		MyLabel titleLabel;
		JComponent[] rb;

		ChoiceRow(MyLabel titleLabel, JComponent[] rb) {
			this.titleLabel = titleLabel;
			this.rb = rb;
		}

		int[] getWidths() {
			int[] widths = new int[rb.length + 1];
			widths[0] = titleLabel.getWidth();
			for (int i = 0; i < rb.length; i++) {
				widths[i + 1] = rb[i].getWidth();
			}
			return widths;
		}

		int getHeight() {
			int height = titleLabel.getHeight();
			return height;
		}

		int getChoice() {
			int choice = 0;
			for (int i = 0; i < rb.length; i++) {
				if (rb[i] instanceof MyRadioButton) {
					if (((MyRadioButton) rb[i]).isSelected()) {
						choice |= 1 << i;
					}
				}
				if (rb[i] instanceof MyCheckBox) {
					if (((MyCheckBox) rb[i]).isSelected()) {
						choice |= 1 << i;
					}
				}
			}
			return choice;
		}

		boolean hasChoices() {
			for (int i = 0; i < rb.length; i++) {
				if ((rb[i] instanceof MyRadioButton) || (rb[i] instanceof MyCheckBox)) {
					return true;
				}
			}
			return false;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ConflictPanel#hasChoice()
	 */
	@Override
	public boolean hasChoice() {
		return rows.size() > 0;
	}

	private class MyLabel extends GLabel {

		/**
		 * @param text the text of this label.
		 */
		public MyLabel(String text) {
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
					int displayedWidth = getWidth();
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

		/**
		 * @param text the text for this radio button
		 */
		public MyRadioButton(final String text) {
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
	}

	private class MyCheckBox extends GCheckBox {
		private final static long serialVersionUID = 1;

		/**
		 * @param text the text for this check box
		 */
		public MyCheckBox(String text) {
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
	}
}
