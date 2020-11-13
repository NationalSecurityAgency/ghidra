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

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.List;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeListener;
import javax.swing.table.TableModel;

import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDHtmlLabel;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.app.merge.util.ConflictUtility;
import ghidra.util.SystemUtilities;

/**
 * <code>ScrollingListChoicesPanel</code> provides a table type of format for resolving
 * Each row that has choices represents the choices for a single conflict. Each conflict
 * choice has a corresponding radio button and scrolling table/list of text.
 */
public class ScrollingListChoicesPanel extends ConflictPanel {

	private final static long serialVersionUID = 1;

	private GridBagLayout gbl;
	private JPanel rowPanel;
	private GDHtmlLabel headerLabel;
	private ButtonGroup buttonGroup;
	private ListChoice leftListChoice;
	private ListChoice rightListChoice;
	private volatile ChangeListener listener;

	/**
	 * Constructor for a various choices panel.
	 */
	public ScrollingListChoicesPanel() {
		super();
		init();
	}

	/**
	 * Constructor for a various choices panel.
	 * @param isDoubleBuffered
	 */
	public ScrollingListChoicesPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
		init();
	}

	private void init() {
		setBorder(BorderFactory.createTitledBorder("Resolve Conflict"));
		gbl = new GridBagLayout();
		rowPanel = new JPanel(gbl);
		setLayout(new BorderLayout());
		headerLabel = new GDHtmlLabel(" ");
		headerLabel.setHorizontalAlignment(SwingConstants.CENTER);
		add(headerLabel, BorderLayout.NORTH);
		setHeader(null);

		buttonGroup = new ButtonGroup();

		leftListChoice = new ListChoice(buttonGroup, radioButtonListener);

		rightListChoice = new ListChoice(buttonGroup, radioButtonListener);

		gbl.columnWeights = new double[] { 0.15, 0.3, 0.3, 0.15 };

		GridBagConstraints c = new GridBagConstraints();
		c.anchor = GridBagConstraints.CENTER;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(2, 4, 2, 4);
		c.gridx = 0;
		c.gridy = 0;

		Component filler = Box.createHorizontalGlue();
		gbl.setConstraints(filler, c);
		rowPanel.add(filler);

		++c.gridx;
		gbl.setConstraints(leftListChoice, c);
		rowPanel.add(leftListChoice);

		++c.gridx;
		gbl.setConstraints(rightListChoice, c);
		rowPanel.add(rightListChoice);

		++c.gridx;
		filler = Box.createHorizontalGlue();
		gbl.setConstraints(filler, c);
		rowPanel.add(filler);

		add(rowPanel, BorderLayout.CENTER);
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

	void setListChoice(final ChangeListener listener, String[] choices, String[] listHeadings,
			List<String[]> leftData, List<String[]> rightData) {

		leftListChoice.setData(listHeadings, leftData);
		rightListChoice.setData(listHeadings, rightData);

		this.listener = listener;

		rowPanel.validate();
		validate();
		invalidate();
	}

	void setChoiceNames(String leftRBText, String leftRBName, String rightRBText,
			String rightRBName) {
		leftListChoice.setChoiceName(leftRBText, leftRBName);
		rightListChoice.setChoiceName(rightRBText, rightRBName);
	}

	@Override
	public int getUseForAllChoice() {
		if (leftListChoice.rb.isSelected()) {
			return 1;
		}
		if (rightListChoice.rb.isSelected()) {
			return 2;
		}
		return 0;
	}

	@Override
	public boolean hasChoice() {
		return allChoicesAreResolved();
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table.
	 */
	@Override
	public boolean allChoicesAreResolved() {
		return getNumConflictsResolved() == 1;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.merge.listing.ChoiceComponent#getNumConflictsResolved()
	 */
	@Override
	public int getNumConflictsResolved() {
		if (leftListChoice.rb.isSelected() || rightListChoice.rb.isSelected()) {
			return 1;
		}
		return 0;
	}

	/**
	 * Returns true if the user made a selection for every conflict in the table and
	 * made the same choice for every row.
	 */
	@Override
	public boolean allChoicesAreSame() {
		return allChoicesAreResolved();
	}

	@Override
	public void removeAllListeners() {
		listener = null;
	}

	/**
	 * Removes header text for this panel and all table/row information.
	 */
	@Override
	public void clear() {
		listener = null;
		buttonGroup.remove(leftListChoice.rb);
		buttonGroup.remove(rightListChoice.rb);
		leftListChoice.rb.setSelected(false);
		rightListChoice.rb.setSelected(false);
		buttonGroup.add(leftListChoice.rb);
		buttonGroup.add(rightListChoice.rb);
//		List<String[]> noData = new ArrayList<String[]>();
//		leftListChoice.setData(new String[0], noData);
//		rightListChoice.setData(new String[0], noData);
//		setHeader(null);
		rowPanel.validate();
		validate();
		invalidate();
	}

	private ItemListener radioButtonListener = new ItemListener() {
		@Override
		public void itemStateChanged(ItemEvent e) {
			if (listener != null) {
				Object source = e.getSource();
				if (((JRadioButton) source).isSelected()) {
					ResolveConflictChangeEvent re =
						new ResolveConflictChangeEvent(source, 0, getUseForAllChoice());
					listener.stateChanged(re);
				}
			}
		}
	};
}

class ListChoice extends JPanel {

	JRadioButton rb;

	private String[] headings = new String[0];
	private List<String[]> data;
	private AbstractSortedTableModel<String[]> model;
	private GTable table;

	ListChoice(ButtonGroup group, ItemListener radioButtonListener) {

		setLayout(new BorderLayout());

		rb = new GRadioButton("UNKNOWN");
		rb.addItemListener(radioButtonListener);
		group.add(rb);
		add(rb, BorderLayout.NORTH);

		model = new AbstractSortedTableModel<>() {
			@Override
			public Object getColumnValueForRow(String[] t, int columnIndex) {
				return t[columnIndex];
			}

			@Override
			public String getName() {
				return "Choice Panel";
			}

			@Override
			public String getColumnName(int column) {
				return headings[column];
			}

			@Override
			public Class<?> getColumnClass(int columnIndex) {
				return String.class;
			}

			@Override
			public List<String[]> getModelData() {
				return data;
			}

			@Override
			public int getColumnCount() {
				return headings.length;
			}

			@Override
			public boolean isSortable(int columnIndex) {
				return true;
			}
		};

		table = new ListChoiceTable(model);
		table.setRowSelectionAllowed(false);
		table.setColumnSelectionAllowed(false);
		table.setCellSelectionEnabled(false);
		table.setFocusable(false);
		JScrollPane scrollPane = new JScrollPane(table);
		add(scrollPane, BorderLayout.CENTER);

	}

	void setChoiceName(String rbText, String rbName) {
		rb.setText(rbText);
		rb.setName(rbName);
	}

	void setData(String[] headings, List<String[]> data) {
		this.headings = headings;
		this.data = data;

		SystemUtilities.runIfSwingOrPostSwingLater(new Runnable() {
			@Override
			public void run() {
				model.fireTableStructureChanged();
			}
		});
	}

	public boolean isSelected() {
		return rb.isSelected();
	}

}

class ListChoiceTable extends GTable {

	public ListChoiceTable(TableModel model) {
		super(model);
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension dim = super.getPreferredSize();
		return new Dimension(dim.width, 100);
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		Dimension dim = super.getPreferredScrollableViewportSize();
		return new Dimension(dim.width, 100);
	}
}
