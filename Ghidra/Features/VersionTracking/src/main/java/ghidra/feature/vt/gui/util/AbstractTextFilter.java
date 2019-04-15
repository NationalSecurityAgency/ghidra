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
package ghidra.feature.vt.gui.util;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ComponentAdapter;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.text.DefaultFormatter;
import javax.swing.text.DefaultFormatterFactory;

import docking.widgets.label.GDLabel;
import docking.widgets.table.GTable;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.filters.*;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public abstract class AbstractTextFilter<T> extends Filter<T> {

	private static final Integer BASE_COMPONENT_LAYER = 1;
	private static final Integer HOVER_COMPONENT_LAYER = 2;

	private JComponent component;
	private FilterFormattedTextField textField;
	private String defaultValue = "";
	protected VTController controller;
	protected final GTable table;

	protected AbstractTextFilter(VTController controller, GTable table, String filterName) {
		this.controller = controller;
		this.table = table;
		component = createComponent(filterName);
	}

	private JComponent createComponent(String filterName) {
		final JPanel panel = new JPanel(new BorderLayout());
		Border paddingBorder = BorderFactory.createEmptyBorder(1, 5, 1, 5);
		Border outsideBorder = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
		panel.setBorder(BorderFactory.createCompoundBorder(outsideBorder, paddingBorder));

		DefaultFormatterFactory factory = new DefaultFormatterFactory(new DefaultFormatter());
		textField = new FilterFormattedTextField(factory, defaultValue);
		textField.setName(filterName + " Field"); // for debugging 	
		textField.setColumns(20);
		textField.setMinimumSize(textField.getPreferredSize());

		// we handle updates in real time, so ignore focus events, which trigger excess filtering
		textField.disableFocusEventProcessing();

		JLabel label = new GDLabel(filterName + ": ");
		panel.add(label, BorderLayout.WEST);
		panel.add(textField, BorderLayout.CENTER);

		StatusLabel nameFieldStatusLabel = new StatusLabel(textField, defaultValue);
		textField.addFilterStatusListener(nameFieldStatusLabel);
		textField.addFilterStatusListener(status -> fireStatusChanged(status));

		final JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.add(panel, BASE_COMPONENT_LAYER);
		layeredPane.add(nameFieldStatusLabel, HOVER_COMPONENT_LAYER);

		layeredPane.setPreferredSize(panel.getPreferredSize());
		layeredPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(java.awt.event.ComponentEvent e) {
				Dimension preferredSize = layeredPane.getSize();
				panel.setBounds(0, 0, preferredSize.width, preferredSize.height);
				panel.validate();
			}
		});

		return layeredPane;
	}

	public void setName(String name) {
		textField.setName(name);
	}

	@Override
	public void dispose() {
		super.dispose();
		table.dispose();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putString(getStateKey(), getTextFieldText());
	}

	private String getStateKey() {
		return AbstractTextFilter.class.getSimpleName() + ":" + getClass().getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		setFilterText(saveState.getString(getStateKey(), ""));
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void clearFilter() {
		textField.setText(defaultValue);
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		return textField.getFilterStatus();
	}

	protected String getTextFieldText() {
		return textField.getText();
	}

	protected void setFilterText(String filterText) {
		textField.setText(filterText);
	}

	@Override
	public FilterShortcutState getFilterShortcutState() {
		String textFieldText = getTextFieldText();
		if (textFieldText.trim().isEmpty()) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	protected boolean passesNameFilterImpl(VTAssociation association) {
		String filterText = getTextFieldText();
		if (filterText == null || filterText.trim().length() == 0) {
			return true; // no text for this filter
		}

		//
		// This filter is internally an OR filter, returning true if either symbol name
		// matches the filter text
		//
		Address address = association.getSourceAddress();
		String symbolText = getSymbolText(address);
		if (symbolText.toLowerCase().indexOf(filterText.toLowerCase()) != -1) {
			return true;
		}

		address = association.getDestinationAddress();
		symbolText = getSymbolText(address);
		if (symbolText.toLowerCase().indexOf(filterText.toLowerCase()) != -1) {
			return true;
		}
		return false;
	}

	protected String getSymbolText(Address address) {
		VTSession session = controller.getSession();
		Program sourceProgram = session.getSourceProgram();
		SymbolTable symbolTable = sourceProgram.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		if (symbol == null) {
			return "<No Symbol>";
		}
		return symbol.getName();
	}

	@Override
	public boolean isSubFilterOf(Filter<T> otherFilter) {

		if (!(otherFilter instanceof AbstractTextFilter)) {
			return false;
		}

		AbstractTextFilter<?> otherTextFilter = (AbstractTextFilter<?>) otherFilter;
		String value = getTextFieldText();
		String otherValue = otherTextFilter.getTextFieldText();
		if (Objects.equals(value, otherValue)) {
			return true;
		}

		if (value == null || otherValue == null) {
			return false;
		}

		//
		// We are a 'contains' filter; we are a sub-filter if we completely contain the other
		// filter.  For example, if our value is 'cats', then we are a sub-filter of 'cat', 
		// since all 'cats' are in the set of 'cat' filter matches.
		//
		return value.contains(otherValue);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " '" + getTextFieldText() + "'";
	}
}
