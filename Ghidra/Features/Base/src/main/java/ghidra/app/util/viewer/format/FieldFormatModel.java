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
package ghidra.app.util.viewer.format;

import java.util.*;

import org.jdom.Element;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.RowLayout;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.util.Msg;

/**
 * Maintains the size and ordering for a layout of fields.
 */
public class FieldFormatModel {

	private static final Comparator<FieldFactory> COMPARATOR = new FieldFactoryComparator();

	public final static int DIVIDER = 0;
	public final static int PLATE = 1;
	public final static int FUNCTION = 2;
	public final static int FUNCTION_VARS = 3;
	public final static int INSTRUCTION_OR_DATA = 4;
	public final static int OPEN_DATA = 5;
	public final static int ARRAY = 6;

	private int baseRowID = 0;
	private FormatManager formatMgr;
	private String name;
	private int width;
	private List<Row> rows;
	protected FieldFactory[] factories;

	FieldFormatModel(FormatManager formatMgr, String name, int categoryID,
			Class<?> proxyObjectClass, FieldFactory[] factorys) {
		this.formatMgr = formatMgr;
		this.name = name;
		List<FieldFactory> list = new ArrayList<>(factorys.length);
		for (FieldFactory factory : factorys) {
			if (factory.acceptsType(categoryID, proxyObjectClass)) {
				list.add(factory);
			}
		}
		this.factories = new FieldFactory[list.size()];
		list.toArray(this.factories);
		rows = new ArrayList<>();
		rows.add(new Row());
	}

	/**
	 * Sets the base id for this model. Each row in a model gets an id which must
	 * be unique across all models.
	 * @param id the base id for this format.
	 */
	public void setBaseRowID(int id) {
		baseRowID = id;
	}

	/**
	 * Updates users of the formatMgr to indicate the format has changed.
	 */
	public void update() {
		formatMgr.update();
	}

	/**
	 * Returns the formatMgr that is managing this model.
	 */
	public FormatManager getFormatManager() {
		return formatMgr;
	}

	/**
	 * Generates the layout objects for the given index and proxy object
	 * @param list the list to add layouts to
	 * @param index the index (represents address)
	 * @param proxy the object to get layouts for.
	 */
	public void addLayouts(List<RowLayout> list, int index, ProxyObj<?> proxy) {
		int n = rows.size();
		for (int i = 0; i < n; i++) {
			Row row = rows.get(i);
			RowLayout l = row.getLayout(index, proxy, baseRowID + i);
			if (l != null) {
				list.add(l);
			}
		}
	}

	/**
	 * Adds new empty row at the given position.  The position must be in the
	 * interval [0,numRows].
	 * @exception IllegalArgumentException thrown if the position is outside the
	 * interval [0,numRows].
	 */
	public void addRow(int index) {
		if (rows.size() <= 11) {
			rows.add(index, new Row());
			findWidth();
			formatMgr.modelChanged(this);
		}
		else {
			Msg.showWarn(this, null, "Too Many Rows", "Too Many Rows");
		}
	}

	/**
	 * Removes the row currently at the given position.
	 * @param index the index of the row to remove.
	 */
	public void removeRow(int index) {
		rows.remove(index);
		if (rows.isEmpty()) {
			// this class was written such that there must always be at least one row
			rows.add(new Row());
		}
		findWidth();
		formatMgr.modelChanged(this);
	}

	private void findWidth() {
		width = 0;
		for (int i = 0; i < rows.size(); i++) {
			width = Math.max(width, (rows.get(i)).width);
		}
	}

	/**
	 * Adds a new field to this format.
	 * @param factory the FieldFactory to add
	 * @param rowIndex the row to add the field to
	 * @param colIndex the position in the row for the new field.
	 */
	public void addFactory(FieldFactory factory, int rowIndex, int colIndex) {
		HighlightProvider hsProvider = formatMgr.getFormatHighlightProvider();
		ToolOptions displayOptions = formatMgr.getDisplayOptions();
		ToolOptions fieldOptions = formatMgr.getFieldOptions();
		FieldFactory ff = factory.newInstance(this, hsProvider, displayOptions, fieldOptions);
		if (rowIndex == rows.size()) {
			rows.add(new Row());
		}

		Row row = rows.get(rowIndex);
		row.insertField(ff, colIndex);
		findWidth();
		formatMgr.modelChanged(this);
	}

	/**
	 * Removes a field from the format.
	 * @param rowIndex the row index of the field to remove.
	 * @param colIndex the column index of the field to remove.
	 */
	public void removeFactory(int rowIndex, int colIndex) {
		Row row = rows.get(rowIndex);
		row.removeField(colIndex);
		findWidth();
		formatMgr.modelChanged(this);
	}

	/**
	 * Notifies the formatMgr that this format model has changed.
	 *
	 */
	public void modelChanged() {
		formatMgr.modelChanged(this);
	}

	/**
	 * Returns the number of rows in the model.
	 */
	public int getNumRows() {
		return rows.size();
	}

	/**
	 * Returns the name of this format model.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the number of FieldFactorys on any given row.
	 */
	public int getNumFactorys(int row) {
		if ((row < 0) || (row >= rows.size())) {
			return 0;
		}
		return (rows.get(row)).size();
	}

	/**
	 * Returns the FieldFactorys on a given row.
	 */
	public FieldFactory[] getFactorys(int row) {
		return (rows.get(row)).getFactorys();
	}

	/**
	 * Returns the list factories valid for this format.
	 */
	public FieldFactory[] getFactorys() {
		return factories.clone();
	}

	/**
	 * Moves the Field at (oldrow,oldCol) to (row,col)
	 * @param oldRowIndex the row containing the field to be moved.
	 * @param oldColIndex the column index of the field to be moved.
	 * @param newRowIndex the row to move to.
	 * @param newColIndex the column to move to.
	 * @exception IllegalArgumentException thrown if any of the parameters don't
	 * map to a valid grid position.
	 */
	public void moveFactory(int oldRowIndex, int oldColIndex, int newRowIndex, int newColIndex) {
		if (oldRowIndex < 0 || oldRowIndex >= rows.size() || newRowIndex < 0 ||
			newRowIndex >= rows.size()) {
			return;
		}
		Row oldRow = rows.get(oldRowIndex);
		Row newRow = rows.get(newRowIndex);
		if (oldColIndex < 0 || oldColIndex > oldRow.size() - 1 || newColIndex < 0 ||
			newColIndex > newRow.size()) {
			return;
		}

		FieldFactory ff = oldRow.removeField(oldColIndex);
		newRow.insertField(ff, newColIndex);
		findWidth();
		formatMgr.modelChanged(this);
	}

	/**
	 * Returns the width of this model
	 */
	public int getWidth() {
		return width;
	}

	/**
	 * Updates the fields on the given row.
	 * @param index the row to update.
	 */
	public void updateRow(int index) {
		Row row = rows.get(index);
		row.layoutFields();
		findWidth();
		formatMgr.modelChanged(this);
	}

	/**
	 * Notifies each row that the services have changed.
	 */
	public void servicesChanged() {
		for (int i = 0; i < rows.size(); i++) {
			Row row = rows.get(i);
			row.servicesChanged();
		}
	}

	/**
	 * Saves this format to XML.
	 */
	public Element saveToXml() {
		Element root = new Element("FORMAT");

		for (int i = 0; i < rows.size(); i++) {
			Element rowElem = new Element("ROW");
			Row row = rows.get(i);
			FieldFactory[] rowFactorys = row.getFactorys();
			for (FieldFactory ff : rowFactorys) {
				Element colElem = new Element("FIELD");

				if (ff instanceof SpacerFieldFactory) {
					SpacerFieldFactory sff = (SpacerFieldFactory) ff;
					String text = sff.getText();
					// has no name!
					if (text != null) {
						colElem.setAttribute("TEXT", text);
					}
				}
				else {
					colElem.setAttribute("NAME", ff.getFieldName());
				}
				colElem.setAttribute("WIDTH", "" + ff.getWidth());
				colElem.setAttribute("ENABLED", "" + ff.isEnabled());

				rowElem.addContent(colElem);
			}
			root.addContent(rowElem);
		}
		return root;
	}

	/**
	 * Restores the format for this model from XML.
	 * @param root the root XML element from which to get the format information.
	 */
	public void restoreFromXml(Element root) {
		List<?> list = root.getChildren("ROW");
		Iterator<?> rowIter = list.iterator();
		rows = new ArrayList<>(list.size());
		while (rowIter.hasNext()) {
			Row row = createRow((Element) rowIter.next());
			rows.add(row);
		}
		findWidth();
		formatMgr.modelChanged(this);
	}

	private Row createRow(Element rowElement) {
		Row row = new Row();
		Iterator<?> colIter = rowElement.getChildren("FIELD").iterator();
		while (colIter.hasNext()) {
			Element colElem = (Element) colIter.next();

			String fieldName = colElem.getAttributeValue("NAME");
			String text = colElem.getAttributeValue("TEXT");
			String fieldWidth = colElem.getAttributeValue("WIDTH");
			String enabled = colElem.getAttributeValue("ENABLED");

			FieldFactory factoryPrototype =
				FieldFactoryNameMapper.getFactoryPrototype(fieldName, factories);
			FieldFactory newInstance = getNewFieldFactoryInstance(factoryPrototype, text);

			try {
				newInstance.setWidth(Integer.parseInt(fieldWidth));
			}
			catch (Exception exc) {
				Msg.error(this, "Unparsable format for element 'fieldWidth' - '" + fieldWidth +
					"': " + exc.getMessage(), exc);
			}

			try {
				newInstance.setEnabled(Boolean.valueOf(enabled).booleanValue());
			}
			catch (Exception exc) {
				Msg.error(this, "Unparsable format for element 'enabled' - '" + enabled + "': " +
					exc.getMessage(), exc);
			}

			row.addField(newInstance);
		}
		return row;
	}

	private FieldFactory getNewFieldFactoryInstance(FieldFactory factoryPrototype, String text) {
		if (factoryPrototype != null) {
			return factoryPrototype.newInstance(this, formatMgr.getFormatHighlightProvider(),
				formatMgr.getDisplayOptions(), formatMgr.getFieldOptions());
		}

		return new SpacerFieldFactory(text, this, formatMgr.getFormatHighlightProvider(),
			formatMgr.getDisplayOptions(), formatMgr.getFieldOptions());
	}

	/**
	 * Adds all unused fields to this model.
	 */
	public void addAllFactories() {
		FieldFactory[] unusedFactorys = getUnusedFactories();
		for (FieldFactory unusedFactory : unusedFactorys) {
			addFactory(unusedFactory, 0, 0);
		}
		findWidth();
		formatMgr.modelChanged(this);
	}

	/**
	 * Returns a list of unused valid fields for this model 
	 * @return a list of unused valid fields for this model
	 */
	public FieldFactory[] getUnusedFactories() {
		List<FieldFactory> list = new ArrayList<>(Arrays.asList(factories));
		for (int i = 0; i < rows.size(); i++) {
			Row row = rows.get(i);
			FieldFactory[] rowFactorys = row.getFactorys();
			for (FieldFactory rowFactory : rowFactorys) {
				Class<?> c = rowFactory.getClass();
				for (int k = 0; k < list.size(); k++) {
					if (c.equals(list.get(k).getClass())) {
						list.remove(k);
						break;
					}
				}
			}
		}
		return list.toArray(new FieldFactory[list.size()]);
	}

	public FieldFactory[] getAllFactories() {
		List<FieldFactory> arrayBackedList = new ArrayList<>(Arrays.asList(factories));
		Collections.sort(arrayBackedList, COMPARATOR);
		return arrayBackedList.toArray(new FieldFactory[factories.length]);  // new array
	}

	/**
	 * Removes all fields from this model.
	 */
	public void removeAllFactories() {
		for (int i = 0; i < rows.size(); i++) {
			Row row = rows.get(i);
			while (row.size() > 0) {
				row.removeField(0);
			}
		}
		findWidth();
		formatMgr.modelChanged(this);

	}

	/**
	 * Notifies that the options have changed.
	 * @param options the Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	public void optionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		for (Row row : rows) {
			row.optionsChanged(options, optionName, oldValue, newValue);
		}
	}

//==================================================================================================
//Inner Classes 
//==================================================================================================

	private static class FieldFactoryComparator implements Comparator<FieldFactory> {
		@Override
		public int compare(FieldFactory f1, FieldFactory f2) {
			return f1.getFieldName().compareTo(f2.getFieldName());
		}
	}

}

class Row {
	List<FieldFactory> fields = new ArrayList<>();
	int width = 0;

	public void insertField(FieldFactory ff, int colIndex) {
		fields.add(colIndex, ff);
		layoutFields();
	}

	public void optionsChanged(Options options, String name, Object oldValue, Object newValue) {
		for (FieldFactory factory : fields) {
			factory.optionsChanged(options, name, oldValue, newValue);
		}
	}

	public void servicesChanged() {
		for (int i = 0; i < fields.size(); i++) {
			FieldFactory factory = fields.get(i);
			factory.servicesChanged();
		}
	}

	public void addField(FieldFactory ff) {
		fields.add(ff);
		layoutFields();
	}

	public void layoutFields() {
		width = 0;
		for (int i = 0; i < fields.size(); i++) {
			FieldFactory factory = fields.get(i);
			factory.setStartX(width);
			width += factory.getWidth();
		}
	}

	public RowLayout getLayout(int index, ProxyObj<?> proxy, int id) {
		ArrayList<Field> temp = new ArrayList<>(20);
		int varWidth = 0;
		for (int i = 0; i < fields.size(); i++) {
			FieldFactory ff = fields.get(i);
			ListingField f = null;
			try {
				f = ff.getField(proxy, varWidth);
			}
			catch (Throwable t) {
				f = new ErrorListingField(ff, proxy, varWidth, t);
			}
			if (f != null) {
				if (f.getWidth() != ff.getWidth()) {
					varWidth += f.getWidth() - ff.getWidth();
				}
				temp.add(f);
			}
		}
		if (temp.size() > 0) {
			Field[] rowFields = new Field[temp.size()];
			rowFields = temp.toArray(rowFields);
			temp.clear();
			return new RowLayout(rowFields, id);
		}
		return null;
	}

	public FieldFactory[] getFactorys() {
		FieldFactory[] ffs = new FieldFactory[fields.size()];
		return fields.toArray(ffs);
	}

	public int size() {
		return fields.size();
	}

	public FieldFactory removeField(int colIndex) {
		FieldFactory ff = fields.remove(colIndex);
		layoutFields();
		return ff;
	}

	@Override
	public String toString() {
		return fields.toString();
	}
}
