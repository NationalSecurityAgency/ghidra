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
package docking.widgets.table;

import java.util.Arrays;
import java.util.List;

import javax.swing.table.TableModel;

/**
 * An interface to mark that the given model uses a single object to represent each row in the
 * table.
 *
 * @param <T> The type of the row object.
 */
public interface RowObjectTableModel<T> extends TableModel {

	public static TableModel unwrap(TableModel m) {

		TableModel model = m;
		while (model instanceof TableModelWrapper) {
			model = ((TableModelWrapper<?>) model).getWrappedModel();
		}
		return model;
	}

	/**
	 * Returns the name of this model
	 * @return the name of this model
	 */
	public String getName();

	/**
	 * Returns the row object for the given row.  This is the row in the UI.  For models that
	 * know how to filter, the model row value will not match the view row value.  For
	 * non-filtering models the view and model rows will always be the same.
	 *
	 * @param viewRow the row for which to return a row object.
	 * @return the row object
	 */
	public T getRowObject(int viewRow);

	/**
	 * Returns the row number for the given object.
	 * <p>
	 * <b>Note: the index returned is always the 'view' index.  For non-filtering table models,
	 * the 'view' and the 'model' index are the same.  However, for filtering table models,
	 * the 'view' may be a subset of the 'model' index.   Thus, it is possible, if this model
	 * is a filtering model, that the given <code>t</code> may not have a row value for the current
	 * state of the model (i.e., when the model is filtered in the view.  If you really need to
	 * get the model index in such a situation, see {@link RowObjectFilterModel}.
	 * </b>
	 *
	 * @param t the object
	 * @return the row number
	 */
	public int getRowIndex(T t);

	/**
	 * Implementors should return the current data of the model.  For models that support
	 * filtering, this will be the filtered version of the data.  Furthermore, the data should be
	 * the underlying data and not a copy, as this method will potentially sort the given data.
	 * <p>
	 * For those subclasses using an array, you may use the <code>Arrays</code> class to create
	 * a list backed by the array ({@link Arrays#asList(Object...)}).
	 * @return the model data.
	 */
	public List<T> getModelData();

	/**
	 * Implementors are expected to return a value at the given column index for the specified
	 * row object.  This is essentially a more specific version of the
	 * {@link TableModel#getValueAt(int, int)} that allows this class's comparator objects to work.
	 *
	 * @param t The object that represents a given row.
	 * @param columnIndex The column index for which a value is requested.
	 * @return a value at the given column index for the specified row object.
	 */
	public Object getColumnValueForRow(T t, int columnIndex);

	/**
	 * Sends an event to all listeners that all the data inside of this model may have changed.
	 */
	public void fireTableDataChanged();
}
