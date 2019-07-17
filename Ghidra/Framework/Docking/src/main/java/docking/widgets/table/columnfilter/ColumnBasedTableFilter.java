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
package docking.widgets.table.columnfilter;

import java.util.*;
import java.util.stream.Collectors;

import org.jdom.Element;

import docking.widgets.table.*;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.TableFilterContext;
import ghidra.framework.options.SaveState;

/**
 * A {@link TableFilter}  that filters based on column values
 *
 * <P>This class maintains a list of {@link ColumnConstraintSet} objects that are logically combined
 * to determine if the overall filter accepts the given row object. Each ColumnConstraint has an
 * associated {@link LogicOperation} which determines how its result are combined with the constraint
 * set before it. (The first ConstraintSets LogicOperation is not used).  AND operations have higher
 * precedence than the OR operations.
 *
 * @param <R> the row type of the table
 */
public class ColumnBasedTableFilter<R> implements TableFilter<R> {
	private final RowObjectTableModel<R> model;

	private String name;
	private List<ColumnConstraintSet<R, ?>> constraintSets = new ArrayList<>();
	private TableFilterContext tableFilterContext = this::getDataSource;
	private OrList orList;

	/**
	 * Constructs a new empty ColumnBasedTableFilter
	 *
	 * @param model the table model
	 */
	public ColumnBasedTableFilter(RowObjectTableModel<R> model) {
		this.model = model;
		this.name = null;
	}

	public ColumnBasedTableFilter<R> copy() {
		ColumnBasedTableFilter<R> newFilter = new ColumnBasedTableFilter<>(model);
		newFilter.constraintSets.addAll(constraintSets);
		newFilter.name = name;
		return newFilter;
	}

	@Override
	public boolean acceptsRow(R rowObject) {
		if (orList == null) {
			orList = buildOrList();
		}
		return orList.acceptsRow(rowObject);
	}

	/**
	 * Organizes the list of constraint sets into groups that will first be "ANDed" together, then
	 * those "AND" groups will be "ORed" together.
	 * @return the list of "AND" groups that will be "ORed" together.
	 */
	private OrList buildOrList() {
		OrList localOrList = new OrList();
		if (constraintSets.isEmpty()) {
			return localOrList;
		}

		AndList currentAndList = new AndList();
		localOrList.addAndList(currentAndList);
		currentAndList.addConstraintSet(constraintSets.get(0));

		for (int i = 1; i < constraintSets.size(); i++) {
			ColumnConstraintSet<R, ?> columnConstraintSet = constraintSets.get(i);
			// if the logical operation is OR, start a new list of ANDed sets.
			if (columnConstraintSet.getLogicOperation() == LogicOperation.OR) {
				currentAndList = new AndList();
				localOrList.addAndList(currentAndList);
			}
			currentAndList.addConstraintSet(columnConstraintSet);
		}
		return localOrList;
	}

	/**
	 * Returns the name of this filter.
	 *
	 * <P>Names are used for saving filters, so unless they are saved they typically don't have a name.
	 *
	 * @return the name of this filter.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Sets the name of this filter.
	 *
	 * @param name the new name for this filter.
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Adds a new constraintSet to this ColumnBasedTableFilter
	 *
	 * @param logicalOp The logic operation (AND or OR) for how the new ConstraintSet's result will be
	 * combined with the previous ConstraintSet's result.
	 * @param columnIndex the model index of the column whose values must past the given constraint filters.
	 * @param constraints a list of ColumnConstraints where at least one must pass for the constraintSet to pass.
	 */
	public <T> void addConstraintSet(LogicOperation logicalOp, int columnIndex,
			List<ColumnConstraint<T>> constraints) {
		constraintSets.add(new ColumnConstraintSet<>(model, columnIndex, constraints, logicalOp));
		orList = null; // the current orList is now invalid, this will cause it to be rebuilt when needed.
	}

	@Override
	public boolean isSubFilterOf(TableFilter<?> tableFilter) {
		return equals(tableFilter);
	}

	@Override
	public boolean hasColumnFilter(int columnModelIndex) {
		for (ColumnConstraintSet<?, ?> constraintSet : constraintSets) {
			if (constraintSet.getColumnModelIndex() == columnModelIndex) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Return the list of ConstraintSets in this TableFilter
	 *
	 * @return the list of ConstraintSets in this TableFilter
	 */
	public List<ColumnConstraintSet<R, ?>> getConstraintSets() {
		return constraintSets;
	}

	/**
	 * Serializes this filter into a SaveState object.
	 *
	 * @return the SaveState serialized version of this filter.
	 */
	public SaveState save() {
		SaveState saveState = new SaveState("COLUMN_TABLE_FILTER");
		saveState.putString("NAME", name);
		saveState.putInt("COLUMN_FILTER_COUNT", constraintSets.size());
		for (int i = 0; i < constraintSets.size(); i++) {
			ColumnConstraintSet<R, ?> constraintSet = constraintSets.get(i);
			SaveState save = constraintSet.save();
			saveState.putXmlElement("COLUMN_FILTER_" + i, save.saveToXml());
		}
		return saveState;
	}

	/**
	 * Restore this filter from the given saveState.
	 *
	 * @param saveState that contains the serialized filter data
	 * @param dataSource the Table's DataSource which some objects might need to restore themselves.
	 */
	public <T> void restore(SaveState saveState, Object dataSource) {
		constraintSets.clear();
		this.name = saveState.getString("NAME", "");
		int columnCount = saveState.getInt("COLUMN_FILTER_COUNT", 0);
		for (int i = 0; i < columnCount; i++) {
			Element xmlElement = saveState.getXmlElement("COLUMN_FILTER_" + i);
			SaveState childState = new SaveState(xmlElement);
			constraintSets.add(new ColumnConstraintSet<R, T>(model, childState, dataSource));
		}
	}

	/**
	 * Returns an HTML description of this filter.
	 * <P>
	 * Note: the HTML string returned does NOT start with the HTML tag so that it can be combined
	 * with other text.
	 *
	 * @return  an HTML description of this filter.
	 */
	public String getHtmlRepresentation() {
		return getHtmlRepresentation(constraintSets);
	}

	/**
	 * Return a tooltip  that describes the effect of this filter for a specific filter.
	 *
	 * @param columnIndex the model index of the column to get a filter description of.
	 * @return a tooltip that describes this filter for a specific column.
	 */
	public String getToolTip(int columnIndex) {
		//@formatter:off
		List<ColumnConstraintSet<R, ?>> filtered =
			constraintSets.stream()
				.filter(cf -> cf.getColumnModelIndex() == columnIndex)
				.collect(Collectors.toList());
		//@formatter:on

		if (filtered.isEmpty()) {
			return null;
		}
		return getHtmlRepresentation(filtered);
	}

	// The html will format something like:
	//
	//       Name Contains    "aa"
	//        or  Contains    "bb"
	//        or  Starts With "foo"
	//  And  Path Contains     "Bar"
	//  And  Size At Most      1000
	//
	private String getHtmlRepresentation(List<ColumnConstraintSet<R, ?>> filters) {
		StringBuilder buf = new StringBuilder();
		buf.append("<table valign=top cellspacing=5 cellpadding=0 >");
		buf.append("<tr>");
		// The first row has an empty first column
		// so that additional rows can display an "AND"
		buf.append("<td></td><td>");
		buf.append(filters.get(0).getHtmlRepresentation());
		buf.append("</td></tr>");
		for (int i = 1; i < filters.size(); i++) {
			buf.append("<tr><td style=\"color:gray\"> " + filters.get(i).getLogicOperation() +
				"&nbsp;</td><td>");
			buf.append(filters.get(i).getHtmlRepresentation());
			buf.append("</td></tr>");
		}
		buf.append("</table>");
		buf.append("</html>");

		return buf.toString();
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public int hashCode() {
		return Objects.hash(model.getClass(), name, constraintSets);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ColumnBasedTableFilter<?> other = (ColumnBasedTableFilter<?>) obj;

		if (model != other.model) {
			return false;
		}
		if (!Objects.equals(name, other.name)) {
			return false;
		}
		return Objects.equals(constraintSets, other.constraintSets);
	}

	/**
	 * Checks if the given {@link ColumnBasedTableFilter} is the same as this one except for
	 * its name.
	 * @param other the other filter to check for equivalence.
	 * @return true if the other filter is the same as this one except for its name
	 */
	public boolean isEquivalent(ColumnBasedTableFilter<?> other) {
		if (other == null) {
			return false;
		}
		if (model != other.model) {
			return false;
		}
		// Deliberately not using name in equals, so that saved filters can be compared to generated filters
		return Objects.equals(constraintSets, other.constraintSets);

	}

	/**
	 * Gets the table's DataSource (if it has one). Only table models
	 * that extends {@link GDynamicColumnTableModel} can have a data source.
	 * @return the table's data source or null if the table doesn't have one.
	 */
	private Object getDataSource() {
		if (model instanceof GDynamicColumnTableModel) {
			return ((GDynamicColumnTableModel<?, ?>) model).getDataSource();
		}
		return null;
	}

	private class AndList {
		private List<ColumnConstraintSet<R, ?>> list = new ArrayList<>();

		void addConstraintSet(ColumnConstraintSet<R, ?> constraintSet) {
			list.add(constraintSet);
		}

		boolean acceptsRow(R rowObject) {
			for (ColumnConstraintSet<R, ?> constraintSet : list) {
				if (!constraintSet.accepts(rowObject, tableFilterContext)) {
					return false;
				}
			}
			return true;
		}
	}

	private class OrList {
		private List<AndList> list = new ArrayList<>();

		void addAndList(AndList andList) {
			list.add(andList);
		}

		boolean acceptsRow(R rowObject) {
			for (AndList andList : list) {
				if (andList.acceptsRow(rowObject)) {
					return true;
				}
			}
			return false;
		}
	}

	/**
	 * Returns true if this filter has been saved (i.e. has a name)
	 * @return true if this filter has been saved (i.e. has a name)
	 */
	public boolean isSaved() {
		return name != null;
	}
}
