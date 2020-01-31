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
package ghidra.util.table.column;

import java.util.Date;

import javax.swing.JLabel;
import javax.swing.table.TableCellRenderer;

import docking.widgets.table.*;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.dialog.ColumnFilterDialog;
import ghidra.docking.settings.Settings;
import ghidra.util.exception.AssertException;

/**
 * An interface for the {@link DynamicTableColumn}.  This allows the filtering system to stay
 * in sync with the rendering system by using the display text to filter.
 * 
 * <P>Table filtering in {@link GTable}s typically works with the following setup:
 * <OL>
 * 	<LI>The table has a text field that allows for quick filtering across all <B>visible</B> 
 *      columns.  The specifics of how the text filter works are defined by the 
 *      {@link RowFilterTransformer}, which is controlled by the user via the button at the right
 *      of the filter field.  (In the absence of this button, filters are typically a 'contains'
 *      filter.)
 *      
 *      <P>The default transformer turns items to strings by, in order,:
 *      <OL>
 *      	<LI>checking the the <b>column</b> renderer's 
 *      		{@link #getFilterString(Object, Settings)},if a column renderer is installed
 *      	</LI>
 *      	<LI>checking to see if the column value is an instance of {@link DisplayStringProvider}
 *      	</LI>
 *      	<LI>checking to see if the column value is a {@link JLabel}
 *      	</LI>
 *      	<LI>calling <code>toString()</code> on the object
 *      	</LI>
 *      </OL>
 *  </LI>
 *  <LI>
 *  	The table has the ability to perform advanced filtering based upon specific columns.  Each
 *  	column's type is used to find dynamically discovered {@link ColumnConstraint}s.  These
 *  	constraints dictate how a given column can be filtered.  The user will create filters
 *  	using these constraints in the {@link ColumnFilterDialog} by pressing the 
 *  	button at the far right of the filter text field.
 *  	
 *  	<P>The way the constraints are used in the filtering system, in conjunction with 
 *  	   this renderer, is defined by the {@link ColumnConstraintFilterMode} via
 *  	   {@link #getColumnConstraintFilterMode()}.
 *  </LI>
 *  <LI>
 *  	Any custom filters, defined by individual clients (this is outside the scope of the 
 *  	default filtering system)
 *  </LI>
 * </OL>
 * 
 * <P><B>Note: The default filtering behavior of this class is to only filter on the aforementioned
 *       filter text field.  That is, column constraints will not be enabled by default. To
 *       change this, change the value returned by {@link #getColumnConstraintFilterMode()}.</B>
 * 
 * @param <T> the column type
 */
public interface GColumnRenderer<T> extends TableCellRenderer {

	/**
	 * An enum that signals how the advanced column filtering should work.   (This does not affect
	 * the normal table filtering that happens via the filter text field).
	 */
	public enum ColumnConstraintFilterMode {
		//@formatter:off
		
		/** Use only {@link GColumnRenderer#getFilterString(Object, Settings)} value; no constraints */
		ALLOW_RENDERER_STRING_FILTER_ONLY,
		
		/** Use only column constraints when filtering */
		ALLOW_CONSTRAINTS_FILTER_ONLY,
		
		/** Use both the rendered filter String and any found column constraints */
		ALLOW_ALL_FILTERS,
		//@formatter:on
	}

	/**
	 * Returns the current mode of how column constraints will be used to filter this column
	 * 
	 * <P>This method is typically not overridden.  This is only needed in rare cases, such as
	 * when a column uses a renderer, but does *not* want this column to be filtered using
	 * a String column constraint.   Or, if a column uses a renderer and wants that text to 
	 * be available as a filter, along with any other column constraints.
	 * @return the mode
	 */
	public default ColumnConstraintFilterMode getColumnConstraintFilterMode() {
		return ColumnConstraintFilterMode.ALLOW_RENDERER_STRING_FILTER_ONLY;
	}

	/**
	 * Returns a string that is suitable for use when filtering.  The returned String should 
	 * be an unformatted (e.g., no HTML markup, icons, etc) version of what is on the screen.
	 * If the String returned here does not match what the user sees (that which is rendered),
	 * then the filtering action may confuse the user.
	 *   
	 * @param t the column type instance
	 * @param settings any settings the converter may need to convert the type
	 * @return the unformatted String version of what is rendered in the table cell on screen
	 */
	public String getFilterString(T t, Settings settings);

	/**
	 * A convenience method for primitive-based/wrapper-based renderers to signal that they
	 * should not be using text to filter.  
	 * 
	 * <P>The basic wrapper types, like Number, and some others, like {@link Date}, have special
	 * built-in filtering capabilities.  Columns whose column type is one of the wrapper classes
	 * will not have their {@link #getFilterString(Object, Settings)} methods called.  They can
	 * stub out those methods by throwing the exception returned by this method.
	 * 
	 * @return the new exception
	 * @see AbstractWrapperTypeColumnRenderer
	 */
	public default AssertException createWrapperTypeException() {
		return new AssertException("Wrapper column type not expected to be filtered as a String");
	}
}
