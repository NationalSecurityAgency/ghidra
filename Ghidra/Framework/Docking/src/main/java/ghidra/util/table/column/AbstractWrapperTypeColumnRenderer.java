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

import ghidra.docking.settings.Settings;

/**
 * A convenience interface of {@link GColumnRenderer} for primitive-based/wrapper-based 
 * renderers.   This class implements {@link #getFilterString(Object, Settings)} to 
 * throw an exception, as it should not be called for primitive types.
 * 
 * <P>The basic wrapper types, like Number, and some others, like {@link Date}, have special
 * built-in filtering capabilities.  Columns whose column type is one of the wrapper classes
 * will not have their {@link #getFilterString(Object, Settings)} methods called.  They can
 * stub out those methods by throwing the exception returned by this method.
 *
 * @param <T> the column type
 */
public interface AbstractWrapperTypeColumnRenderer<T> extends GColumnRenderer<T> {

	// Overridden to only allow the constraint filtering mechanism.
	@Override
	public default ColumnConstraintFilterMode getColumnConstraintFilterMode() {
		return ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY;
	}

	@Override
	public default String getFilterString(T t, Settings settings) {
		// we don't use String values for filtering wrapper types
		throw createWrapperTypeException();
	}
}
