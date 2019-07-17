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
package ghidra.app.tablechooser;

import java.util.List;

import utilities.util.reflection.ReflectionUtilities;

/**
 * A base implementation of {@link ColumnDisplay} that knows how to figure out the column 
 * type dynamically.  
 *
 * @param <COLUMN_TYPE> the column type
 */
public abstract class AbstractColumnDisplay<COLUMN_TYPE> implements ColumnDisplay<COLUMN_TYPE> {

	@Override
	@SuppressWarnings("unchecked")
	public Class<COLUMN_TYPE> getColumnClass() {

		@SuppressWarnings("rawtypes")
		Class<? extends AbstractColumnDisplay> implementationClass = getClass();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(AbstractColumnDisplay.class, implementationClass);
		return (Class<COLUMN_TYPE>) typeArguments.get(0);
	}

}
