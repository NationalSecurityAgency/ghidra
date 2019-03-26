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
package ghidra.app.plugin.core.strings;

import docking.widgets.table.constraint.ColumnData;
import docking.widgets.table.constraint.TableFilterContext;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.DoNothingColumnConstraintEditor;
import ghidra.program.model.data.StringDataInstance;

/**
 * Tests if a string data instance has a translated value available
 */
public class HasTranslationValueColumnConstraint extends StringDataInstanceColumnConstraint {

	@Override
	public boolean accepts(StringDataInstance value, TableFilterContext context) {
		return value.getTranslatedValue() != null && !value.getTranslatedValue().isEmpty();
	}

	@Override
	public String getName() {
		return "Has Translated Value";
	}

	@Override
	public ColumnConstraintEditor<StringDataInstance> getEditor(
			ColumnData<StringDataInstance> columnDataSource) {
		return new DoNothingColumnConstraintEditor<>(this);
	}
}
