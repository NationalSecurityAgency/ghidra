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
package ghidra.features.base.replace.handler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.RenameCategoryQuickFix;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalConsumer;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for datatype category names.
 */
public class DatatypeCategorySearchAndReplaceHandler extends SearchAndReplaceHandler {

	public DatatypeCategorySearchAndReplaceHandler() {
		addType(new SearchType(this, "Datatype Categories",
			"Search and replace datatype category names"));
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		int categoryCount = program.getDataTypeManager().getCategoryCount();
		monitor.initialize(categoryCount, "Searching Datatype categories...");

		Pattern pattern = query.getSearchPattern();

		DataTypeManager dtm = program.getDataTypeManager();
		Category rootCategory = dtm.getRootCategory();

		visitRecursively(rootCategory, category -> {
			monitor.increment();
			Matcher matcher = pattern.matcher(category.getName());
			if (matcher.find()) {
				String newName = matcher.replaceAll(query.getReplacementText());
				RenameCategoryQuickFix item = new RenameCategoryQuickFix(program, category, newName);
				accumulator.add(item);
				if (accumulator.size() >= query.getSearchLimit()) {
					return;
				}
			}
		});

	}

	private void visitRecursively(Category category,
			ExceptionalConsumer<Category, CancelledException> callback) throws CancelledException {

		callback.accept(category);
		Category[] categories = category.getCategories();
		for (Category childCategory : categories) {
			visitRecursively(childCategory, callback);
		}
	}
}
