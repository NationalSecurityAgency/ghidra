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
package ghidra.app.plugin.core.function.tags;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Model that backs a {@link FunctionTagTable}
 */
public class FunctionTagTableModel extends ThreadedTableModel<FunctionTag, List<FunctionTag>> {

	/** The list of tags to display in the table */
	private List<FunctionTag> tags = new ArrayList<>();
	private Program program;
	
	/**
	 * Constructor
	 * 
	 * @param modelName the name of this table model
	 * @param serviceProvider the service provider
	 */
	protected FunctionTagTableModel(String modelName, ServiceProvider serviceProvider) {
		super(modelName, serviceProvider);
	}
	
	public void setProgram(Program program) {
		this.program = program;
	}

	@Override
	protected void doLoad(Accumulator<FunctionTag> accumulator, TaskMonitor monitor)
			throws CancelledException {
		accumulator.addAll(tags);
		fireTableDataChanged();
	}

	@Override
	protected TableColumnDescriptor<FunctionTag> createTableColumnDescriptor() {
		TableColumnDescriptor<FunctionTag> descriptor = new TableColumnDescriptor<>();
		
		descriptor.addVisibleColumn(new FunctionTagNameColumn());		
		descriptor.addVisibleColumn(new FunctionTagCountColumn());

		return descriptor;
	}
	
	@Override
	public List<FunctionTag> getDataSource() {
		return tags;
	}
	
	/**
	 * Adds a function tag to the table. If a tag with the same name is already
	 * present in the table, does nothing.
	 * 
	 * @param tag the function tag to add
	 */
	public void addTag(FunctionTag tag) {		
		Optional<FunctionTag> existingTag = tags.stream()
												.filter(t -> t.getName().equals(tag.getName()))
												.findAny();
		if (existingTag.isPresent()) {
			tags.remove(existingTag.get());
		}
		
		tags.add(tag);
		fireTableDataChanged();
	}
	
	/**
	 * Removes all function tags from the model
	 */
	public void clear() {
		tags.clear();
		fireTableDataChanged();
	}
		
	/**
	 * Returns all function tags in the model
	 * 
	 * @return all function tags
	 */
	public List<FunctionTag> getTags() {
		return tags;
	}
	
	/**
	 * Returns the {@link FunctionTag} object with a given name
	 * 
	 * @param name the tag name to search for
	 * @return the function tag
	 */
	public FunctionTag getTag(String name) {
		Optional<FunctionTag> tag = tags.stream()
										.filter(t -> t.getName().equals(name))
										.findAny();
		if (tag.isPresent()) {
			return tag.get();
		}
		
		return null;
	}
	
	/**
	 * Returns true if a function tag with a given name is in the model
	 * 
	 * @param name the tag name to search fo
	 * @return true if the tag exists in the model
	 */
	public boolean isTagInModel(String name) {
		Optional<FunctionTag> tag = tags.stream()
										.filter(t -> t.getName().equals(name))
										.findAny();
		return tag.isPresent();
	}
	
	/**
	 * Table column that displays a count of the number of times a function tag has been
	 * applied to a function (in the selected program)
	 */
	private class FunctionTagCountColumn extends AbstractDynamicTableColumnStub<FunctionTag, Integer> {

		@Override
		public String getColumnDisplayName(Settings settings) {
			return " ";  // don't display any name, but need it to be at least one space
			             // wide so the correct space is allocated to the header
		}
		
		@Override
		public String getColumnName() {
			return "Count";
		}
		
		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
		
		@Override
		public Integer getValue(FunctionTag rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			int count = 0;
			
			if (program == null) {
				return 0;
			}
			
			FunctionIterator iter = program.getFunctionManager().getFunctions(true);
			while (iter.hasNext()) {
				Function f = iter.next();
				Optional<FunctionTag> foundTag = f.getTags()
												  .stream()
												  .filter(t -> t.getName().equals(rowObject.getName()))
												  .findAny();
				if (foundTag.isPresent()) {
					count++;
				}
			}
			return count;
		}
	}
	
	/**
	 * Table column that displays the name of a function tag
	 */
	private class FunctionTagNameColumn extends AbstractDynamicTableColumnStub<FunctionTag, String> {
		
		@Override
		public String getColumnName() {
			return "Name";
		}
		
		@Override
		public String getValue(FunctionTag rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getName();
		}
	}
}
