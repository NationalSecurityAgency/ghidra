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
package ghidra.program.model;

import java.util.List;

import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * A basic {@link Category} test double for tests to extend
 */
public class TestDoubleCategory implements Category {

	private String categoryName;

	public TestDoubleCategory(String name) {
		this.categoryName = name;
	}

	@Override
	public String getName() {
		return categoryName;
	}

	@Override
	public int compareTo(Category o) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) throws DuplicateNameException, InvalidNameException {
		this.categoryName = name;
	}

	@Override
	public Category[] getCategories() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType[] getDataTypes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DataType> getDataTypesByBaseName(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType addDataType(DataType dt, DataTypeConflictHandler handler) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getCategory(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CategoryPath getCategoryPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType getDataType(String name) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category createCategory(String name) throws InvalidNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeCategory(String name, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeEmptyCategory(String name, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void moveCategory(Category category, TaskMonitor monitor) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category copyCategory(Category category, DataTypeConflictHandler handler,
			TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getParent() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isRoot() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getCategoryPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Category getRoot() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void moveDataType(DataType type, DataTypeConflictHandler handler)
			throws DataTypeDependencyException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean remove(DataType type, TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getID() {
		throw new UnsupportedOperationException();
	}
}
