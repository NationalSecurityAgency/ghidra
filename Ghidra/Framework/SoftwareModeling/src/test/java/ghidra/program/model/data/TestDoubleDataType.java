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
package ghidra.program.model.data;

import java.net.URL;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

/**
 * A stub of the {@link DataType} interface.  This can be used to supply a test values 
 * or to spy on system internals by overriding methods as needed.
 */
public class TestDoubleDataType implements DataType {

	private UniversalID id;
	private String name;

	public TestDoubleDataType(String name) {
		this.name = name;
		this.id = UniversalIdGenerator.nextID();
	}

	@Override
	public String toString() {
		return name;
	}

	@Override
	public boolean hasLanguageDependantLength() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isNotYetDefined() {
		throw new UnsupportedOperationException();
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Settings getDefaultSettings() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		throw new UnsupportedOperationException();
	}

	@Override
	public CategoryPath getCategoryPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypePath getDataTypePath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataTypeManager getDataTypeManager() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDisplayName() {
		return "Test double data type '" + getName() + "'";
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getPathName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String name) throws InvalidNameException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNameAndCategory(CategoryPath path, String name)
			throws InvalidNameException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getMnemonic(Settings settings) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getLength() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isZeroLength() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDescription() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDescription(String description) throws UnsupportedOperationException {
		throw new UnsupportedOperationException();
	}

	@Override
	public URL getDocs() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultLabelPrefix() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultAbbreviatedLabelPrefix() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
			DataTypeDisplayOptions options, int offcutOffset) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDeleted() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeSizeChanged(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeAlignmentChanged(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeDeleted(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDefaultSettings(Settings settings) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addParent(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeParent(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataType[] getParents() {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getAlignment() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean dependsOn(DataType dt) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceArchive getSourceArchive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSourceArchive(SourceArchive archive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastChangeTime() {
		throw new UnsupportedOperationException();
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		throw new UnsupportedOperationException();
	}

	@Override
	public UniversalID getUniversalID() {
		return id;
	}

	@Override
	public void replaceWith(DataType dataType) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		throw new UnsupportedOperationException();
	}

	@Override
	public DataOrganization getDataOrganization() {
		throw new UnsupportedOperationException();
	}
}
