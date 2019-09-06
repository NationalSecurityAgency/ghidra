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
package ghidra.app.plugin.core.datamgr.util;

import java.net.URL;
import java.util.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.datamgr.archive.SourceArchive;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeComparator;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;

public class DataTypeUtilsTest {

	@Test
	public void testDataSearch() throws Exception {

		String[] TEST_DATA =
			{ "10th", "1st", "2nd", "3rd", "4th", "5th", "6th", "7th", "8th", "9th", "a", "AAA",
				"AAAS", "Aarhus", "azure", "b", "babbitt", "babble", "Babcock", "bromide",
				"bromine", "Bromley", "Yves", "Yvette", "YWCA", "z", "Zachary", "zag", "zagging" };

		final List<DataType> data = new ArrayList<>();

		for (String element : TEST_DATA) {
			data.add(new DataTypeDummy(element));
		}

		// sort them how our data will be sorted
		Collections.sort(data, new DataTypeComparator());
		List<DataType> finalData = Collections.unmodifiableList(data);

		// a
		runDataSearchForString("a", data, finalData.subList(10, 15));

		// aa
		runDataSearchForString("AA", data, finalData.subList(11, 14));

		// aaa
		runDataSearchForString("aaa", data, finalData.subList(11, 13));

		// 1
		runDataSearchForString("1", data, finalData.subList(0, 2));

		// 1s
		runDataSearchForString("1s", data, finalData.subList(1, 2));

		// 8
		runDataSearchForString("8", data, finalData.subList(8, 9));

		// 8th
		runDataSearchForString("8th", data, finalData.subList(8, 9));

		// no match
		List<DataType> emptyList = Collections.emptyList();
		runDataSearchForString("8thz", data, emptyList);

		// b
		runDataSearchForString("b", data, finalData.subList(15, 22));

		// ba
		runDataSearchForString("ba", data, finalData.subList(16, 19));

		// bab (same as ba)    
		runDataSearchForString("bab", data, finalData.subList(16, 19));

		// br
		runDataSearchForString("br", data, finalData.subList(19, 22));

		// Y        
		runDataSearchForString("Y", data, finalData.subList(22, 25));

		// yv
		runDataSearchForString("Yv", data, finalData.subList(22, 24));

		// z
		runDataSearchForString("Z", data, finalData.subList(25, 29));

		// za
		runDataSearchForString("zA", data, finalData.subList(26, 29));

		// zag
		runDataSearchForString("zag", data, finalData.subList(27, 29));
	}

	private void runDataSearchForString(String text, List<DataType> sourceData,
			List<DataType> expectedMatches) {

		char endChar = '\uffff';
		List<DataType> actualMatches =
			DataTypeUtils.getMatchingSubList(text, text + endChar, sourceData);

		AbstractGenericTest.assertListEqualUnordered(null, expectedMatches, actualMatches);
	}

	private class DataTypeDummy implements DataType {

		String wrappedString;
		UniversalID id;

		DataTypeDummy(String wrappedString) {
			this.wrappedString = wrappedString;
			id = UniversalIdGenerator.nextID();
		}

		@Override
		public String toString() {
			return wrappedString;
		}

		@Override
		public DataTypeManager getDataTypeManager() {
			return null;
		}

		@Override
		public DataOrganization getDataOrganization() {
			throw new UnsupportedOperationException();
		}

		@Override
		public String getDisplayName() {
			return "This is a wrapper for: " + wrappedString;
		}

		@Override
		public String getName() {
			return wrappedString;
		}

		@Override
		public boolean isNotYetDefined() {
			return false;
		}

		@Override
		public boolean isDynamicallySized() {
			return false;
		}

		@Override
		public String getPathName() {
			return "/" + wrappedString;
		}

		@Override
		public SettingsDefinition[] getSettingsDefinitions() {
			return null;
		}

		@Override
		public Settings getDefaultSettings() {
			return null;
		}

		@Override
		public CategoryPath getCategoryPath() {
			return null;
		}

		@Override
		public DataTypePath getDataTypePath() {
			return null;
		}

		@Override
		public void setCategoryPath(CategoryPath path) throws DuplicateNameException {
			// no-op
		}

		@Override
		public void setName(String name) throws InvalidNameException, DuplicateNameException {
			// no-op
		}

		@Override
		public void setNameAndCategory(CategoryPath path, String name)
				throws InvalidNameException, DuplicateNameException {
			// no-op
		}

		@Override
		public String getMnemonic(Settings settings) {
			return null;
		}

		@Override
		public int getLength() {
			return 0;
		}

		@Override
		public String getDescription() {
			return null;
		}

		@Override
		public void setDescription(String description) throws UnsupportedOperationException {
			throw new UnsupportedOperationException(
				getClass().getName() + " doesn't allow the description to be changed.");
		}

		@Override
		public URL getDocs() {
			return null;
		}

		@Override
		public Object getValue(MemBuffer buf, Settings settings, int length) {
			return null;
		}

		@Override
		public Class<?> getValueClass(Settings settings) {
			return null;
		}

		@Override
		public String getRepresentation(MemBuffer buf, Settings settings, int length) {
			return null;
		}

		@Override
		public boolean isDeleted() {
			return false;
		}

		@Override
		public boolean isEquivalent(DataType dt) {
			return false;
		}

		@Override
		public void dataTypeSizeChanged(DataType dt) {
			// no-op
		}

		@Override
		public void dataTypeDeleted(DataType dt) {
			// no-op
		}

		@Override
		public void dataTypeReplaced(DataType oldDt, DataType newDt) {
			// no-op
		}

		@Override
		public void setDefaultSettings(Settings settings) {
			// no-op
		}

		@Override
		public void addParent(DataType dt) {
			// no-op
		}

		@Override
		public void removeParent(DataType dt) {
			// no-op
		}

		@Override
		public void dataTypeNameChanged(DataType dt, String oldName) {
			// no-op
		}

		@Override
		public DataType[] getParents() {
			return null;
		}

		@Override
		public boolean dependsOn(DataType dt) {
			return false;
		}

		@Override
		public String getDefaultLabelPrefix() {
			return null;
		}

		@Override
		public String getDefaultAbbreviatedLabelPrefix() {
			return null;
		}

		@Override
		public String getDefaultLabelPrefix(MemBuffer buf, Settings settings, int len,
				DataTypeDisplayOptions options) {
			return null;
		}

		@Override
		public String getDefaultOffcutLabelPrefix(MemBuffer buf, Settings settings, int len,
				DataTypeDisplayOptions options, int offcutLength) {
			return null;
		}

		@Override
		public long getLastChangeTimeInSourceArchive() {
			return DataType.NO_SOURCE_SYNC_TIME;
		}

		@Override
		public long getLastChangeTime() {
			return DataType.NO_LAST_CHANGE_TIME;
		}

		@Override
		public SourceArchive getSourceArchive() {
			return null;
		}

		@Override
		public UniversalID getUniversalID() {
			return id;
		}

		@Override
		public void replaceWith(DataType dataType) {
			// no-op
		}

		@Override
		public void setLastChangeTime(long lastChangeTime) {
			// no-op
		}

		@Override
		public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
			// no-op
		}

		@Override
		public void setSourceArchive(SourceArchive archive) {
			// no-op
		}

		@Override
		public DataType clone(DataTypeManager dtm) {
			return this;
		}

		@Override
		public DataType copy(DataTypeManager dtm) {
			return this;
		}

		@Override
		public int getAlignment() {
			return 1;
		}
	}
}
