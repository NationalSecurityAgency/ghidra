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
package ghidra.app.plugin.core.checksums;

import java.util.Comparator;
import java.util.List;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

/**
 * This class is used to model the table in the ComputeChecksumsProvider.
 */
public class ChecksumTableModel extends GDynamicColumnTableModel<ChecksumAlgorithm, Object> {
	final public static int NAME_COL = 0;
	final public static int VALUE_COL = 1;

	private List<ChecksumAlgorithm> checksumList;
	private boolean isHex;

	/**
	 * Constructor for the table model.
	 * @param serviceProvider The service provider
	 * @param checksumAlgorithms The list of checksum algorithms to use in the table
	 */
	public ChecksumTableModel(ServiceProvider serviceProvider,
			List<ChecksumAlgorithm> checksumAlgorithms) {
		super(serviceProvider);
		this.checksumList = checksumAlgorithms;
	}

	@Override
	public String getName() {
		return "Checksum";
	}

	@Override
	public List<ChecksumAlgorithm> getModelData() {
		return checksumList;
	}

	/**
	 * Method used to update the display options for the applicable checksums.
	 * @param asHex True if the applicable checksums should be displayed in hex, otherwise false.
	 */
	void setFormatOptions(boolean asHex) {
		this.isHex = asHex;
	}

	/**
	 * Returns the checksum with the given name.
	 * @param checksumName the name of the checksum to get.
	 * @return the checksum with the given name, or null if there isn't one.
	 */
	ChecksumAlgorithm getChecksumFor(String checksumName) {
		for (ChecksumAlgorithm res : checksumList) {
			if (res.getName().equals(checksumName)) {
				return res;
			}
		}
		return null;
	}

	@Override
	protected TableColumnDescriptor<ChecksumAlgorithm> createTableColumnDescriptor() {
		TableColumnDescriptor<ChecksumAlgorithm> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new ChecksumNameColumn());
		descriptor.addVisibleColumn(new ChecksumValueColumn());

		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	private class ChecksumNameColumn
			extends AbstractDynamicTableColumn<ChecksumAlgorithm, String, Object> {
		Comparator<String> comparator = new CaseInsensitiveComparator();

		@Override
		public String getColumnName() {
			return "Name";
		}

		@Override
		public String getValue(ChecksumAlgorithm rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject.getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 280;
		}

		@Override
		public Comparator<String> getComparator() {
			return comparator;
		}
	}

	private class ChecksumValueColumn
			extends AbstractDynamicTableColumn<ChecksumAlgorithm, String, Object> {

		@Override
		public String getColumnName() {
			return "Value";
		}

		@Override
		public String getValue(ChecksumAlgorithm rowObject, Settings settings, Object data,
				ServiceProvider sp) throws IllegalArgumentException {
			if (rowObject.supportsDecimal()) {
				return ChecksumAlgorithm.format(rowObject.getChecksum(), isHex);
			}
			return ChecksumAlgorithm.format(rowObject.getChecksum(), true);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 280;
		}
	}

	private class CaseInsensitiveComparator implements Comparator<String> {

		@Override
		public int compare(String o1, String o2) {

			if (o1 == null && o2 == null) {
				return 0;
			}
			else if (o1 != null && o2 == null) {
				return -1;
			}
			else if (o1 == null && o2 != null) {
				return 1;
			}
			return o1.compareToIgnoreCase(o2);
		}
	}
}
