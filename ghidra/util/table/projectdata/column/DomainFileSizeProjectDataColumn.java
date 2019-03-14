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
package ghidra.util.table.projectdata.column;

import ghidra.docking.settings.Settings;
import ghidra.framework.main.datatable.DomainFileInfo;
import ghidra.framework.main.datatable.ProjectDataColumn;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.ServiceProvider;

public class DomainFileSizeProjectDataColumn extends ProjectDataColumn<Long> {

	@Override
	public String getColumnName() {
		return "Size";
	}

	@Override
	public Long getValue(DomainFileInfo info, Settings settings, ProjectData data,
			ServiceProvider services) throws IllegalArgumentException {
		String sizeString = info.getMetaDataValue("# of Bytes");
		if (sizeString == null) {
			return null;
		}
		try {
			return Long.parseLong(sizeString);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	@Override
	public int getColumnPreferredWidth() {
		return 120;
	}

	@Override
	public boolean isDefaultColumn() {
		return true;
	}

	@Override
	public int getPriority() {
		return 5;
	}

}
