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
import ghidra.program.model.lang.Endian;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * Column for the ProjectDataTable (Frontend) to display the endianess of a program.
 */
public class EndianProjectDataColumn extends ProjectDataColumn<Endian> {

	private GColumnRenderer<Endian> renderer = new AbstractGhidraColumnRenderer<Endian>() {
		@Override
		protected String getText(Object value) {
			if (value == null) {
				return null;
			}
			return ((Endian) value).getDisplayName();
		}

		@Override
		public String getFilterString(Endian t, Settings settings) {
			return getText(t);
		}
	};

	@Override
	public String getColumnName() {
		return "Endian";
	}

	@Override
	public Endian getValue(DomainFileInfo info, Settings settings, ProjectData data,
			ServiceProvider services) throws IllegalArgumentException {
		String name = info.getMetaDataValue("Endian");
		return Endian.toEndian(name);
	}

	@Override
	public int getColumnPreferredWidth() {
		return 100;
	}

	@Override
	public boolean isDefaultColumn() {
		return true;
	}

	@Override
	public int getPriority() {
		return 2;
	}

	@Override
	public GColumnRenderer<Endian> getColumnRenderer() {
		return renderer;
	}
}
