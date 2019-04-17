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

import java.text.*;
import java.util.Date;

public class CreationDateProjectDataColumn extends ProjectDataColumn<Date> {
	private static final DateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy");

	@Override
	public String getColumnName() {
		return "Created";
	}

	@Override
	public Date getValue(DomainFileInfo info, Settings settings, ProjectData data,
			ServiceProvider services) throws IllegalArgumentException {

		String dateString = info.getMetaDataValue("Date Created");
		if (dateString != null) {
			return getDate(dateString);
		}
		return null;
	}

	private Date getDate(String dateString) {
		if (dateString != null) {
			try {
				return format.parse(dateString);
			}
			catch (ParseException e) {
				// just return the default date.
			}
		}
		return new Date(0);
	}

	@Override
	public int getColumnPreferredWidth() {
		return 200;
	}

	@Override
	public boolean isDefaultColumn() {
		return false;
	}

	@Override
	public int getPriority() {
		return 7;
	}

}
