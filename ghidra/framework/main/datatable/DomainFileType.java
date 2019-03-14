/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.main.datatable;

import javax.swing.Icon;

import docking.widgets.table.DisplayStringProvider;

public class DomainFileType implements Comparable<DomainFileType>, DisplayStringProvider {
	private String contentType;
	private Icon icon;
	private boolean isVersioned;

	public DomainFileType(String contentType, Icon icon, boolean isVersioned) {
		this.contentType = contentType;
		this.icon = icon;
		this.isVersioned = isVersioned;
	}

	@Override
	public int compareTo(DomainFileType other) {
		int result = contentType.compareTo(other.contentType);
		if (result == 0) {
			result = Boolean.valueOf(isVersioned).compareTo(Boolean.valueOf(other.isVersioned));
		}
		return result;
	}

	public String getContentType() {
		return contentType;
	}

	public Icon getIcon() {
		return icon;
	}

	@Override
	public String getDisplayString() {
		return contentType;
	}

	@Override
	public String toString() {
		return contentType + " (" + (isVersioned ? "versioned" : "unversioned") + ")";
	}
}
