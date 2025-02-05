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
package ghidra.framework.model;

import ghidra.framework.store.FileSystem;
import ghidra.util.StringUtilities;

public class DomainObjectDisplayUtils {
	private static final String VERSION_SEP = "@";
	private static final String CHANGE_INDICATOR = "*";
	private static final String READ_ONLY = " [Read-Only]";
	private static final String PROJECT_SEP_ELLIPSES =
		":" + FileSystem.SEPARATOR + "..." + FileSystem.SEPARATOR;

	private static final int TOOLTIP_PATH_LENGTH_LIMIT = 100;
	private static final int TAB_NAME_LENGTH_LIMIT = 40;

	private DomainObjectDisplayUtils() {
	}

	public static String getShortPath(DomainFile df) {
		String pathString = df.toString();
		int length = pathString.length();
		if (length < TOOLTIP_PATH_LENGTH_LIMIT) {
			return pathString;
		}

		String[] pathParts = pathString.split(FileSystem.SEPARATOR);
		if (pathParts.length == 2) { // at least 2 for project name and filename
			return pathString;
		}

		String projectName = df.getProjectLocator().getName();
		int parentFolderIndex = pathParts.length - 2;
		String parentName = pathParts[parentFolderIndex];
		String filename = df.getName();
		pathString =
			projectName + PROJECT_SEP_ELLIPSES + parentName + FileSystem.SEPARATOR + filename;
		return pathString;
	}

	public static String getToolTip(DomainObject object) {
		DomainFile df = object.getDomainFile();
		String changeIndicator = object.isChanged() ? CHANGE_INDICATOR : "";
		String pathString = getShortPath(df);
		if (!df.isInWritableProject()) {
			return pathString + READ_ONLY + changeIndicator;
		}
		return pathString + changeIndicator;
	}

	public static String getTabText(DomainFile df) {
		String tabName = df.getName();
		String trimmedName = StringUtilities.trimMiddle(tabName, TAB_NAME_LENGTH_LIMIT);
		if (!df.isReadOnly()) {
			return trimmedName;
		}

		int version = df.getVersion();
		if (!df.canSave() && version != DomainFile.DEFAULT_VERSION) {
			trimmedName += VERSION_SEP + version;
		}
		return trimmedName + READ_ONLY;
	}

	public static String getTabText(DomainObject object) {
		if (object.isChanged()) {
			return CHANGE_INDICATOR + getTabText(object.getDomainFile());
		}
		return getTabText(object.getDomainFile());
	}
}
