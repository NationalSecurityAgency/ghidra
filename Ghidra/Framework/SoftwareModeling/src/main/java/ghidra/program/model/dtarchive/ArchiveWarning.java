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
package ghidra.program.model.dtarchive;

import ghidra.program.model.lang.*;

public enum ArchiveWarning {

	/**
	 * {@link #NONE} indicates a normal archive condition
	 */
	NONE(ArchiveWarningLevel.INFO),

	/**
	 * {@link #UPGRADED_LANGUAGE_VERSION} indicates an archive which has been open for update
	 * was upgraded to a newer language version.  This is expected when the {@link Language}
	 * required by the associated {@link ProgramArchitecture} has a major version change 
	 * which involves significant {@link Register} changes.  Sharing an upgraded archive 
	 * may impact others who do not have access to the updated {@link Language} module.
	 */
	UPGRADED_LANGUAGE_VERSION(ArchiveWarningLevel.INFO),

	/**
	 * {@link #LANGUAGE_NOT_FOUND} indicates the {@link Language} or its appropriate version, 
	 * required by the associated {@link ProgramArchitecture}, was not found or encountered
	 * a problem being loaded.  The {@link DataTypeArchive#getWarningDetail()} may provide
	 * additional insight to the underlying cause. 
	 */
	LANGUAGE_NOT_FOUND(ArchiveWarningLevel.ERROR),

	/**
	 * {@link #COMPILER_SPEC_NOT_FOUND} indicates the {@link CompilerSpec}, 
	 * required by the associated {@link ProgramArchitecture}, was not found or encountered
	 * a problem being loaded.  The {@link DataTypeArchive#getWarningDetail()} may provide
	 * additional insight to the underlying cause.  This condition can only occur if the
	 * required {@link Language} was found. 
	 */
	COMPILER_SPEC_NOT_FOUND(ArchiveWarningLevel.ERROR),

	/**
	 * {@link #LANGUAGE_UPGRADE_REQURED} indicates an archive which has been open read-only
	 * requires an upgraded to a newer language version.  This is expected when the 
	 * {@link Language} required by the associated {@link ProgramArchitecture} has a major 
	 * version change within the current installation.  Major version changes for a 
	 * {@link Language} rarely occur but are required when significant {@link Register} 
	 * or addressing changes have been made.  Upgrading a shared archive may impact others 
	 * who do not have access to the updated {@link Language} module and should be 
	 * coordinated with others who may be affected.
	 */
	LANGUAGE_UPGRADE_REQURED(ArchiveWarningLevel.WARN),

	/**
	 * {@link #DATA_ORG_CHANGED} indicates an archive which has been open read-only
	 * requires an upgraded to adjust for changes in the associated data organization.
	 */
	DATA_ORG_CHANGED(ArchiveWarningLevel.WARN);

	public final ArchiveWarningLevel level;

	private ArchiveWarning(ArchiveWarningLevel level) {
		this.level = level;
	}

	/**
	 * Get the warning level
	 * @return warning level
	 */
	public ArchiveWarningLevel level() {
		return level;
	}

	public static enum ArchiveWarningLevel {
		INFO, WARN, ERROR;
	}
}
