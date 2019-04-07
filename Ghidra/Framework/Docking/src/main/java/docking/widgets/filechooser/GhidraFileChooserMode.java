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
package docking.widgets.filechooser;

/**
 * Modes available for selecting files in the file chooser
 */
public enum GhidraFileChooserMode {

	/** Only files may be chosen */
	FILES_ONLY,

	/** Only directories may be chosen */
	DIRECTORIES_ONLY,

	/** Files and directories may be chosen */
	FILES_AND_DIRECTORIES;

	public boolean supportsFiles() {
		return this == FILES_ONLY || this == FILES_AND_DIRECTORIES;
	}

	public boolean supportsDirectories() {
		return this == DIRECTORIES_ONLY || this == FILES_AND_DIRECTORIES;
	}
}
