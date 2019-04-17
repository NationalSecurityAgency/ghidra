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
package ghidra.formats.gfilesystem;

import java.util.List;

import ghidra.formats.gfilesystem.factory.FileSystemInfoRec;

/**
 * A callback interface used to choose which filesystem implementation to use when
 * multiple filesystem types indicate that they can open a container file.
 * <p>
 */
public interface FileSystemProbeConflictResolver {

	/**
	 * Picks a single {@link FileSystemInfoRec} to use when mounting a filesystem.
	 * <p>
	 * @param factories a {@link List} of {@link FileSystemInfoRec}s.
	 * @return the choosen FSIR, or null
	 */
	default public FileSystemInfoRec resolveFSIR(List<FileSystemInfoRec> factories) {
		switch (factories.size()) {
			case 0:
				return null;
			case 1:
				return factories.get(0);
			default:
				return chooseFSIR(factories);
		}

	}

	/**
	 * This method should be provided by the actual strategy implementation.
	 * <p>
	 * This method will only be called if the list contains more than a single item.
	 * <p>
	 * @param factories {@link List} of {@link FileSystemInfoRec}, always more than 1 element.
	 * @return the choosen FSIR, or null
	 */
	public FileSystemInfoRec chooseFSIR(List<FileSystemInfoRec> factories);

	/**
	 * Conflict handler that chooses the first filesystem in the list.
	 */
	public static final FileSystemProbeConflictResolver CHOOSEFIRST =
		new FileSystemProbeConflictResolver() {
			@Override
			public FileSystemInfoRec chooseFSIR(List<FileSystemInfoRec> factories) {
				return factories.get(0);
			}
		};

	/**
	 * Conflict handler that allows the user to pick the filesystem to use from a GUI list.
	 * <p>
	 */
	public static FileSystemProbeConflictResolver GUI_PICKER =
		new FileSystemProbeConflictResolver() {
			@Override
			public FileSystemInfoRec chooseFSIR(List<FileSystemInfoRec> factories) {
				return SelectFromListDialog.selectFromList(factories, "Select filesystem",
					"Select a filesystem from list", FileSystemInfoRec::getDescription);
			}
		};

}
