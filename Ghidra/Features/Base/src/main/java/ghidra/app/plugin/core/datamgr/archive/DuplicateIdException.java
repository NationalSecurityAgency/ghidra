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
package ghidra.app.plugin.core.datamgr.archive;

public class DuplicateIdException extends Exception {

	private final String newArchiveName;
	private final String existingArchiveName;

	public DuplicateIdException(String newArchiveName, String existingArchiveName) {
		super(
			"Attempted to open a datatype archive with the same ID as datatype archive that is\n " +
				"already open. " + newArchiveName + " has same id as " + existingArchiveName +
				"\nOne is probably a copy of the other.  Ghidra does not support using \n" +
				"archive copies within the same project!");
		this.newArchiveName = newArchiveName;
		this.existingArchiveName = existingArchiveName;
	}

	public String getNewArchiveName() {
		return newArchiveName;
	}

	public String getExistingArchiveName() {
		return existingArchiveName;
	}

}
