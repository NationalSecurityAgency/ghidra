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
package ghidra.util.prop;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

public class SaveableString implements Saveable {

	private String string;

	private Class<?>[] fields = new Class<?>[] { String.class };

	public SaveableString(String string) {
		if (string == null) {
			throw new IllegalArgumentException("Saved string cannot be null");
		}
		this.string = string;
	}

	public SaveableString() {
		// for restoring
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
		return fields;
	}

	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putString(string);
	}

	@Override
	public void restore(ObjectStorage objStorage) {
		objStorage.getString();
	}

	@Override
	public int getSchemaVersion() {
		return 0;
	}

	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion,
			ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		return string.equals(((SaveableString) obj).string);
	}

	@Override
	public int hashCode() {
		return string.hashCode();
	}
}
