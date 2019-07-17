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

/**
 * 
 */
public class SaveableInt  implements Saveable {
	private int i;
	private Class<?>[] fields = new Class<?>[] {
        Integer.class
    };
	
	/**
	 * Constructor for SaveableInt.
	 */
	public SaveableInt(int i){
		this.i = i;
	}
	public SaveableInt() {
	}
	/**
	 * @see Saveable#restore(ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		i = objStorage.getInt();
	}
	/**
	 * @see Saveable#save(ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putInt(i);
	}
	
	@Override
	public Class<?>[] getObjectStorageFields() {
	    return fields;
	}
	
	@Override
    public String toString() {
		return ""+i;
	}
	@Override
    public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof SaveableInt)) {
			return false;
		}
		return i == ((SaveableInt)obj).i;
	}
	
	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	/**
	 * @see ghidra.util.Saveable#getSchemaVersion()
	 */
	@Override
	public int getSchemaVersion() {
		return 0;
	}

	/**
	 * @see ghidra.util.Saveable#isUpgradeable(int)
	 */
	@Override
	public boolean isUpgradeable(int oldSchemaVersion) {
		return false;
	}

	/**
	 * @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int, ghidra.util.ObjectStorage)
	 */
	@Override
	public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
		return false;
	}

	@Override
	public boolean isPrivate() {
		return false;
	}
}
