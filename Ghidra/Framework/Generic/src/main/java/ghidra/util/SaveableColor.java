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
package ghidra.util;

import java.awt.Color;

public class SaveableColor extends PrivateSaveable 
{
	private Color color;
	private Class<?>[] fields = new Class<?>[] {
	    Integer.class, Integer.class, Integer.class
	};
	
	public SaveableColor(Color color) {
		this.color = color;
	}
	public SaveableColor() {
	}
	/**
	 * @see Saveable#restore(ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putInt(color.getRed());
		objStorage.putInt(color.getBlue());
		objStorage.putInt(color.getGreen());
	}
	
	@Override
	public Class<?>[] getObjectStorageFields() {
	    return fields;
	}
	
	/**
	 * @see Saveable#save(ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		int red = objStorage.getInt();
		int blue = objStorage.getInt();
		int green = objStorage.getInt();
		color = new Color(red,green,blue);
	}

	public Color getColor() {
		return color;
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
	
	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
    public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass() ) {
			return false;
		}
		return color.equals(((SaveableColor)obj).color);
	}
	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
    public int hashCode() {
		return color.hashCode();
	}
	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return color.toString();
	}
}
