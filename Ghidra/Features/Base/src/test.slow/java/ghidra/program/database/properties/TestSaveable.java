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
package ghidra.program.database.properties;

import java.util.Arrays;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

/**
 * 
 */
class TestSaveable implements Saveable {
	
	boolean booleanValue;
	byte byteValue;
	short shortValue;
	int intValue;
	long longValue;
	float floatValue;
	double doubleValue;
	String strValue;
	byte[] byteValues;
	short[] shortValues;
	int[] intValues;
	long[] longValues;
	float[] floatValues;
	double[] doubleValues;
	String[] strValues; 
	
	private Class<?>[] fields = new Class<?>[] {
	    // don't think this is used in the tests
	};
	
	public TestSaveable() {
	}

	@Override
	public Class<?>[] getObjectStorageFields() {
	    return fields;
	}
	
	/**
	 * @see ghidra.util.Saveable#save(ghidra.util.ObjectStorage)
	 */
	@Override
	public void save(ObjectStorage objStorage) {
		objStorage.putBoolean(booleanValue);
		objStorage.putByte(byteValue);
		objStorage.putShort(shortValue);
		objStorage.putInt(intValue);
		objStorage.putLong(longValue);
		objStorage.putFloat(floatValue);
		objStorage.putDouble(doubleValue);
		objStorage.putString(strValue);
		objStorage.putBytes(byteValues);
		objStorage.putShorts(shortValues);
		objStorage.putInts(intValues);
		objStorage.putLongs(longValues);
		objStorage.putFloats(floatValues);
		objStorage.putDoubles(doubleValues);
		objStorage.putStrings(strValues);
	}

	/**
	 * @see ghidra.util.Saveable#restore(ghidra.util.ObjectStorage)
	 */
	@Override
	public void restore(ObjectStorage objStorage) {
		booleanValue = objStorage.getBoolean();
		byteValue = objStorage.getByte();
		shortValue = objStorage.getShort();
		intValue = objStorage.getInt();
		longValue = objStorage.getLong();
		floatValue = objStorage.getFloat();
		doubleValue = objStorage.getDouble();
		strValue = objStorage.getString();
		byteValues = objStorage.getBytes();
		shortValues = objStorage.getShorts();
		intValues = objStorage.getInts();
		longValues = objStorage.getLongs();
		floatValues = objStorage.getFloats();
		doubleValues = objStorage.getDoubles();
		strValues = objStorage.getStrings();
	}

	@Override
	public boolean isPrivate() {
		return false;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (booleanValue ? 1231 : 1237);
		result = prime * result + byteValue;
		result = prime * result + Arrays.hashCode(byteValues);
		long temp;
		temp = Double.doubleToLongBits(doubleValue);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		result = prime * result + Arrays.hashCode(doubleValues);
		result = prime * result + Arrays.hashCode(fields);
		result = prime * result + Float.floatToIntBits(floatValue);
		result = prime * result + Arrays.hashCode(floatValues);
		result = prime * result + intValue;
		result = prime * result + Arrays.hashCode(intValues);
		result = prime * result + (int) (longValue ^ (longValue >>> 32));
		result = prime * result + Arrays.hashCode(longValues);
		result = prime * result + shortValue;
		result = prime * result + Arrays.hashCode(shortValues);
		result = prime * result + ((strValue == null) ? 0 : strValue.hashCode());
		result = prime * result + Arrays.hashCode(strValues);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		TestSaveable other = (TestSaveable) obj;
		if (booleanValue != other.booleanValue) {
			return false;
		}
		if (byteValue != other.byteValue) {
			return false;
		}
		if (!Arrays.equals(byteValues, other.byteValues)) {
			return false;
		}
		if (Double.doubleToLongBits(doubleValue) != Double.doubleToLongBits(other.doubleValue)) {
			return false;
		}
		if (!Arrays.equals(doubleValues, other.doubleValues)) {
			return false;
		}
		if (!Arrays.equals(fields, other.fields)) {
			return false;
		}
		if (Float.floatToIntBits(floatValue) != Float.floatToIntBits(other.floatValue)) {
			return false;
		}
		if (!Arrays.equals(floatValues, other.floatValues)) {
			return false;
		}
		if (intValue != other.intValue) {
			return false;
		}
		if (!Arrays.equals(intValues, other.intValues)) {
			return false;
		}
		if (longValue != other.longValue) {
			return false;
		}
		if (!Arrays.equals(longValues, other.longValues)) {
			return false;
		}
		if (shortValue != other.shortValue) {
			return false;
		}
		if (!Arrays.equals(shortValues, other.shortValues)) {
			return false;
		}
		if (strValue == null) {
			if (other.strValue != null) {
				return false;
			}
		}
		else if (!strValue.equals(other.strValue)) {
			return false;
		}
		if (!Arrays.equals(strValues, other.strValues)) {
			return false;
		}
		return true;
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

}
