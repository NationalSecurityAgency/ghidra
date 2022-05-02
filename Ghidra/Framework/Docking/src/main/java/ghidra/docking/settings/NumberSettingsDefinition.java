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
package ghidra.docking.settings;

import java.math.BigInteger;

import ghidra.util.BigEndianDataConverter;

public interface NumberSettingsDefinition extends SettingsDefinition {

	/**
	 * Gets the value for this SettingsDefinition given a Settings object.
	 * @param settings the set of Settings values for a particular location or null for default value.
	 * @return the value for this settings object given the context.
	 */
	public abstract long getValue(Settings settings);

	/**
	 * Sets the given value into the given settings object using this settingsDefinition as the key.
	 * @param settings the settings object to store the value in.
	 * @param value the value to store in the settings object using this settingsDefinition as the key.
	 */
	public abstract void setValue(Settings settings, long value);

	/**
	 * Get the maximum value permitted.  The absolute value of the setting may not exceed this value.
	 * @return maximum value permitted
	 */
	public abstract BigInteger getMaxValue();

	/**
	 * Determine if negative values are permitted.
	 * @return true if negative values are permitted, else false.
	 */
	public abstract boolean allowNegativeValue();

	/**
	 * Determine if hexidecimal entry/display is preferred due to the
	 * nature of the setting (e.g., mask)
	 * @return true if hex preferred over decimal, else false
	 */
	public boolean isHexModePreferred();

	@Override
	public default String getValueString(Settings settings) {
		long value = getValue(settings);
		if (!allowNegativeValue()) {
			byte[] bytes = BigEndianDataConverter.INSTANCE.getBytes(value);
			BigInteger unsignedValue = new BigInteger(1, bytes);
			return "0x" + unsignedValue.toString(16);
		}
		BigInteger signedValue = BigInteger.valueOf(value);
		String sign = "";
		if (signedValue.signum() < 0) {
			sign = "-";
			signedValue = signedValue.negate();
		}
		return sign + "0x" + signedValue.toString(16);
	}

	@Override
	public default boolean hasSameValue(Settings settings1, Settings settings2) {
		return getValue(settings1) == getValue(settings2);
	}
}
