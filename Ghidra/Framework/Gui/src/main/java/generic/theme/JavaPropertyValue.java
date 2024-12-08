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
package generic.theme;

/**
 * A base class that represents a Java UIManager property.  This value is used to allow for
 * overriding Java UI values using the theme properties files.
 */
public abstract class JavaPropertyValue extends ThemeValue<Object> {

	public JavaPropertyValue(String id, String refId, Object value) {
		super(id, refId, value);
	}

	@Override
	public boolean isExternal() {
		// Java properties are always used to define 'external' UIManager values
		return true;
	}

	@Override
	public String getSerializationString() {
		String outputId = toExternalId(id);
		return outputId + " = " + getSerializedValue();
	}

	protected abstract String toExternalId(String internalId);

	protected abstract String getSerializedValue();

	@Override
	protected ThemeValue<Object> getReferredValue(GThemeValueMap values, String refId) {
		return values.getProperty(refId);
	}

	@Override
	public void installValue(ThemeManager themeManager) {
		// We do not currently support changing these values from the UI or API.  Assuming that,
		// then this method is probably not needed for properties
		throw new UnsupportedOperationException();
	}
}
