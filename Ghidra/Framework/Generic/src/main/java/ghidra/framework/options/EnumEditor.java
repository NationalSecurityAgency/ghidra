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
package ghidra.framework.options;

import ghidra.util.Msg;

import java.beans.PropertyEditorSupport;
import java.lang.reflect.Method;
import java.util.HashSet;

public class EnumEditor extends PropertyEditorSupport {

	private Enum<?> value;

	/**
	 * 
	 * @see java.beans.PropertyEditor#setValue(java.lang.Object)
	 */
	@Override
	public void setValue(Object o) {
		value = (Enum<?>) o;
	}

	/**
	 * 
	 * @see java.beans.PropertyEditor#getValue()
	 */
	@Override
	public Object getValue() {
		return value;
	}

	/**
	 * 
	 * @see java.beans.PropertyEditor#getTags()
	 */
	@Override
	public String[] getTags() {

		try {
			Method m = value.getClass().getMethod("values");
			Enum<?>[] enums = (Enum<?>[]) m.invoke(null);
			HashSet<String> set = new HashSet<String>();
			String[] choices = new String[enums.length];
			for (int i = 0; i < enums.length; i++) {
				String s = enums[i].toString();
				if (s == null || set.contains(s)) {
					s = enums[i].name();
				}
				choices[i] = s;
				set.add(s);
			}
			return choices;
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
		}
		return new String[] { value.toString() };
	}

	public Enum<?>[] getEnums() {

		try {
			Method m = value.getClass().getMethod("values");
			Enum<?>[] enums = (Enum<?>[]) m.invoke(null);
			return enums;
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
		}
		return new Enum<?>[] { value };
	}

	/**
	 * 
	 * @see java.beans.PropertyEditor#getAsText()
	 */
	@Override
	public String getAsText() {
		return value.toString();
	}

	/**
	 * 
	 * @see java.beans.PropertyEditor#setAsText(java.lang.String)
	 */
	@Override
	public void setAsText(String s) {

		try {
			Method m = value.getClass().getMethod("values");
			Enum<?>[] enums = (Enum<?>[]) m.invoke(null);
			for (int i = 0; i < enums.length; i++) {
				if (s.equals(enums[i].toString())) {
					value = enums[i];
					break;
				}
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
		}

		firePropertyChange();
	}

}
