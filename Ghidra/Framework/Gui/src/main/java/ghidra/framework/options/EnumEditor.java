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
package ghidra.framework.options;

import java.beans.PropertyEditorSupport;
import java.lang.reflect.Method;
import java.util.HashSet;

import ghidra.util.Msg;

public class EnumEditor extends PropertyEditorSupport {

	private Enum<?> value;

	@Override
	public void setValue(Object o) {
		value = (Enum<?>) o;
	}

	@Override
	public Object getValue() {
		return value;
	}

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

	@Override
	public String getAsText() {
		return value.toString();
	}

	@Override
	public void setAsText(String s) {

		try {
			Method m = value.getClass().getMethod("values");
			Enum<?>[] enums = (Enum<?>[]) m.invoke(null);
			for (Enum<?> enum1 : enums) {
				if (s.equals(enum1.toString())) {
					value = enum1;
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
