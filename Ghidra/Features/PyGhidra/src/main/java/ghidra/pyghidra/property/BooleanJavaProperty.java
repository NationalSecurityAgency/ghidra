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
package ghidra.pyghidra.property;

import java.lang.invoke.MethodHandle;

/**
 * The {@link JavaProperty} for the primitive <b>boolean</b> type
 */
public final class BooleanJavaProperty extends AbstractJavaProperty<Boolean> {

	BooleanJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	/**
	 * The method to be used as the fget value for a Python property.
	 *
	 * This method will be called by the Python property __get__ function.
	 *
	 * @param self the object containing the property
	 * @return the property's value
	 * @throws Throwable if any exception occurs while getting the value
	 */
	public boolean fget(Object self) throws Throwable {
		return doGet(self);
	}
}
