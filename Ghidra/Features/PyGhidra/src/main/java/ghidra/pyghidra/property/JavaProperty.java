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

/**
 * Property interface for creating a Python property for getters and setters.
 *
 * Each implementation is required to have a defined fget method which returns
 * the corresponding primitive type. By doing so we can utilize Python duck typing,
 * auto boxing/unboxing and the Jpype conversion system to automatically convert
 * the primitive return types to the equivalent Python type. This removes the
 * headache of having to carefully and explicitly cast things to an int to
 * avoid exceptions in Python code related to type conversion or type attributes.
 *
 * The fget and fset methods are named to correspond with the fget and fset members
 * of Python's property type.
 */
public sealed interface JavaProperty<T> permits AbstractJavaProperty {

	/**
	 * The method to be used as the fset value for a Python property.
	 *
	 * This method will be called by the Python property __set__ function.
	 *
	 * @param self the object containing the property
	 * @param value the value to be set
	 * @throws Throwable if any exception occurs while setting the value
	 */
	public abstract void fset(Object self, T value) throws Throwable;
}
