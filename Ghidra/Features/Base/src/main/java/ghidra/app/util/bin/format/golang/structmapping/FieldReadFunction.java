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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;

/**
 * Functional interface to read a structure field's value.
 * <p>
 * @see #get(FieldContext)
 * 
 * @param <T> type of structure mapped class that contains this field
 */
@FunctionalInterface
public interface FieldReadFunction<T> {
	/**
	 * Deserializes and returns a field's value.
	 *  
	 * @param context context for this field
	 * @return value of the field
	 * @throws IOException if error reading
	 */
	Object get(FieldContext<T> context) throws IOException;

}
