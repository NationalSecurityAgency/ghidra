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
package ghidra.util.database.annot;

import java.lang.annotation.*;

import ghidra.util.database.DBAnnotatedObject;
import ghidra.util.database.DBObjectColumn;

/**
 * Mark a {@link DBObjectColumn} to receive a column handle
 *
 * @see DBAnnotatedObject
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface DBAnnotatedColumn {
	/**
	 * The name of the column
	 * 
	 * <p>
	 * There should be a {@link DBAnnotatedField} annotation with the same column name
	 */
	String value();
}
