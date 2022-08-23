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

/**
 * Required annotation for {@link DBAnnotatedObject}
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface DBAnnotatedObjectInfo {
	/**
	 * The schema version
	 * 
	 * <p>
	 * This should be incremented in many situtations, including but not limited to:
	 * <ul>
	 * <li>A field is added or removed</li>
	 * <li>A field's type changes</li>
	 * <li>A field's column name changes. See {@link DBAnnotatedField#column()}</li>
	 * <li>A field's codec changes. See {@link DBAnnotatedField#codec()}</li>
	 * <li>A field's sparse-storage flag changes. See {@link DBAnnotatedField#sparse()}</li>
	 * <li>A field's index flag changes. See {@link DBAnnotatedField#indexed()}</li>
	 * <li>The order of field declarations changes.</li>
	 * <li>The codec used by a field changes how it encodes values</li>
	 * <li>The fields of a superclass change in any of the above ways</li>
	 * </ul>
	 */
	int version();
}
