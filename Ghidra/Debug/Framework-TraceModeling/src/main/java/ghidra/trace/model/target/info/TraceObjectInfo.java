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
package ghidra.trace.model.target.info;

import java.lang.annotation.*;

/**
 * Information about a trace target interface
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface TraceObjectInfo {
	/**
	 * The name for this interface in the schema
	 */
	String schemaName();

	/**
	 * A short name for this interface type
	 */
	String shortName();

	/**
	 * The attributes expected or required by this interface
	 */
	String[] attributes();

	/**
	 * Keys intrinsic to this interface, whose values are fixed during the object's lifespan
	 */
	String[] fixedKeys();
}
