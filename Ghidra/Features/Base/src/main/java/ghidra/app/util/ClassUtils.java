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
package ghidra.app.util;

import ghidra.program.model.data.PointerDataType;

public class ClassUtils {

	// Prototype values for now.  Need to come to agreement on what these should be
	public static final String VBPTR = "{vbptr}";
	public static final String VFPTR = "{vfptr}";

	/**
	 * Type used for {@link #VBPTR} and {@link #VFPTR} fields in a class
	 */
	public static final PointerDataType VXPTR_TYPE = new PointerDataType();

	private ClassUtils() {
		// no instances
	}

}
