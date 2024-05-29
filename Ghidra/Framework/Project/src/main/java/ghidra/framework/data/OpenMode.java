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
package ghidra.framework.data;

import ghidra.framework.model.DomainObject;

/**
 * {@link OpenMode} provides an instantiation mode for {@link DomainObject}
 * implementations and internal storage adapters.  Implementation code
 * may impose restrictions on which modes are supported.
 */
public enum OpenMode {
	/**
	 * Creating new domain object.
	 * This mode is generally not supported by {@link DomainObject} object constructors since
	 * object creation would generally have a dedicated constructor.
	 */
	CREATE,
	/**
	 * Domain object opened as an immutable instance
	 */
	IMMUTABLE,
	/**
	 * Domain object opened for modification
	 */
	UPDATE,
	/**
	 * Domain object opened for modification with data upgrade permitted.
	 */
	UPGRADE,
}
