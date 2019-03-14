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
package ghidra.feature.fid.db;

/**
 * A class to represent the types of relations stored in the FID database. 
 */
public enum RelationType {
	/**
	 * Direct call means that the inferior (callee) function exists in
	 * the same program as the superior (caller).
	 */
	DIRECT_CALL,
	/**
	 * An intralibrary call is between two functions that are in different programs but in the same library.
	 * The relation was discovered by linking on the name
	 */
	INTRA_LIBRARY_CALL,
	
	/**
	 * An interlibrary call is between two functions in entirely different libraries.
	 */
	INTER_LIBRARY_CALL
}
