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
package ghidra.features.bsim.query;

public interface SQLFunctionDatabase extends FunctionDatabase {

	/**
	 * Generate SQL bitwise-and syntax for use in database query WHERE clause
	 * @param v1 first value
	 * @param v2 second value
	 * @return SQL
	 */
	public String formatBitAndSQL(String v1, String v2);
}
