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
package ghidra.feature.fid.service;

import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.plugin.HashLookupListMode;

/**
 * Interface abstracting a potential function match and its score.
 */
public interface FidMatchScore {
	/**
	 * Returns the function record of the potential match.
	 * @return the function record
	 */
	public abstract FunctionRecord getFunctionRecord();

	/**
	 * Returns the number of code units in just the potential function.
	 * @return the number of code units in the function record match
	 */
	public abstract float getPrimaryFunctionCodeUnitScore();

	/**
	 * Returns the type of hash match for the potential function.
	 * @return the type of the hash match for the potential function
	 */
	public abstract HashLookupListMode getPrimaryFunctionMatchMode();

	/**
	 * Returns the accumulated matching code units in child (inferior, callee)
	 * functions.
	 * @return the sum of matching inferior functions' code units
	 */
	public abstract float getChildFunctionCodeUnitScore();

	/**
	 * Returns the accumulated matching code units in parent (superior, caller)
	 * functions
	 * @return the sum of matching superior functions' code units
	 */
	public abstract float getParentFunctionCodeUnitScore();

	/**
	 * Returns the overall score (higher is better).
	 * @return the overall score
	 */
	public abstract float getOverallScore();
}
