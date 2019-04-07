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
 * The implementation class of the FidMatchScore.
 */
public class HashMatch implements FidMatchScore {
	private final FunctionRecord functionRecord;
	private final float primaryFunctionCodeUnitScore;
	private final HashLookupListMode primaryFunctionMatchMode;
	private final float childFunctionCodeUnitScore;
	private final float parentFunctionCodeUnitScore;

	public HashMatch(FunctionRecord functionRecord, float primaryFunctionCodeUnitScore,
			HashLookupListMode primaryFunctionMatchMode, float childFunctionCodeUnitScore,
			float parentFunctionCodeUnitScore) {
		this.functionRecord = functionRecord;
		this.primaryFunctionCodeUnitScore = primaryFunctionCodeUnitScore;
		this.primaryFunctionMatchMode = primaryFunctionMatchMode;
		this.childFunctionCodeUnitScore = childFunctionCodeUnitScore;
		this.parentFunctionCodeUnitScore = parentFunctionCodeUnitScore;
	}

	@Override
	public FunctionRecord getFunctionRecord() {
		return functionRecord;
	}

	@Override
	public float getPrimaryFunctionCodeUnitScore() {
		return primaryFunctionCodeUnitScore;
	}

	@Override
	public HashLookupListMode getPrimaryFunctionMatchMode() {
		return primaryFunctionMatchMode;
	}

	@Override
	public float getChildFunctionCodeUnitScore() {
		return childFunctionCodeUnitScore;
	}

	@Override
	public float getParentFunctionCodeUnitScore() {
		return parentFunctionCodeUnitScore;
	}

	@Override
	public String toString() {
		return String.format("%.1f - %.1f (%s)/%.1f/%.1f %s", getOverallScore(),
			primaryFunctionCodeUnitScore, primaryFunctionMatchMode, childFunctionCodeUnitScore,
			parentFunctionCodeUnitScore, functionRecord.toString());
	}

	@Override
	public float getOverallScore() {
		return primaryFunctionCodeUnitScore + childFunctionCodeUnitScore +
			parentFunctionCodeUnitScore;
	}
}
