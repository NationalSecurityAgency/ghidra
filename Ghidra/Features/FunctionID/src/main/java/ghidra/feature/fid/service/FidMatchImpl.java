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
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.plugin.HashLookupListMode;
import ghidra.program.model.address.Address;

/**
 * Implementation of the FidMatch interface.
 */
class FidMatchImpl implements FidMatch {
	private final LibraryRecord library;
	private final Address functionEntryPoint;
	private final FidMatchScore scoreDelegate;

	FidMatchImpl(LibraryRecord library, Address functionEntryPoint, FidMatchScore score) {
		this.library = library;
		this.functionEntryPoint = functionEntryPoint;
		this.scoreDelegate = score;
	}

	@Override
	public LibraryRecord getLibraryRecord() {
		return library;
	}

	@Override
	public Address getMatchedFunctionEntryPoint() {
		return functionEntryPoint;
	}

	@Override
	public String toString() {
		return scoreDelegate + " @ " + functionEntryPoint;
	}

	@Override
	public FunctionRecord getFunctionRecord() {
		return scoreDelegate.getFunctionRecord();
	}

	@Override
	public float getPrimaryFunctionCodeUnitScore() {
		return scoreDelegate.getPrimaryFunctionCodeUnitScore();
	}

	@Override
	public HashLookupListMode getPrimaryFunctionMatchMode() {
		return scoreDelegate.getPrimaryFunctionMatchMode();
	}

	@Override
	public float getChildFunctionCodeUnitScore() {
		return scoreDelegate.getChildFunctionCodeUnitScore();
	}

	@Override
	public float getParentFunctionCodeUnitScore() {
		return scoreDelegate.getParentFunctionCodeUnitScore();
	}

	@Override
	public float getOverallScore() {
		return scoreDelegate.getOverallScore();
	}
}
