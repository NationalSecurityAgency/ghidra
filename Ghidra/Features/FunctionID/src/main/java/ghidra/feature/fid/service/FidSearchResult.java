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

import java.util.ArrayList;
import java.util.List;

import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.program.model.listing.Function;

/**
 * Represents the result of a search operation on the FID libraries.
 */
public class FidSearchResult {
	public Function function;
	public FidHashQuad hashQuad;
	public List<FidMatch> matches;
	
	public FidSearchResult(Function func,FidHashQuad hashQuad,List<FidMatch> matches) {
		this.function = func;
		this.hashQuad = hashQuad;
		this.matches = matches;
	}

	public void filterBySymbolPrefix(String prefix) {
		ArrayList<FidMatch> result = new ArrayList<FidMatch>();
		for (FidMatch match : matches) {
			FunctionRecord function = match.getFunctionRecord();

			if (!function.getName().startsWith(prefix)) {
				result.add(match);
			}

		}
		matches = result;		// Replace old matches list with filtered list
	}
}
