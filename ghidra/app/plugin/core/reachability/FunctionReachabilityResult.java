/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.reachability;

import ghidra.program.model.listing.Function;

import java.util.List;

class FunctionReachabilityResult {

	private List<FRVertex> path;
	private Function fromFunction;
	private Function toFunction;

	FunctionReachabilityResult(Function fromFunction, Function toFunction, List<FRVertex> path) {
		this.fromFunction = fromFunction;
		this.toFunction = toFunction;
		this.path = path;
	}

	Function getFromFunction() {
		return fromFunction;
	}

	Function getToFunction() {
		return toFunction;
	}

	public int getPathLength() {
		return path.size();
	}

	List<FRVertex> getPath() {
		return path;
	}
}
