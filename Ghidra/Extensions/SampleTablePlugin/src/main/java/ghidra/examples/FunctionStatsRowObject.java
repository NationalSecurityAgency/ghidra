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
package ghidra.examples;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class FunctionStatsRowObject {

	private final Function function;
	private final String algorithmName;
	private int score;

	FunctionStatsRowObject(Function function, String algorithmName, int score) {
		this.function = function;
		this.algorithmName = algorithmName;
		this.score = score;
	}

	public Address getAddress() {
		return function.getEntryPoint();
	}

	public String getFunctionName() {
		return function.getName();
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public Integer getScore() {
		return score;
	}

}
