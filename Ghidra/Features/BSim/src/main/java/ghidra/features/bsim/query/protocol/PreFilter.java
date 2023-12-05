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
package ghidra.features.bsim.query.protocol;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;

import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.program.model.listing.Program;

public class PreFilter {
	private List<BiPredicate<Program, FunctionDescription>> preFilters;

	public PreFilter() {
		preFilters = new ArrayList<>();
	}

	public void addPredicate(BiPredicate<Program, FunctionDescription> predicate) {
		preFilters.add(predicate);
	}

	public BiPredicate<Program, FunctionDescription> getAndReducedPredicate() {
		return preFilters.stream().reduce((x, y) -> true, BiPredicate::and);
	}

	public BiPredicate<Program, FunctionDescription> getOrReducedPredicate() {
		return preFilters.stream().reduce((x, y) -> false, BiPredicate::or);
	}

	public void clearFilters() {
		preFilters.clear();
	}

}
