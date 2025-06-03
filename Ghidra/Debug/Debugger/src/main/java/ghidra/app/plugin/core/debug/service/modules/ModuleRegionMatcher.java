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
package ghidra.app.plugin.core.debug.service.modules;

import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.memory.TraceMemoryRegion;

class ModuleRegionMatcher {
	final long snap;
	MemoryBlock block;
	TraceMemoryRegion region;

	public ModuleRegionMatcher(long snap) {
		this.snap = snap;
	}

	int score() {
		if (block == null || region == null) {
			return 0; // Unmatched
		}
		int score = 3; // For the matching offset
		if (block.getSize() == region.getLength(snap)) {
			score += 10;
		}
		return score;
	}
}
