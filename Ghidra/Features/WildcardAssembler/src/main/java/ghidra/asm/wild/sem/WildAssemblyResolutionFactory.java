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
package ghidra.asm.wild.sem;

import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.AbstractAssemblyResolutionFactory;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedBackfill;
import ghidra.asm.wild.WildOperandInfo;

public class WildAssemblyResolutionFactory extends
		AbstractAssemblyResolutionFactory<WildAssemblyResolvedPatterns, AssemblyResolvedBackfill> {

	protected class WildAssemblyResolvedPatternsBuilder
			extends AbstractAssemblyResolvedPatternsBuilder<WildAssemblyResolvedPatterns> {
		protected Set<WildOperandInfo> opInfo;

		@Override
		protected WildAssemblyResolvedPatterns build() {
			return new DefaultWildAssemblyResolvedPatterns(WildAssemblyResolutionFactory.this,
				description, cons, children, right, ins, ctx, backfills, forbids, opInfo);
		}
	}

	@Override
	public WildAssemblyResolvedPatternsBuilder newPatternsBuilder() {
		return new WildAssemblyResolvedPatternsBuilder();
	}

	@Override
	public DefaultAssemblyResolvedBackfillBuilder newBackfillBuilder() {
		return new DefaultAssemblyResolvedBackfillBuilder();
	}
}
