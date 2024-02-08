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

import java.util.List;
import java.util.Set;

import ghidra.app.plugin.assembler.sleigh.sem.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.asm.wild.WildOperandInfo;

/**
 * The result of assembling an instruction with the wildcard assembler
 */
public interface WildAssemblyResolvedPatterns extends AssemblyResolvedPatterns {

	/**
	 * The information for wildcarded operands in this instruction
	 * 
	 * @return the set of information
	 */
	Set<WildOperandInfo> getOperandInfo();

	/**
	 * Create a copy of this result with added wilcard information
	 * 
	 * @param wildcard see {@link WildOperandInfo}
	 * @param path see {@link WildOperandInfo}
	 * @param location see {@link WildOperandInfo}
	 * @param expression see {@link WildOperandInfo}
	 * @param choice see {@link WildOperandInfo}
	 * @return the copy
	 */
	WildAssemblyResolvedPatterns withWildInfo(String wildcard,
			List<AssemblyConstructorSemantic> path, AssemblyPatternBlock location,
			PatternExpression expression, Object choice);
}
