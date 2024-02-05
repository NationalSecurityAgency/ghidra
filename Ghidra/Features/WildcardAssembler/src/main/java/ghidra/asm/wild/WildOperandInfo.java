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
package ghidra.asm.wild;

import java.util.List;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;

/**
 * Information about an operand that was matched to a wildcard
 * 
 * @param wildcard the name of the wildcard that matched the operand
 * @param path the hierarchy of Sleigh constructors leading to the operand
 * @param location the bit pattern giving the location of the operand's field(s) in the machine
 *            instruction
 * @param expression the expression describing how to encode the operand in the field(s)
 * @param choice if applicable, the value encoded in the result containing this information
 */
public record WildOperandInfo(String wildcard, List<AssemblyConstructorSemantic> path,
		AssemblyPatternBlock location, PatternExpression expression, Object choice) {

	/**
	 * Copy this wildcard info, but with an increased shift amount
	 * 
	 * @param amt the number of bits to shift (right)
	 * @return the copy
	 */
	public WildOperandInfo shift(int amt) {
		return new WildOperandInfo(wildcard, path, location.shift(amt), expression, choice);
	}
}
