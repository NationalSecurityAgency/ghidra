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
package ghidra.pcode.emu.util;

/**
 * An interface for things that count instructions and p-code ops
 */
public interface CountsPcodeOps {
	/**
	 * {@return the number of instructions counted}
	 */
	int instructionCount();

	/**
	 * {@return the number of trailing p-code ops counted}
	 * <p>
	 * This represents partial execution of an instruction. Though {@link #instructionCount()}
	 * <em>does</em> count the partial instruction, this indicates how much of that instruction was
	 * counted. This should provide enough information to replay an execution to exactly the same
	 * p-code op step.
	 */
	int trailingOpCount();
}
