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
package ghidra.pcode.emulate;

public enum EmulateExecutionState {

	/**
	 * Currently stopped
	 */
	STOPPED,

	/**
	 * Currently stopped at a breakpoint
	 */
	BREAKPOINT,

	/**
	 * Currently decoding instruction (i.e., generating pcode ops)
	 */
	INSTRUCTION_DECODE,

	/**
	 * Currently executing instruction pcode
	 */
	EXECUTE,

	/**
	 * Execution stopped due to a fault/error
	 */
	FAULT

}
