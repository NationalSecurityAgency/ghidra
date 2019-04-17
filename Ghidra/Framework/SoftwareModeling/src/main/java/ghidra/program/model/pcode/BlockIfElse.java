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
package ghidra.program.model.pcode;


/**
 * A standard if/else control flow block
 *     possible multiple incoming edges
 *     1 outgoing edge - going to the common out block rejoining the 2 control flows
 *     
 *     1 "condition" block with exactly 2 outputs
 *     1 "true" block representing the control flow if the condition is true
 *     1 "false" block representing the control flow if the condition is false
 *
 */
public class BlockIfElse extends BlockGraph {

	public BlockIfElse() {
		super();
		blocktype = PcodeBlock.IFELSE;
	}

}
