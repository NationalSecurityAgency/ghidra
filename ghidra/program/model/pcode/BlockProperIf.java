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
 * A block containing condition control flow
 * 
 * possible multiple incoming edges
 * 1 outgoing edge representing rejoined control flow
 * 
 * 2 interior blocks
 *    one "condition" block representing the decision point on whether to take the conditional flow
 *    one "body" block representing the conditional flow that may be followed or may be skipped 
 *
 */
public class BlockProperIf extends BlockGraph {

	public BlockProperIf() {
		super();
		blocktype = PcodeBlock.PROPERIF;
	}
}
