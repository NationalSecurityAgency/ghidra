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
 * Do-while block:
 *    possible multiple incoming edges
 *    1 (implied) edge outgoing back to itself
 *    1 edge outgoing (the loop exit)
 *    
 *    1 block representing the body of the loop
 */
public class BlockDoWhile extends BlockGraph {

	public BlockDoWhile() {
		super();
		blocktype = PcodeBlock.DOWHILE;
	}
}
