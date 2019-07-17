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
 * Block representing a while-do (exit from the top) loop construction
 * 
 * possible multiple incoming edges
 * 1 outgoing exit edge
 * 1 (implied) loop edge
 * 
 * 1 interior block representing the top of the loop and the decision point for staying in the loop
 * 1 interior block representing the body of the loop, which always exits back to the top of the loop
 *
 */
public class BlockWhileDo extends BlockGraph {

	public BlockWhileDo() {
		super();
		blocktype = PcodeBlock.WHILEDO;
	}
}
