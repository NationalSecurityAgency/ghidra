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
 * Block representing an infinite loop
 * 
 * possible multiple incoming edges
 * no outgoing edges
 * 1 (implied) outgoing edge representing loop to the top control flow
 *
 * 1 interior block representing the body of the loop
 */
public class BlockInfLoop extends BlockGraph {
	
	public BlockInfLoop() {
		super();
		blocktype = PcodeBlock.INFLOOP;
	}
}
