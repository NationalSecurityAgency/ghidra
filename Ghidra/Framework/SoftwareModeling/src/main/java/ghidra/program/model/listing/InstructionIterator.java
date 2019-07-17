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
package ghidra.program.model.listing;

import java.util.Iterator;

import util.CollectionUtils;

/**
 * Interface to define an iterator over over some set of instructions.
 * 
 * @see CollectionUtils#asIterable
 */
public interface InstructionIterator extends Iterator<Instruction>, Iterable<Instruction> {

	/**
	 * Returns true if the iteration has more elements.
	 */
	@Override
	public boolean hasNext();

	/**
	 * Return the next instruction in the iteration.
	 */
	@Override
	public Instruction next();
}
