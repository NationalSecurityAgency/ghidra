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
package ghidra.trace.util;

import java.util.Iterator;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class WrappingInstructionIterator implements InstructionIterator {
	protected final Iterator<? extends Instruction> it;

	public WrappingInstructionIterator(Iterator<? extends Instruction> it) {
		this.it = it;
	}

	@Override
	public Iterator<Instruction> iterator() {
		return this;
	}

	@Override
	public boolean hasNext() {
		return it.hasNext();
	}

	@Override
	public Instruction next() {
		return it.next();
	}
}
