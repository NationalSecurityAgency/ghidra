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
package ghidra.program.model.block;

import java.util.Iterator;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * An iterator interface over CodeBlocks.
 * 
 * <P>Note: this iterator is also {@link Iterable}.  The {@link #hasNext()} and {@link #next()}
 * methods of this interface throw a {@link CancelledException} if the monitor is cancelled.  The
 * iterator returned from {@link #iterator()} does <b>not</b> throw a cancelled exception.  If 
 * you need to know the cancelled state of this iterator, then you must check the cancelled state
 * of the monitor passed into this iterator via the {@link CodeBlockModel}.  See 
 * {@link TaskMonitor#isCancelled()}.  
 * 
 * @see ghidra.program.model.block.CodeBlock
 * @see CollectionUtils#asIterable
 */
public interface CodeBlockIterator extends Iterable<CodeBlock> {

	/**
	 * Return true if next() will return a CodeBlock.
	 * @return true if next() will return a CodeBlock.
	 * @throws CancelledException thrown if the operation is cancelled.
	 */
	public boolean hasNext() throws CancelledException;

	/**
	 * Return the next CodeBlock.
	 * @return the next CodeBlock.
	 * @throws CancelledException thrown if the operation is cancelled.
	 */
	public CodeBlock next() throws CancelledException;

	@Override
	default Iterator<CodeBlock> iterator() {
		return new Iterator<>() {
			@Override
			public boolean hasNext() {
				try {
					return CodeBlockIterator.this.hasNext();
				}
				catch (CancelledException e) {
					return false;
				}
			}

			@Override
			public CodeBlock next() {
				try {
					return CodeBlockIterator.this.next();
				}
				catch (CancelledException e) {
					return null;
				}
			}
		};
	}
}
