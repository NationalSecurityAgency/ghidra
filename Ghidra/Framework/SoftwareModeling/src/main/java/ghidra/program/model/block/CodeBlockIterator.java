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

import ghidra.util.exception.CancelledException;
import util.CollectionUtils;

/**
 * An iterator interface over CodeBlocks.
 * 
 * @see ghidra.program.model.block.CodeBlock
 * @see CollectionUtils#asIterable
 */ 
public interface CodeBlockIterator {

    /**
     * Return true if next() will return a CodeBlock.
     * @throws CancelledException thrown if the operation is cancelled.
     */
	public boolean hasNext() throws CancelledException;

    /**
     * Return the next CodeBlock.
     * @throws CancelledException thrown if the operation is cancelled.
     */
    public CodeBlock next() throws CancelledException;
}
