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
package ghidra.pcode.exec;

import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * A plain concrete state piece without any backing objects
 */
public class BytesPcodeExecutorStatePiece
		extends AbstractBytesPcodeExecutorStatePiece<BytesPcodeExecutorStateSpace> {

	/**
	 * Construct a state for the given language
	 * 
	 * @param language the language (used for its memory model)
	 * @param cb callbacks to receive emulation events
	 */
	public BytesPcodeExecutorStatePiece(Language language, PcodeStateCallbacks cb) {
		super(language, cb);
	}

	@Override
	public BytesPcodeExecutorStatePiece fork(PcodeStateCallbacks cb) {
		BytesPcodeExecutorStatePiece result = new BytesPcodeExecutorStatePiece(language, cb);
		forkMap(result.spaceMap, this.spaceMap, s -> s.fork(result));
		return result;
	}

	@Override
	protected BytesPcodeExecutorStateSpace newSpace(AddressSpace space) {
		return new BytesPcodeExecutorStateSpace(language, space, this);
	}

	@Override
	public Entry<Long, byte[]> getNextEntryInternal(AddressSpace space, long offset) {
		BytesPcodeExecutorStateSpace s = getForSpace(space, false);
		if (s == null) {
			return null;
		}
		ULongSpanSet initialized = s.bytes.getInitialized(0, -1);
		ULongSpan span = initialized.spanContaining(offset);
		if (span == null) {
			var it = initialized.intersecting(ULongSpan.span(offset, -1)).iterator();
			if (!it.hasNext()) {
				return null;
			}
			span = it.next();
		}
		byte[] data = new byte[(int) span.length()];
		s.bytes.getData(span.min(), data);
		return Map.entry(span.min(), data);
	}
}
