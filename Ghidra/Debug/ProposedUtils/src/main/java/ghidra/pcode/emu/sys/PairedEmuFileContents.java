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
package ghidra.pcode.emu.sys;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.exec.PairedPcodeExecutorStatePiece;

/**
 * The analog of {@link PairedPcodeExecutorStatePiece} for simulated file contents
 * 
 * @param <L> the type of values for the left
 * @param <R> the type of values for the right
 */
public class PairedEmuFileContents<L, R> implements EmuFileContents<Pair<L, R>> {
	protected final EmuFileContents<L> left;
	protected final EmuFileContents<R> right;

	/**
	 * Create a paired file contents
	 * 
	 * @param left the left contents
	 * @param right the right contents
	 */
	public PairedEmuFileContents(EmuFileContents<L> left, EmuFileContents<R> right) {
		this.left = left;
		this.right = right;
	}

	@Override
	public long read(long offset, Pair<L, R> buf, long fileSize) {
		long result = left.read(offset, buf.getLeft(), fileSize);
		right.read(offset, buf.getRight(), fileSize);
		return result;
	}

	@Override
	public long write(long offset, Pair<L, R> buf, long curSize) {
		long result = left.write(offset, buf.getLeft(), curSize);
		right.write(offset, buf.getRight(), curSize);
		return result;
	}

	@Override
	public void truncate() {
		left.truncate();
		right.truncate();
	}
}
