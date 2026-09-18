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
package ghidra.feature.vt.api.correlator.program;

import java.util.*;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Computes per-basic-block mnemonic hashes for a function. For each basic block,
 * mnemonic hashes are collected, sorted (to tolerate instruction reordering by
 * the compiler), and combined into a single per-block hash.
 *
 * <p>Also provides {@link #getBulkSimilarity(List, List)} for comparing two
 * functions' block-hash lists via sorted-merge counting.</p>
 */
public class BasicBlockMnemonicFunctionBulker implements FunctionBulker {

	public static final BasicBlockMnemonicFunctionBulker INSTANCE =
		new BasicBlockMnemonicFunctionBulker();

	@Override
	public List<Long> hashes(Function func, TaskMonitor monitor) throws CancelledException {
		List<Long> bbhashes = new ArrayList<>();

		CodeBlockModel blockModel = new BasicBlockModel(func.getProgram());
		AddressSetView addresses = func.getBody();
		CodeBlockIterator bbiter = blockModel.getCodeBlocksContaining(addresses, monitor);

		while (!monitor.isCancelled() && bbiter.hasNext()) {
			CodeBlock block = bbiter.next();
			List<Long> mnemonicHashes = new ArrayList<>();
			CodeUnitIterator iter = func.getProgram().getListing().getCodeUnits(block, true);
			while (!monitor.isCancelled() && iter.hasNext()) {
				CodeUnit next = iter.next();
				mnemonicHashes.add((long) next.getMnemonicString().hashCode());
			}
			// Sort mnemonics so compiler instruction reordering doesn't affect the hash
			Collections.sort(mnemonicHashes);

			long bbhash = 0;
			for (long hash : mnemonicHashes) {
				bbhash = bbhash * 31 + hash;
			}
			bbhashes.add(bbhash);
		}
		return bbhashes;
	}

	/**
	 * Compute the similarity between two functions' block-hash lists.
	 * Uses a sorted-merge to count common elements.
	 *
	 * @param srcList block hashes for the source function
	 * @param dstList block hashes for the destination function
	 * @return similarity score in [0.0, 1.0], or 0.0 if both lists are empty
	 */
	public static double getBulkSimilarity(List<Long> srcList, List<Long> dstList) {
		int total = Math.max(srcList.size(), dstList.size());
		if (total == 0) {
			return 0.0;
		}

		List<Long> sortedSrc = new ArrayList<>(srcList);
		List<Long> sortedDst = new ArrayList<>(dstList);
		Collections.sort(sortedSrc);
		Collections.sort(sortedDst);

		// Count matching basic-block hashes via sorted-merge
		int common = 0;
		int s = 0;
		int d = 0;
		while (s < sortedSrc.size() && d < sortedDst.size()) {
			int c = sortedSrc.get(s).compareTo(sortedDst.get(d));
			if (c < 0) {
				s++;
			}
			else if (c > 0) {
				d++;
			}
			else {
				common++;
				s++;
				d++;
			}
		}
		return (double) common / (double) total;
	}

	/**
	 * Compute a combined similarity score that accounts for both mnemonic
	 * block-hash overlap and stack frame size differences.
	 *
	 * <p>The combined score is a weighted blend:
	 * <ul>
	 *   <li><b>Mnemonic similarity (80%)</b> – sorted-merge count of matching
	 *       per-basic-block mnemonic hashes, as computed by
	 *       {@link #getBulkSimilarity(List, List)}.</li>
	 *   <li><b>Stack frame similarity (20%)</b> – measures how similar the two
	 *       functions' stack frame sizes are. Uses the formula
	 *       {@code min(a,b) / max(a,b)} when both are nonzero, giving 1.0 for
	 *       identical sizes and approaching 0.0 as they diverge. When both sizes
	 *       are zero the score is 1.0 (perfect match); when only one is zero the
	 *       score is 0.0 (one function uses stack, the other does not).</li>
	 * </ul>
	 *
	 * @param srcHashes block hashes for the source function
	 * @param dstHashes block hashes for the destination function
	 * @param srcFrameSize stack frame size (bytes) of the source function
	 * @param dstFrameSize stack frame size (bytes) of the destination function
	 * @return combined similarity score in [0.0, 1.0]
	 */
	public static double getCombinedSimilarity(List<Long> srcHashes, List<Long> dstHashes,
			int srcFrameSize, int dstFrameSize) {

		// Mnemonic block-hash similarity (core structural comparison)
		double mnemonicScore = getBulkSimilarity(srcHashes, dstHashes);

		// Stack frame size similarity (detects differences in local variable allocation)
		double stackScore = getStackSizeSimilarity(srcFrameSize, dstFrameSize);

		// Weighted combination (95/5): mnemonics are the primary structural signal;
		// stack size is a subtle tiebreaker that distinguishes otherwise-identical matches
		// (e.g. two functions with the same mnemonic sequence but different local buffers).
		return 0.95 * mnemonicScore + 0.05 * stackScore;
	}

	/**
	 * Compute how similar two stack frame sizes are.
	 *
	 * <p>Returns {@code min / max} when both are positive, 1.0 when both are
	 * zero, and 0.0 when exactly one is zero. This captures cases like patch
	 * diffs that add/remove local buffers (changing stack size) even when the
	 * mnemonic sequence is nearly identical.
	 *
	 * @param srcSize stack frame size of the source function
	 * @param dstSize stack frame size of the destination function
	 * @return similarity in [0.0, 1.0]
	 */
	private static double getStackSizeSimilarity(int srcSize, int dstSize) {
		if (srcSize == 0 && dstSize == 0) {
			return 1.0; // Both leaf/no-stack functions — perfect match
		}
		if (srcSize == 0 || dstSize == 0) {
			return 0.0; // One uses stack, the other doesn't — maximum penalty
		}
		// Ratio of smaller to larger; e.g. 64/128 = 0.5
		return (double) Math.min(srcSize, dstSize) / (double) Math.max(srcSize, dstSize);
	}
}
