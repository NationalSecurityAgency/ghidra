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
package ghidra.bitpatterns.info;

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

/**
 * This class is used to filter {@code InstructionSequence}s.  
 */

public class InstructionSequenceTreePathFilter {

	private List<String> instructions;//list of instructions that must be matches
	private List<Integer> lengths;//list of lengths of instructions that must be matches
	private PatternType type;//the type of the instructions!

	/**
	 * Create an InstSeqTreePathFilter based on a {@link Treepath} and an {@link InstructionType}.
	 * @param path {@link InstructionSequence}s must be consistent with this path in order to pass the filter.
	 * @param type the type of instructions to filter.
	 */
	public InstructionSequenceTreePathFilter(TreePath path, PatternType type) {
		//start at 1 instead of 0 because we don't care about the root node
		instructions = new ArrayList<String>();
		lengths = new ArrayList<Integer>();
		this.type = type;
		for (int i = 1; i < path.getPathCount(); ++i) {
			if (!(path.getPathComponent(i) instanceof FunctionBitPatternsGTreeNode)) {
				throw new IllegalArgumentException(
					"non-root nodes must be members of class FunctionStartPatternsGTreeNode");
			}
			FunctionBitPatternsGTreeNode currentNode =
				(FunctionBitPatternsGTreeNode) path.getPathComponent(i);
			String currentInstruction = currentNode.getInstruction();
			Integer currentNumBytes = currentNode.getNumBytes();
			if ((currentInstruction == null) || (currentNumBytes == null)) {
				throw new IllegalArgumentException(
					"Can't have null instructions or lengths in the path!");
			}
			instructions.add(currentInstruction);
			lengths.add(currentNumBytes);
		}

	}

	/**
	 * Create an InstSeqTreePathFilter explicitly.
	 * 
	 * @param insts instructions to match
	 * @param lens lenghts of instructions
	 * @param type type of instructions
	 */
	public InstructionSequenceTreePathFilter(List<String> insts, List<Integer> lens,
			PatternType pType) {
		instructions = insts;
		lengths = lens;
		type = pType;
	}

	/**
	 * Determine whether {@link instSeq} passes the filter.
	 * @param instSeq
	 * @return {@code true} precisely when each instruction and size in the filter matches those in {@link InstSeq}.
	 */
	public boolean allows(InstructionSequence instSeq) {
		if (instSeq.getInstructions() == null) {
			return false;
		}
		//filter wants to check more instructions that this InstructionSequence has, so return false
		if (instSeq.getInstructions().length < instructions.size()) {
			return false;
		}

		for (int i = 0; i < instructions.size(); ++i) {
			String currentInst = instSeq.getInstructions()[i];
			if (currentInst == null) {
				return false;//ith instruction in filter can't be null - see constructor
			}
			if (!(currentInst.equals(instructions.get(i)))) {
				return false;
			}

			Integer currentSize = instSeq.getSizes()[i];
			if (currentSize == null) {
				return false;//ditto for the ith size
			}
			if (!currentSize.equals(lengths.get(i))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < instructions.size(); ++i) {
			sb.append(instructions.get(i));
			sb.append(":");
			sb.append(lengths.get(i));
			if (i != instructions.size() - 1) {
				sb.append(", ");
			}
		}
		return sb.toString();
	}

	/**
	 * Returns the list of instructions in this filter
	 * @return instruction list
	 */
	public List<String> getInstructions() {
		return instructions;
	}

	/**
	 * Returns the lengths of the instructions in this filter
	 * @return length list
	 */
	public List<Integer> getLengths() {
		return lengths;
	}

	/**
	 * Returns the sum of the lengths of all of the instructions in this filter
	 * @return sum of all the lengths
	 */
	public int getTotalLength() {
		int totalLength = 0;
		for (Integer length : lengths) {
			totalLength += length;
		}
		return totalLength;
	}

	/**
	 * Returns the type of the instructions in this filter
	 * @return type
	 */
	public PatternType getInstructionType() {
		return type;
	}
}
