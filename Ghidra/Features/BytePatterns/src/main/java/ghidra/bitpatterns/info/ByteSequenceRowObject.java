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

import java.util.*;

import ghidra.util.bytesearch.DittedBitSequence;

/**
 * Objects in this class represent rows in tables for analyzing sequences of bytes.
 * Each sequence of bytes is associated with a {@link String} containing the instructions 
 * disassembled from the bytes, the number of times this particular sequence occurs,
 * and the percentage of all byte sequences collected which are equal to this byte
 * sequence.
 */
public class ByteSequenceRowObject {
	private String byteSequence;
	private String disassembly;
	private int numOccurrences;
	private double percentage;
	private static final int HEX_DIGITS_PER_BYTE = 2;

	/**
	 * Creates a row in a byte sequence table
	 * @param byteSequence byte sequence
	 * @param disassembly string representation of disassembly of byte sequence
	 * @param numOccurences number of occurrences of sequence
	 * @param percentage percentage of number of occurrences of this sequences compared to
	 * all sequences in table
	 */
	public ByteSequenceRowObject(String byteSequence, String disassembly, int numOccurences,
			double percentage) {
		this.byteSequence = byteSequence;
		this.disassembly = disassembly;
		this.numOccurrences = numOccurences;
		this.percentage = percentage;
	}

	/**
	 * Returns the {@link ByteSequenceRowObjects} of {@link PatternType} in {@code unfilteredInfo} which
	 * pass the context register filter and the length filter
	 *  
	 * @param unfilteredInfo information about function starts/pre-starts/returns
	 * @param type desired {@code PatternType}
	 * @param registerFilter {@ContextRegisterFilter} to apply
	 * @param lengthFilter {@ByteSequenceLengthFilter} to apply
	 * @return filtered row objects
	 */
	public static List<ByteSequenceRowObject> getFilteredRowObjects(
			List<FunctionBitPatternInfo> unfilteredInfo, PatternType type,
			ContextRegisterFilter registerFilter, ByteSequenceLengthFilter lengthFilter) {
		Map<String, Integer> byteSeqCounts = new HashMap<String, Integer>();
		Map<String, String> bytesToDisassembly = new HashMap<String, String>();
		int numTotalSeqs = 0;
		for (FunctionBitPatternInfo fInfo : unfilteredInfo) {
			if (failsFilter(fInfo, registerFilter)) {
				continue;
			}
			List<String> byteStrings = getAllByteStringsOfType(fInfo, type);
			FilteredBytesAndDisassembly fAndD =
				getFilteredBytesAndDisassembly(byteStrings, lengthFilter, fInfo, type);

			int numFilteredStrings = fAndD.getFilteredBytes().size();
			for (int i = 0; i < numFilteredStrings; ++i) {
				//only record the disassembly string if it's longer than what is there already
				//this is important for prebyte strings, where sometimes the bytes will have been
				//disassembled by ghidra and sometimes they won't have been
				String currentFilteredByteString = fAndD.getFilteredBytes().get(i);
				String currentDis = bytesToDisassembly.get(currentFilteredByteString);
				List<String> disassembly = fAndD.getDisassembly();
				if (currentDis == null || currentDis.length() < disassembly.get(i).length()) {
					if (!(disassembly.get(i).contains("null"))) {
						bytesToDisassembly.put(currentFilteredByteString, disassembly.get(i));
					}
				}
				if (byteSeqCounts.containsKey(currentFilteredByteString)) {
					Integer count = byteSeqCounts.get(currentFilteredByteString);
					byteSeqCounts.put(currentFilteredByteString, count + 1);
					numTotalSeqs++;
				}
				else {
					byteSeqCounts.put(currentFilteredByteString, new Integer(1));
					numTotalSeqs++;
				}
			}
		}
		return getRowObjectsForLengthFilteredSeqs(byteSeqCounts, bytesToDisassembly, numTotalSeqs);
	}

	private static List<ByteSequenceRowObject> getRowObjectsForLengthFilteredSeqs(
			Map<String, Integer> byteSeqCounts, Map<String, String> bytesToDisassembly,
			int numTotalSeqs) {
		List<ByteSequenceRowObject> rowObjects = new ArrayList<ByteSequenceRowObject>();
		//iterate over the keyset of the paircount
		for (String bytes : byteSeqCounts.keySet()) {
			Integer count = byteSeqCounts.get(bytes);
			ByteSequenceRowObject rowObject = new ByteSequenceRowObject(bytes,
				bytesToDisassembly.get(bytes), count, 100.0 * count / numTotalSeqs);
			rowObjects.add(rowObject);
		}
		return rowObjects;
	}

	private static FilteredBytesAndDisassembly getFilteredBytesAndDisassembly(
			List<String> byteStrings, ByteSequenceLengthFilter lengthFilter,
			FunctionBitPatternInfo fInfo, PatternType type) {
		List<String> disassembly = new ArrayList<String>();
		List<String> filteredByteStrings = new ArrayList<String>();
		for (int i = 0, numStrings = byteStrings.size(); i < numStrings; ++i) {
			String currentByteString = byteStrings.get(i);
			if (lengthFilter != null) {
				String filteredString = lengthFilter.filter(currentByteString);
				//if it is null, the string does not meet the 
				//minimum length requirements of the filter
				if (filteredString != null) {
					filteredByteStrings.add(filteredString);
					disassembly.add("partial bytestring");
				}
			}
			else {
				if (currentByteString != null) {
					filteredByteStrings.add(currentByteString);
					disassembly.add(getCompleteDisassembly(fInfo, type,
						type.equals(PatternType.RETURN) ? i : 0));
				}
			}
		}
		FilteredBytesAndDisassembly fAndD =
			new FilteredBytesAndDisassembly(filteredByteStrings, disassembly);
		return fAndD;
	}

	//get all of the byte strings of PatternType type in fInfo
	private static List<String> getAllByteStringsOfType(FunctionBitPatternInfo fInfo,
			PatternType type) {
		List<String> byteStringList = new ArrayList<String>();
		switch (type) {
			case FIRST:
				byteStringList.add(fInfo.getFirstBytes());
				break;
			case PRE:
				byteStringList.add(fInfo.getPreBytes());
				break;
			case RETURN:
				byteStringList.addAll(fInfo.getReturnBytes());
				break;
			default:
				throw new IllegalArgumentException("unsupported PatternType: " + type.name());
		}
		return byteStringList;
	}

	private static String getCompleteDisassembly(FunctionBitPatternInfo fInfo, PatternType type,
			int i) {
		switch (type) {
			case FIRST:
				return fInfo.getFirstInst().getCompleteDisassembly(true);
			case PRE:
				return fInfo.getPreInst().getCompleteDisassembly(false);
			case RETURN:
				return fInfo.getReturnInst().get(i).getCompleteDisassembly(false);
			default:
				throw new IllegalArgumentException("Unsupported PatternType: " + type.name());
		}
	}

	/**
	 * Returns a string containing the disassembly in {@code instSeq} up to the number
	 * of instructions specified in {@code pathFilter}
	 * @param instSeq sequence of instruction
	 * @param pathFilter filter specifying number of instructions
	 * @return
	 */
	private static String getDisassemblyForTreePath(InstructionSequence instSeq,
			InstructionSequenceTreePathFilter pathFilter) {
		int numInstructions = pathFilter.getInstructions().size();
		boolean inOrder = pathFilter.getInstructionType().equals(PatternType.FIRST);
		return instSeq.getDisassembly(numInstructions, inOrder);
	}

	/**
	 * Get the sequence of bytes
	 * @return byte sequence
	 */
	public String getSequence() {
		return byteSequence;
	}

	/**
	 * Get the disassembly of as a string
	 * @return disassembly string
	 */
	public String getDisassembly() {
		return disassembly;
	}

	/**
	 * Get the number of occurrences of this sequence
	 * @return number of occurrences
	 */
	public int getNumOccurrences() {
		return numOccurrences;
	}

	/**
	 * Get the percentage of the number of occurrences of this sequence relative to all
	 * sequences in the table
	 * @return
	 */
	public double getPercentage() {
		return percentage;
	}

	/**
	 * Get the byte sequences whose corresponding instruction sequences pass
	 * {@code pathFilter}
	 * @param unfilteredInfo data source
	 * @param pathFilter path filter
	 * @param contextRegisterFilter context register filter
	 * @param type pattern type
	 * @return byte sequences
	 */
	public static List<ByteSequenceRowObject> getRowObjectsFromInstructionSequences(
			List<FunctionBitPatternInfo> unfilteredInfo, InstructionSequenceTreePathFilter pathFilter,
			ContextRegisterFilter contextRegisterFilter) {

		int numBytes = pathFilter.getTotalLength();
		Map<BytesAndDisassembly, Integer> bytesAndDisCount = new HashMap<>();
		int numTotalSeqs = 0;

		for (FunctionBitPatternInfo fInfo : unfilteredInfo) {
			if (failsFilter(fInfo, contextRegisterFilter)) {
				continue;
			}

			List<InstructionSequence> instSeqs = getInstructionSequences(pathFilter, fInfo);

			for (int i = 0, numSeqs = instSeqs.size(); i < numSeqs; i++) {
				InstructionSequence currentSeq = instSeqs.get(i);
				if (!pathFilter.allows(currentSeq)) {
					continue;
				}
				numTotalSeqs++;
				String totalBytes = null;
				int totalBytesLen = 0;
				String bytes = null;
				String disassembly = null;
				switch (pathFilter.getInstructionType()) {
					case FIRST:
						if (fInfo.getFirstBytes() == null) {
							break;
						}
						totalBytes = fInfo.getFirstBytes();
						bytes = totalBytes.substring(0, HEX_DIGITS_PER_BYTE * numBytes);
						disassembly = getDisassemblyForTreePath(currentSeq, pathFilter);
						break;
					case PRE:
						if (fInfo.getPreBytes() == null) {
							break;
						}
						totalBytes = fInfo.getPreBytes();
						totalBytesLen = totalBytes.length();
						bytes = totalBytes.substring(totalBytesLen - HEX_DIGITS_PER_BYTE * numBytes,
							totalBytesLen);
						disassembly = getDisassemblyForTreePath(currentSeq, pathFilter);
						break;
					case RETURN:
						if (fInfo.getReturnBytes() == null || fInfo.getReturnBytes().size() <= i) {
							break;
						}
						totalBytes = fInfo.getReturnBytes().get(i);
						totalBytesLen = totalBytes.length();
						bytes = totalBytes.substring(totalBytesLen - HEX_DIGITS_PER_BYTE * numBytes,
							totalBytesLen);
						disassembly = getDisassemblyForTreePath(currentSeq, pathFilter);
						break;
					default:
						throw new IllegalArgumentException(
							"unsupported type: " + pathFilter.getInstructionType().name());
				}
				incrementCountMap(bytesAndDisCount, bytes, disassembly);
			}
		}
		return getRowObjectsForPathFilteredSeqs(bytesAndDisCount, numTotalSeqs);
	}

	private static List<ByteSequenceRowObject> getRowObjectsForPathFilteredSeqs(
			Map<BytesAndDisassembly, Integer> bytesAndDisCount, int numTotalSeqs) {
		List<ByteSequenceRowObject> returnRowObjects = new ArrayList<ByteSequenceRowObject>();
		for (BytesAndDisassembly bytesAndDisassembly : bytesAndDisCount.keySet()) {
			Integer count = bytesAndDisCount.get(bytesAndDisassembly);
			ByteSequenceRowObject rowObject =
				new ByteSequenceRowObject(bytesAndDisassembly.getBytes(),
					bytesAndDisassembly.getDisassembly(), count, 100.0 * count / numTotalSeqs);
			returnRowObjects.add(rowObject);
		}
		return returnRowObjects;
	}

	//return true if fInfo fails the filter (if cRegFilter is null then it passes)
	private static boolean failsFilter(FunctionBitPatternInfo fInfo,
			ContextRegisterFilter cRegFilter) {
		if (cRegFilter == null) {
			return false;
		}
		return !cRegFilter.allows(fInfo.getContextRegisters());
	}

	private static void incrementCountMap(Map<BytesAndDisassembly, Integer> bytesAndDisCount,
			String bytes, String disassembly) {
		BytesAndDisassembly bytesAndDisassembly = new BytesAndDisassembly(bytes, disassembly);
		if (bytesAndDisCount.containsKey(bytesAndDisassembly)) {
			Integer count = bytesAndDisCount.get(bytesAndDisassembly);
			bytesAndDisCount.put(bytesAndDisassembly, count + 1);
		}
		else {
			bytesAndDisCount.put(bytesAndDisassembly, new Integer(1));
		}
	}

	private static List<InstructionSequence> getInstructionSequences(
			InstructionSequenceTreePathFilter pathFilter, FunctionBitPatternInfo fInfo) {
		List<InstructionSequence> instSeqs = new ArrayList<InstructionSequence>();
		switch (pathFilter.getInstructionType()) {
			case FIRST:
				if (fInfo.getFirstBytes() != null) {
					instSeqs.add(fInfo.getFirstInst());
				}
				break;
			case PRE:
				if (fInfo.getPreBytes() != null) {
					instSeqs.add(fInfo.getPreInst());
				}
				break;
			case RETURN:
				List<String> retBytes = fInfo.getReturnBytes();
				if (retBytes.size() != fInfo.getReturnInst().size()) {
					break;
				}
				boolean valid = true;
				for (String bytes : retBytes) {
					if (bytes == null) {
						valid = false;
					}
				}
				if (valid) {
					instSeqs.addAll(fInfo.getReturnInst());
				}
				break;
			default:
				throw new IllegalArgumentException("bad type");
		}
		return instSeqs;
	}

	/**
	 * Merge byte sequences into one {@link DittedBitSequence}
	 * @param rowObjects sequences to merge
	 * @return merged sequences
	 */
	public static DittedBitSequence merge(List<ByteSequenceRowObject> rowObjects) {
		if (rowObjects == null || rowObjects.size() == 0) {
			return null;
		}

		List<DittedBitSequence> dittedSeqs = new ArrayList<>();
		for (ByteSequenceRowObject currentRow : rowObjects) {
			DittedBitSequence currentSeq = new DittedBitSequence(currentRow.getSequence(), true);
			dittedSeqs.add(currentSeq);
		}
		DittedBitSequence currentMerge = dittedSeqs.get(0);
		for (int i = 1, max = dittedSeqs.size(); i < max; ++i) {
			currentMerge = new DittedBitSequence(currentMerge, dittedSeqs.get(i));
		}
		return currentMerge;
	}

}
