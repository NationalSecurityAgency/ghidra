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
package ghidra.bitpatterns.gui;

import java.awt.Component;
import java.util.*;

import ghidra.bitpatterns.info.*;
import ghidra.closedpatternmining.*;
import ghidra.util.Msg;
import ghidra.util.bytesearch.DittedBitSequence;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * Objects in this class are used to display a closed pattern found by the 
 * pattern miner.
 *
 */
public class ClosedPatternRowObject {
	private String dittedString;
	private int fixedBits;
	private int numOccurrences;
	private double percentage;
	private PatternInfoRowObject patternInfo;

	private ClosedPatternRowObject(String minedString, int fixedBits, int numOccurrences,
			double percentage, boolean isBinary, PatternType type,
			ContextRegisterFilter cRegFilter) {
		this.fixedBits = fixedBits;
		this.numOccurrences = numOccurrences;
		this.percentage = percentage;
		this.patternInfo = getPatternInfo(minedString, isBinary, type, cRegFilter);
		this.dittedString = patternInfo.getDittedBitSequence().getHexString();
	}

	private PatternInfoRowObject getPatternInfo(String minedString, boolean isBinary,
			PatternType type, ContextRegisterFilter cRegFilter) {
		DittedBitSequence seq = null;
		if (isBinary) {
			seq = getDittedBitSequenceBinary(minedString);
		}
		else {
			seq = getDittedBitSequenceNibble(minedString);
		}
		return new PatternInfoRowObject(type, seq, cRegFilter);
	}

	/*The sequence miner has produced ditted strings of hexadecimal digits
	 *convert to a ditted binary string before passing to the DittedBitSequence
	 *constructor
	 */
	private DittedBitSequence getDittedBitSequenceNibble(String minedString) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < minedString.length(); i++) {
			if (minedString.charAt(i) == '.') {
				sb.append("....");
			}
			else {
				String nibble = minedString.substring(i, i + 1);
				String binaryString = Integer.toBinaryString(Integer.parseInt(nibble, 16));
				int missing = 4 - binaryString.length();
				switch (missing) {
					case 1:
						binaryString = "0" + binaryString;
						break;
					case 2:
						binaryString = "00" + binaryString;
						break;
					case 3:
						binaryString = "000" + binaryString;
						break;
					default:
						break;
				}
				sb.append(binaryString);
			}
		}
		return new DittedBitSequence(sb.toString(), false);
	}

	private DittedBitSequence getDittedBitSequenceBinary(String minedString) {
		DittedBitSequence seq = new DittedBitSequence(minedString, false);
		return seq;
	}

	/**
	 * Mine closed patterns from the byte sequences.
	 * 
	 * @param byteSeqRowObjects byte sequences to mine
	 * @param minPercentage minimum percentage of byte sequences that a pattern should be in
	 * @param minFixedBits minimum number of fixed bits that a pattern should contain
	 * @param useBinary whether to consider the sequences as binary sequences or character sequences
	 * @param type pattern type of row objects
	 * @param cRegFilter context register filter used when gathering row objects (can be {@code null})
	 * @param parent Component parent for the Task Dialog (can be {@code null})
	 * @return closed sequences
	 */
	public static List<ClosedPatternRowObject> mineClosedPatterns(
			List<ByteSequenceRowObject> byteSeqRowObjects, double minPercentage, int minFixedBits,
			boolean useBinary, PatternType type, ContextRegisterFilter cRegFilter,
			Component parent) {
		List<Sequence> seqsToMine = new ArrayList<>();
		for (ByteSequenceRowObject byteSeqRowObject : byteSeqRowObjects) {
			String seq = byteSeqRowObject.getSequence();
			Integer count = byteSeqRowObject.getNumOccurrences();
			if (useBinary) {
				StringBuilder paddedString = new StringBuilder();
				for (int i = 0; i < seq.length(); ++i) {
					String currentChar = seq.substring(i, i + 1);
					String unpaddedChar = Integer.toBinaryString(Integer.parseInt(currentChar, 16));
					StringBuilder paddedChar = new StringBuilder();
					switch (unpaddedChar.length()) {
						case 1:
							paddedChar.append("000");
							break;
						case 2:
							paddedChar.append("00");
							break;
						case 3:
							paddedChar.append("0");
							break;
						case 4:
							break;
						default:
							Msg.info(ClosedPatternRowObject.class,
								"Shouldn't happen, unpaddedString = " + unpaddedChar);
					}
					paddedString.append(paddedChar);
					paddedString.append(unpaddedChar);
				}
				seq = paddedString.toString();
			}
			seqsToMine.add(new Sequence(seq, count));
		}
		int length = byteSeqRowObjects.get(0).getSequence().length();
		if (useBinary) {
			length = 4 * length;
		}

		SequenceDatabase database = new SequenceDatabase(seqsToMine, length);

		int minSupport = (int) (database.getTotalNumSeqs() * minPercentage);
		ClosedSequenceMiner miner = new ClosedSequenceMiner(database, minSupport);
		Set<FrequentSequence> closedSeqs = null;
		//for testing
		if (parent == null) {
			closedSeqs = miner.mineClosedSequences(TaskMonitor.DUMMY);
		}
		else {
			MineSequenceTask mineTask = new MineSequenceTask(miner);
			@SuppressWarnings("unused")
			TaskLauncher launcher = new TaskLauncher(mineTask, parent);
			closedSeqs = mineTask.getClosedSeqs();
		}

		List<ClosedPatternRowObject> rowObjects = new ArrayList<ClosedPatternRowObject>();
		int totalNumSeqs = database.getTotalNumSeqs();
		for (FrequentSequence seq : closedSeqs) {
			ClosedPatternRowObject rowObject = createClosedPatternRowObject(seq.getSequence(),
				seq.getSupport(), totalNumSeqs, useBinary, length, type, cRegFilter);
			if (rowObject.getNumFixedBits() >= minFixedBits) {
				rowObjects.add(rowObject);
			}
		}
		Msg.info(ClosedPatternRowObject.class, "\nFound " + closedSeqs.size() + " patterns");
		return rowObjects;
	}

	private static ClosedPatternRowObject createClosedPatternRowObject(List<SequenceItem> items,
			Integer support, int totalNumSeqs, boolean isBinary, int length, PatternType type,
			ContextRegisterFilter cRegFilter) {

		String dittedString = getDittedStringFromItemList(items, length);
		int fixedBits = getFixedBits(items);
		if (!isBinary) {
			fixedBits *= 4;
		}
		double percentage = Math.round((100.0 * support) / totalNumSeqs);
		return new ClosedPatternRowObject(dittedString, fixedBits, support, percentage, isBinary,
			type, cRegFilter);
	}

	private static int getFixedBits(List<SequenceItem> items) {
		return items.size();
	}

	private static String getDittedStringFromItemList(List<SequenceItem> items, int length) {
		StringBuilder sb = new StringBuilder();
		int currentPosition = 0;
		for (SequenceItem item : items) {
			while (currentPosition < item.getIndex()) {
				sb.append(".");
				currentPosition++;
			}
			sb.append(item.getSymbol());
			currentPosition++;
		}
		while (sb.length() < length) {
			sb.append(".");
		}

		return sb.toString();
	}

	/**
	 * Return the ditted string for the closed pattern.
	 * @return ditted string
	 */
	public String getDittedString() {
		return dittedString;
	}

	/**
	 * Get the number of fixed bits in the pattern.
	 * @return number fixed bits
	 */
	public int getNumFixedBits() {
		return fixedBits;
	}

	/**
	 * Get the number of occurrences of the pattern
	 * @return number of occurrences
	 */
	public int getNumOccurrences() {
		return numOccurrences;
	}

	/**
	 * Get the percentage of sequences which contain this pattern
	 * @return percentage containing pattern
	 */
	public double getPercentage() {
		return percentage;
	}

	/**
	 * Get the {@link PatternInfoRowObject} for this closed pattern 
	 * @return the {@link PatternInfoRowObject}
	 */
	public PatternInfoRowObject getPatternInfo() {
		return patternInfo;
	}

}
