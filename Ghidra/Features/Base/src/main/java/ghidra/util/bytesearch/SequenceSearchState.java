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
package ghidra.util.bytesearch;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.util.task.TaskMonitor;

/**
 * SeqenceSearchState holds the state of a search for a DittedBitSequence within a byte
 * sequence.
 */
public class SequenceSearchState implements Comparable<SequenceSearchState> {

	private static final int PATTERN_ENDED = Integer.MAX_VALUE;
	private SequenceSearchState parent;
	private ArrayList<DittedBitSequence> possible;		// Patterns that could still match in this state
	private ArrayList<DittedBitSequence> success;		// Patterns that have matched successfully if we reached this state
	private SequenceSearchState[] trans;				// State transitions based on next byte

	/**
	 * Construct a sub sequence state with a parent sequence
	 * 
	 * @param parent parent SequenceSearchState
	 */
	public SequenceSearchState(SequenceSearchState parent) {
		this.parent = parent;
		possible = new ArrayList<DittedBitSequence>();
		success = null;
		trans = null;
	}

	/**
	 * @return maximum number of bytes that could be matched by this sequence
	 */
	public int getMaxSequenceSize() {
		int max = 0;
		for (DittedBitSequence element : possible) {
			int val = element.getSize();
			if (val > max) {
				max = val;
			}
		}
		return max;
	}

	/**
	 * Add a pattern to this search sequence.  The last pattern added is the successful
	 * match pattern.
	 * @param pat pattern to add
	 * @param pos position within the current set of patterns to add this pattern
	 */
	public void addSequence(DittedBitSequence pat, int pos) {
		possible.add(pat);
		if (pos == pat.getSize()) {
			if (success == null) {
				success = new ArrayList<DittedBitSequence>();
			}
			success.add(pat);
		}
	}

	/**
	 * Sort the sequences that have been added 
	 */
	public void sortSequences() {
		Comparator<DittedBitSequence> comp = new Comparator<DittedBitSequence>() {
			@Override
			public int compare(DittedBitSequence o1, DittedBitSequence o2) {
				return o1.getIndex() - o2.getIndex();
			}
		};
		Collections.sort(possible, comp);
		if (success != null) {
			Collections.sort(success, comp);
		}
	}

	@Override
	public int compareTo(SequenceSearchState o) {
		int i = 0;
		for (;;) {
			if (possible.size() <= i) {
				if (o.possible.size() <= i) {
					return 0;
				}
				return -1;
			}
			if (o.possible.size() <= i) {
				return 1;
			}
			int indus = possible.get(i).getIndex();		// Lexicographic compare an sequence of sequences
			int indthem = o.possible.get(i).getIndex();
			if (indus != indthem) {
				return (indus < indthem) ? -1 : 1;
			}
			i += 1;
		}
	}

	private void buildSingleTransition(ArrayList<SequenceSearchState> all, int pos, int val) {
		SequenceSearchState newstate = null;
		for (DittedBitSequence curpat : possible) {
			if (curpat.isMatch(pos, val)) {
				if (newstate == null) {
					newstate = new SequenceSearchState(this);
				}
				newstate.addSequence(curpat, pos + 1);
			}
		}
		trans[val] = newstate;
		if (newstate != null) {
			newstate.sortSequences();
			all.add(newstate);
		}
	}

	private void exportSuccess(ArrayList<Match> match, int offset) {
		for (DittedBitSequence succes : success) {		// If we found matches
			Match newmatch = new Match(succes, offset);
			match.add(newmatch);
		}
	}

	/**
	 * Merge in -op- and this as a single state
	 * @param op
	 */
	private void merge(SequenceSearchState op) {
		SequenceSearchState parent = op.parent;
		for (int i = 0; i < 256; ++i) {
			if (parent.trans[i] == op) {
				parent.trans[i] = this;			// Should be replaced with this
			}
		}
		if (op.success != null) {				// Merge 
			if (success == null) {
				success = op.success;
			}
			else {
				ArrayList<DittedBitSequence> tmp = new ArrayList<DittedBitSequence>();
				int i = 0;
				int j = 0;
				int curpat = -1;
				int thispat = success.get(i).getIndex();
				int oppat = op.success.get(j).getIndex();
				while ((i < success.size()) || (j < op.success.size())) {
					if (thispat == oppat) {
						if (curpat != thispat) {
							tmp.add(success.get(i));
							curpat = thispat;
						}
						i += 1;
						j += 1;
						thispat = (i == success.size()) ? PATTERN_ENDED : success.get(i).getIndex();
						oppat =
							(j == op.success.size()) ? PATTERN_ENDED : op.success.get(j).getIndex();
					}
					else if (thispat < oppat) {
						if (curpat != thispat) {
							tmp.add(success.get(i));
							curpat = thispat;
						}
						i += 1;
						thispat = (i == success.size()) ? PATTERN_ENDED : success.get(i).getIndex();
					}
					else {
						if (curpat != oppat) {
							tmp.add(op.success.get(j));
							curpat = oppat;
						}
						j += 1;
						oppat =
							(j == op.success.size()) ? PATTERN_ENDED : op.success.get(j).getIndex();
					}
				}
				success = tmp;
			}
		}
	}

	/**
	 * Try to match this Sequence to the byteArray, and add any matches to the match list
	 * @param bytearray array of bytes to match
	 * @param numbytes retrict number of bytes to allow to match
	 * @param match list of matches, the result
	 */
	public void sequenceMatch(byte[] bytearray, int numbytes, ArrayList<Match> match) {
		int subindex = 0;
		SequenceSearchState curstate = this;

		do {
			if (curstate.success != null) {
				curstate.exportSuccess(match, 0);
			}
			if (subindex >= numbytes) {
				return;
			}
			curstate = curstate.trans[0xff & bytearray[subindex]];		// Perform state transition based on next byte in buffer
			subindex += 1;
		}
		while (curstate != null);

	}

	/**
	 * Search for patterns in a byte array.  All matches are returned.
	 * @param buffer is the array of bytes to search
	 * @param match is populated with a Match object for each pattern and position that matches 
	 */
	public void apply(byte[] buffer, ArrayList<Match> match) {
		SequenceSearchState curstate;
		int subindex;
		for (int offset = 0; offset < buffer.length; ++offset) {
			curstate = this;			// New starting offset -> Root state
			subindex = offset;
			do {
				if (curstate.success != null) {
					curstate.exportSuccess(match, offset);
				}
				if (subindex >= buffer.length) {	// if we've run out of bytes, must restart at next offset
					break;
				}
				curstate = curstate.trans[0xff & buffer[subindex]];	// Perform state transition based on next byte
				subindex += 1;
			}
			while (curstate != null);
		}
	}

	/**
	 * Search for pattern in the stream -in-.
	 * @param in - The stream to scan for matches
	 * @param match - Any matches are appended as Match records to this ArrayList
	 * @param monitor - if non-null, check for user cancel, and maintain progress info
	 * @throws IOException
	 */
	public void apply(InputStream in, ArrayList<Match> match, TaskMonitor monitor)
			throws IOException {
		apply(in, -1L, match, monitor);
	}

	/**
	 * Search for pattern in the stream -in-.
	 * @param in - The stream to scan for matches
	 * @param maxBytes - The maximum number of bytes to scan forward in this stream
	 * @param match - Any matches are appended as Match records to this ArrayList
	 * @param monitor - if non-null, check for user cancel, and maintain progress info
	 * @throws IOException
	 */
	public void apply(InputStream in, long maxBytes, ArrayList<Match> match, TaskMonitor monitor)
			throws IOException {
		long progress = monitor.getProgress();

		int maxSize = getMaxSequenceSize() + 1;
		if (maxSize < 4096) {
			maxSize = 4096;
		}
		if (maxBytes > 0) {
			maxBytes += getMaxSequenceSize() + 1;
		}
		byte[] firstBuf = new byte[maxSize];
		byte[] secondBuf = new byte[maxSize];
		byte[] curBuf;
		SequenceSearchState curState;
		int fullBuffers;				// Number of buffers that are completely full
		int ra = in.read(firstBuf);
		if (ra == firstBuf.length) {
			ra = in.read(secondBuf);
			if (ra == secondBuf.length) {
				fullBuffers = 2;
			}
			else {
				if (ra < 0) {
					ra = 0;
				}
				fullBuffers = 1;
				byte[] tmp = new byte[ra];
				for (int i = 0; i < ra; ++i) {
					tmp[i] = secondBuf[i];
				}
				secondBuf = tmp;
			}
		}
		else if (ra < 0) {
			return;				// No bytes at all were read
		}
		else {
			byte[] tmp = new byte[ra];
			for (int i = 0; i < ra; ++i) {
				tmp[i] = firstBuf[i];
			}
			firstBuf = tmp;
			fullBuffers = 0;
			secondBuf = new byte[0];
		}
		int offset = 0;
		int bufRelativeOffset = 0;
		int subIndex;
		while (fullBuffers == 2) {
			curState = this;			// New starting offset -> Root state
			subIndex = bufRelativeOffset;
			curBuf = firstBuf;
			do {
				if (curState.success != null) {
					curState.exportSuccess(match, offset);
				}
				if (subIndex >= curBuf.length) {						// check that we have enough bytes in current buffer
					curBuf = secondBuf;									// If not, switch to secondary buffer
					subIndex = 0;
				}
				curState = curState.trans[0xff & curBuf[subIndex]];		// Perform state transition based on next byte in buffer
				subIndex += 1;
			}
			while (curState != null);
			offset += 1;												// Advance to next starting offset
			if (maxBytes > 0 && offset > maxBytes) {
				break;
			}
			bufRelativeOffset += 1;
			if (bufRelativeOffset == firstBuf.length) {							// If starting offset no longer falls in firstbuf
				byte[] tmp = firstBuf;									//     Switch firstbuf with secondbuf
				firstBuf = secondBuf;
				secondBuf = tmp;
				ra = in.read(secondBuf);							//     refill secondbuf (old firstbuf) with new bytes
				if (monitor != null) {
					if (monitor.isCancelled()) {
						return;
					}
					monitor.setProgress(progress + offset);
				}
				if (ra != secondBuf.length) {
					fullBuffers = 1;
					if (ra < 0) {
						ra = 0;
					}
					tmp = new byte[ra];
					for (int i = 0; i < ra; ++i) {
						tmp[i] = secondBuf[i];
					}
					secondBuf = tmp;
				}
				bufRelativeOffset = 0;
			}
		}

		while (fullBuffers >= 0 && (maxBytes <= 0 || offset < maxBytes)) {
			if (secondBuf.length == 0) {
				fullBuffers = 0;
			}
			curState = this;
			subIndex = bufRelativeOffset;
			curBuf = firstBuf;
			do {
				if (curState.success != null) {
					curState.exportSuccess(match, offset);
				}
				if (subIndex >= curBuf.length) {
					if (curBuf == secondBuf) {
						break;				// Out of data, all pending patterns fail
					}
					curBuf = secondBuf;
					subIndex = 0;
					if (curBuf.length == 0) {
						break;
					}
				}
				curState = curState.trans[0xff & curBuf[subIndex]];
				subIndex += 1;
			}
			while (curState != null);
			offset += 1;
			bufRelativeOffset += 1;
			if (bufRelativeOffset == firstBuf.length) {
				if (fullBuffers == 0) {
					break;
				}
				firstBuf = secondBuf;
				fullBuffers = 0;
				bufRelativeOffset = 0;
				secondBuf = new byte[0];
			}
		}
	}

	/**
	 * Build a new transition level for the state machine
	 * 
	 * @param prev previous search sequences
	 * @param pos position within the search sequence state for this level
	 * @return list of possible new search states to be added to the state machine
	 */
	static ArrayList<SequenceSearchState> buildTransitionLevel(ArrayList<SequenceSearchState> prev,
			int pos) {
		ArrayList<SequenceSearchState> res = new ArrayList<SequenceSearchState>();
		Iterator<SequenceSearchState> iterator = prev.iterator();
		while (iterator.hasNext()) {			// For each current state
			SequenceSearchState next = iterator.next();
			next.trans = new SequenceSearchState[256];
			for (int i = 0; i < 256; ++i) {		// Try every byte transition
				next.buildSingleTransition(res, pos, i);
			}
		}
		if (res.isEmpty()) {
			return res;
		}
		// Prepare to dedup the states
		Collections.sort(res);
		ArrayList<SequenceSearchState> finalres = new ArrayList<SequenceSearchState>();
		Iterator<SequenceSearchState> iter = res.iterator();
		SequenceSearchState curpat = iter.next();
		finalres.add(curpat);
		while (iter.hasNext()) {
			SequenceSearchState nextpat = iter.next();
			int comp = curpat.compareTo(nextpat);
			if (comp == 0) {		// Identical states
				curpat.merge(nextpat);
			}
			else {
				curpat = nextpat;
				finalres.add(curpat);
			}
		}
		return finalres;
	}

	/**
	 * Build a search state machine from a list of DittedBitSequences
	 * @param patterns bit sequence patterns
	 * @return search state the will match the given sequences
	 */
	static public SequenceSearchState buildStateMachine(
			ArrayList<? extends DittedBitSequence> patterns) {
		SequenceSearchState root = new SequenceSearchState(null);
		for (int i = 0; i < patterns.size(); ++i) {
			DittedBitSequence pat = patterns.get(i);
			pat.setIndex(i);
			root.addSequence(pat, 0);
		}
		root.sortSequences();
		ArrayList<SequenceSearchState> statelevel = new ArrayList<SequenceSearchState>();
		statelevel.add(root);
		int level = 0;
		do {
			statelevel = buildTransitionLevel(statelevel, level);
			level += 1;
		}
		while (!statelevel.isEmpty());
		return root;
	}
}
