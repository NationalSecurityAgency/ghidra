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

import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;

public class SequenceSearchState implements Comparable<SequenceSearchState> {
	
	private SequenceSearchState parent;
	private ArrayList<DittedBitSequence> possible;		// Patterns that could still match in this state
	private ArrayList<DittedBitSequence> success;		// Patterns that have matched successfully if we reached this state
	private SequenceSearchState[] trans;				// State transitions based on next byte
	
	public SequenceSearchState(SequenceSearchState par) {
		parent = par;
		possible = new ArrayList<DittedBitSequence>();
		success = null;
		trans = null;
	}

	public int getMaxSequenceSize() {
		int max = 0;
		for(int i=0;i<possible.size();++i) {
			int val = possible.get(i).getSize();
			if (val > max)
				max = val;
		}
		return max;
	}
	
	public void addSequence(DittedBitSequence pat,int pos) {
		possible.add(pat);
		if (pos == pat.getSize()) {
			if (success == null)
				success = new ArrayList<DittedBitSequence>();
			success.add(pat);
		}
	}
	
	public void sortSequences() {
		Comparator<DittedBitSequence> comp = new Comparator<DittedBitSequence>() {
			@Override
			public int compare(DittedBitSequence o1, DittedBitSequence o2) {
				return o1.getIndex() - o2.getIndex();
			}
		};
		Collections.sort(possible,comp);
		if (success != null)
			Collections.sort(success,comp);
	}
	
	@Override
	public int compareTo(SequenceSearchState o) {
		int i=0;
		for(;;) {
			if (possible.size() <= i) {
				if (o.possible.size() <=i)
					return 0;
				return -1;
			}
			if (o.possible.size() <= i)
				return 1;
			int indus = possible.get(i).getIndex();		// Lexicographic compare an sequence of sequences
			int indthem = o.possible.get(i).getIndex();
			if (indus != indthem)
				return (indus < indthem) ? -1 : 1;
			i += 1;
		}
	}
	
	private void buildSingleTransition(ArrayList<SequenceSearchState> all,int pos,int val) {
		SequenceSearchState newstate = null;
		for(int i=0;i<possible.size();++i) {
			DittedBitSequence curpat = possible.get(i);
			if (curpat.isMatch(pos, val)) {
				if (newstate == null)
					newstate = new SequenceSearchState(this);
				newstate.addSequence(curpat, pos+1);
			}
		}
		trans[val] = newstate;
		if (newstate != null) {
			newstate.sortSequences();
			all.add(newstate);
		}
	}
	
	private void exportSuccess(ArrayList<Match> match,int offset) {
		for(int i=0;i<success.size();++i) {		// If we found matches
			Match newmatch = new Match(success.get(i),offset);
			match.add(newmatch);
		}			
	}
	
	/**
	 * Merge in -op- and this as a single state
	 * @param op
	 */
	private void merge(SequenceSearchState op) {
		SequenceSearchState parent = op.parent;
		for(int i=0;i<256;++i) {
			if (parent.trans[i] == op)			// Any references to -op- in parent
				parent.trans[i] = this;			// Should be replaced with this
		}
		if (op.success != null) {				// Merge 
			if (success == null) {
				success = op.success;
			}
			else {
				ArrayList<DittedBitSequence> tmp = new ArrayList<DittedBitSequence>();
				int i=0;
				int j=0;
				int curpat = -1;
				int thispat = success.get(i).index;
				int oppat = op.success.get(j).index;
				while((i<success.size())||(j<op.success.size())) {
					if (thispat == oppat) {
						if (curpat != thispat) {
							tmp.add(success.get(i));
							curpat = thispat;
						}
						i += 1;
						j += 1;
						thispat = (i==success.size()) ? 10000000 : success.get(i).index;
						oppat = (j==op.success.size()) ? 10000000 : op.success.get(j).index;
					}
					else if (thispat < oppat) {
						if (curpat != thispat) {
							tmp.add(success.get(i));
							curpat = thispat;
						}
						i += 1;
						thispat = (i==success.size()) ? 10000000 : success.get(i).index;
					}
					else {
						if (curpat != oppat) {
							tmp.add(op.success.get(j));
							curpat = oppat;
						}
						j += 1;
						oppat = (j==op.success.size()) ? 10000000 : op.success.get(j).index;
					}
				}
				success = tmp;
			}
		}
	}
	
	public void sequenceMatch(byte[] bytearray,int numbytes,ArrayList<Match> match) {
		int subindex = 0;
		SequenceSearchState curstate = this;
		
		do {
			if (curstate.success != null)
				curstate.exportSuccess(match, 0);
			if (subindex >= numbytes) return;
			curstate = curstate.trans[ 0xff & bytearray[subindex] ];		// Perform state transition based on next byte in buffer
			subindex += 1;
		} while(curstate != null);
		
	}

	/**
	 * Search for patterns in a byte array.  All matches are returned.
	 * @param buffer is the array of bytes to search
	 * @param match is populated with a Match object for each pattern and position that matches 
	 */
	public void apply(byte[] buffer,ArrayList<Match> match) {
		SequenceSearchState curstate;
		int subindex;
		for(int offset=0;offset<buffer.length;++offset) {
			curstate = this;			// New starting offset -> Root state
			subindex = offset;
			do {
				if (curstate.success != null)		// Check for any successful pattern matches for bytes up to this point
					curstate.exportSuccess(match, offset);
				if (subindex >= buffer.length) {	// if we've run out of bytes, must restart at next offset
					break;
				}
				curstate = curstate.trans[ 0xff & buffer[subindex] ];	// Perform state transition based on next byte
				subindex += 1;
			} while(curstate != null);
		}		
	}

	/**
	 * Search for pattern in the stream -in-.
	 * @param in - The stream to scan for matches
	 * @param match - Any matches are appended as Match records to this ArrayList
	 * @param monitor - if non-null, check for user cancel, and maintain progress info
	 * @throws IOException
	 */
	public void apply(InputStream in,ArrayList<Match> match,TaskMonitor monitor) throws IOException {
		apply(in,-1L,match,monitor);
	}
	
	/**
	 * Search for pattern in the stream -in-.
	 * @param in - The stream to scan for matches
	 * @param maxBytes - The maximum number of bytes to scan forward in this stream
	 * @param match - Any matches are appended as Match records to this ArrayList
	 * @param monitor - if non-null, check for user cancel, and maintain progress info
	 * @throws IOException
	 */
	public void apply(InputStream in, long maxBytes, ArrayList<Match> match,TaskMonitor monitor) throws IOException {
		int maxsize = getMaxSequenceSize()+1;
		if (maxsize <4096)
			maxsize = 4096;
		if (maxBytes > 0) {
			maxBytes += getMaxSequenceSize()+1;
		}
		byte[] firstbuf=new byte[maxsize];
		byte[] secondbuf=new byte[maxsize];
		byte[] curbuf;
		SequenceSearchState curstate;
		int fullbuffers;				// Number of buffers that are completely full
		int ra = in.read(firstbuf);
		if (ra == firstbuf.length) {
			ra = in.read(secondbuf);
			if (ra == secondbuf.length) {
				fullbuffers = 2;
			}
			else {
				if (ra < 0)
					ra = 0;
				fullbuffers = 1;
				byte[] tmp = new byte[ra];
				for(int i=0;i<ra;++i)
					tmp[i] = secondbuf[i];
				secondbuf = tmp;
			}
		}
		else if (ra < 0)
			return;				// No bytes at all were read
		else {
			byte[] tmp = new byte[ra];
			for(int i=0;i<ra;++i)
				tmp[i] = firstbuf[i];
			firstbuf = tmp;
			fullbuffers = 0;
			secondbuf = new byte[0];
		}
		int offset=0;
		int bufreloff=0;
		int subindex;
		while(fullbuffers == 2) {
			curstate = this;			// New starting offset -> Root state
			subindex = bufreloff;
			curbuf = firstbuf;
			do {
				if (curstate.success != null)		// Check for any successful pattern matches for bytes up to this point
					curstate.exportSuccess(match, offset);
				if (subindex >= curbuf.length) {						// check that we have enough bytes in current buffer
					curbuf = secondbuf;									// If not, switch to secondary buffer
					subindex = 0;
				}
				curstate = curstate.trans[ 0xff & curbuf[subindex] ];		// Perform state transition based on next byte in buffer
				subindex += 1;
			} while(curstate != null);
			offset += 1;												// Advance to next starting offset
			if (maxBytes > 0 && offset > maxBytes) {
				break;
			}
			bufreloff += 1;
			if (bufreloff == firstbuf.length) {							// If starting offset no longer falls in firstbuf
				byte[] tmp = firstbuf;									//     Switch firstbuf with secondbuf
				firstbuf = secondbuf;
				secondbuf = tmp;
				ra = in.read(secondbuf);							//     refill secondbuf (old firstbuf) with new bytes
				if (monitor!=null) {
					if (monitor.isCancelled()) return;
					monitor.setProgress(offset);
				}
				if (ra != secondbuf.length) {
					fullbuffers = 1;
					if (ra < 0)
						ra = 0;
					tmp = new byte[ra];
					for(int i=0;i<ra;++i)
						tmp[i] = secondbuf[i];
					secondbuf = tmp;
				}
				bufreloff = 0;
			}
		}
		
		while(fullbuffers >= 0 && (maxBytes <= 0 || offset < maxBytes)) {
			if (secondbuf.length == 0)
				fullbuffers = 0;
			curstate = this;
			subindex = bufreloff;
			curbuf = firstbuf;
			do {
				if (curstate.success != null)
					curstate.exportSuccess(match, offset);
				if (subindex >= curbuf.length) {
					if (curbuf == secondbuf) break;				// Out of data, all pending patterns fail
					curbuf = secondbuf;
					subindex = 0;
					if (curbuf.length==0) break;
				}
				curstate = curstate.trans[ 0xff & curbuf[subindex] ];
				subindex += 1;
			} while(curstate != null);
			offset += 1;
			bufreloff += 1;
			if (bufreloff == firstbuf.length) {
				if (fullbuffers == 0) break;
				firstbuf = secondbuf;
				fullbuffers = 0;
				bufreloff = 0;
				secondbuf = new byte[0];
			}
		}
	}
	
	static public ArrayList<SequenceSearchState> buildTransitionLevel(ArrayList<SequenceSearchState> prev,int pos) {
		ArrayList<SequenceSearchState> res = new ArrayList<SequenceSearchState>();
		Iterator<SequenceSearchState> iterator = prev.iterator();
		while(iterator.hasNext()) {			// For each current state
			SequenceSearchState next = iterator.next();
			next.trans = new SequenceSearchState[256];
			for(int i=0;i<256;++i) {		// Try every byte transition
				next.buildSingleTransition(res, pos, i);
			}
		}
		if (res.isEmpty()) return res;
		// Prepare to dedup the states
		Collections.sort(res);
		ArrayList<SequenceSearchState> finalres = new ArrayList<SequenceSearchState>();
		Iterator<SequenceSearchState> iter = res.iterator();
		SequenceSearchState curpat = iter.next();
		finalres.add(curpat);
		while(iter.hasNext()) {
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
	
	static public SequenceSearchState buildStateMachine(ArrayList<? extends DittedBitSequence> patterns) {
		SequenceSearchState root = new SequenceSearchState(null);
		for(int i=0;i<patterns.size();++i) {
			DittedBitSequence pat = patterns.get(i);
			pat.index = i;
			root.addSequence(pat, 0);
		}
		root.sortSequences();
		ArrayList<SequenceSearchState> statelevel = new ArrayList<SequenceSearchState>();
		statelevel.add(root);
		int level = 0;
		do {
			statelevel = buildTransitionLevel(statelevel, level);
			level += 1;				
		} while(!statelevel.isEmpty());
		return root;
	}
}
