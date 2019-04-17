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
package ghidra.app.plugin.core.entropy;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class EntropyCalculate {
	private MemoryBlock block;
	private int entropy[];				// Quantized entropy statistic for each chunk
	private int chunksize;
	private int[] histo;				// histogram of a chunk (reused for each chunk)
	private byte[] chunk;				// chunk of bytes
	private double[] logtable;			// Table of precalculated logarithms
	
	public EntropyCalculate(MemoryBlock b,int csize) {
		block = b;
		chunksize = csize;
		doEntropy();
	}
	
	public int getValue(int offset) {
		if (offset < 0) return -1;
		offset /= chunksize;
		if (offset >= entropy.length) return -1;
		return entropy[offset];
	}
	
	private void doEntropy() {
		histo = new int[256];
		chunk = new byte[chunksize];
		buildLogTable();
		long size = (int)block.getSize();
		int numchunks = (int)(size / chunksize);
		if ((size % chunksize)!=0)
			numchunks += 1;
		
		entropy = new int[numchunks];
		long offset = 0;
		int chunknum = 0;
		while(offset < size) {
			try {
				histogramChunk(offset);
			} catch (MemoryAccessException e) {
				entropy[chunknum] = -1;			// Undefined values
			}
			quantizeChunk(chunknum);
			offset += chunksize;
			chunknum += 1;
		}
		histo = null;			// Free resources
		chunk = null;
		logtable = null;
	}
	
	private void histogramChunk(long offset) throws MemoryAccessException {
		// The add method is byte based, so if the word-size of the space does not divide evenly into -offset- we
		// may be slightly off cut here.  It probably doesn't matter very much for a histogram though
		Address addr = block.getStart().add(offset);
		int len = block.getBytes(addr, chunk, 0, chunksize);
		for(int i=0;i<256;++i)
			histo[i] = 0;
		for(int i=0;i<len;++i)
			histo[128 + chunk[i]] += 1;
	}
	
	private void buildLogTable() {
		logtable = new double[chunksize+1];
		double logtwo = Math.log(2.0);
		double chunkfloat = chunksize;
		for(int i=1;i<chunksize;++i) {
			double prob = i / chunkfloat;
			logtable[i] = -prob * (Math.log(prob) / logtwo);
		}
		logtable[0] = 0.0;
		logtable[chunksize] = 0.0;
	}
	
	private void quantizeChunk(int pos) {
		double sum = 0.0;
		for(int i=0;i<256;++i)
			sum += logtable[histo[i]];
		sum = (sum/8.0) * 256.0;
		int val = (int)Math.floor(sum);
		if (val > 255)
			val = 255;
		entropy[pos] = val;
	}
}
