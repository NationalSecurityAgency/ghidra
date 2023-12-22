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
package ghidra.features.bsim.query.client;

import java.util.*;

import generic.lsh.vector.LSHVector;
import ghidra.features.bsim.query.description.*;

/**
 * Lightweight object container of an LSHVector and its count within a collection of functions (database/executable)
 * TODO: This should likely be merged with SignatureRecord
 */
public class IdHistogram implements Comparable<IdHistogram> {
	public long id;				// Is the unique id of the vector as computed by LSHVector.getVectorId()
	public int count;			// Is the count of duplicate vectors within the larger set of functions
	public LSHVector vec = null;	// Is an instance of the vector itself

	@Override
	public int compareTo(IdHistogram o) {
		return Long.compare(id, o.id);
	}

	/**
	 * @param iter is iterator over functions whose vectors are to be histogrammed
	 * @return the sorted list of pairs (hash,count)
	 */
	public static TreeSet<IdHistogram> buildVectorIdHistogram(Iterator<FunctionDescription> iter) {
		TreeSet<IdHistogram> table = new TreeSet<IdHistogram>();
		IdHistogram testItem = new IdHistogram();
		while(iter.hasNext()) {
			testItem.id = iter.next().getVectorId();
			if (testItem.id == 0) {
				continue; // Function doesn't have associated vector
			}
			IdHistogram cur = table.floor(testItem);
			if (cur == null || cur.id != testItem.id) {
				cur = new IdHistogram();
				cur.id = testItem.id;
				cur.count = 1;
				table.add(cur);
			}
			else {
				cur.count += 1;
			}
		}
		return table;
	}

	/**
	 * Organize/histogram LSHVectors by hash.  Take into account functions that don't have a vector.
	 * Record hashes in the FunctionDescription's SignatureRecord
	 * @param manage is the container of the FunctionDescriptions
	 * @param iter is the iterator over the FunctionDescriptions being collected
	 * @return the histogram as a set of (id,count,vec) triples
	 */
	public static Set<IdHistogram> collectVectors(DescriptionManager manage,Iterator<FunctionDescription> iter) {
		TreeSet<IdHistogram> res = new TreeSet<IdHistogram>();
		IdHistogram workingRec = new IdHistogram();
		while(iter.hasNext()) {
			FunctionDescription desc = iter.next();
			SignatureRecord sigrec = desc.getSignatureRecord();
			if (sigrec == null) {
				continue;
			}
			long key = sigrec.getLSHVector().calcUniqueHash();
			manage.setSignatureId(sigrec, key);
			workingRec.id = key;
			IdHistogram prevRec = res.floor(workingRec);
			if (prevRec == null || prevRec.id != key) {
				prevRec = new IdHistogram();
				prevRec.id = key;
				prevRec.vec = sigrec.getLSHVector();
				prevRec.count = 1;
				res.add(prevRec);
			}
			else {
				prevRec.count += 1;
			}
		}
		return res;
	}
}
