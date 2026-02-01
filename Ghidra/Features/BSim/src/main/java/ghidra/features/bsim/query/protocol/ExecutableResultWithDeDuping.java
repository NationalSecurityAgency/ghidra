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
package ghidra.features.bsim.query.protocol;

import java.util.*;

import ghidra.features.bsim.query.description.*;

public class ExecutableResultWithDeDuping implements Comparable<ExecutableResultWithDeDuping> {
	private RowKey id;						// Copy ExecutableRecord id
	private ExecutableRecord exerecord;
	private int funccount;					// Number of functions matching into this executable
	private double sumsignif;				// Sum of all matching function significance
	
	private ExecutableResultWithDeDuping() {
		id = null;
		exerecord = null;
		funccount = 0;
		sumsignif = 0.0;
	}
	
	public ExecutableResultWithDeDuping(ExecutableRecord rec) {
		exerecord = rec;
		id = rec.getRowId();
		funccount = 0;
		sumsignif = 0.0;
	}
	
	public ExecutableRecord getExecutableRecord() {
		return exerecord;
	}
	
	public void addFunction(double signif) {
		funccount += 1;
		sumsignif += signif;
	}
	
	/**
	 * @return number of functions with matches into this executable
	 */
	public int getFunctionCount() {
		return funccount;
	}
	
	/**
	 * @return sum of significance scores for all matching functions
	 */
	public double getSignificanceSum() {
		return sumsignif;
	}
	
	@Override
	public boolean equals(Object obj) {
		return (id.equals( ((ExecutableResultWithDeDuping)obj).id) );
	}

	@Override
	/*public int compareTo(ExecutableResultWithDeDuping o) {
		long id2 = o.id;
		if (id == id2) return 0;
		return (id < id2) ? -1 : 1;
	}*/
	
	public int compareTo(ExecutableResultWithDeDuping o){
		return Double.compare(this.getSignificanceSum(), o.getSignificanceSum());
	}
	
	
	
	public static Collection<ExecutableResultWithDeDuping> generate(Iterator<SimilarityResult> iter, Map<FunctionDescription, Integer> duplicationInfo) {
		TreeSet<ExecutableResultWithDeDuping> res = new TreeSet<ExecutableResultWithDeDuping>();
		ExecutableResultWithDeDuping curres = new ExecutableResultWithDeDuping();
		while(iter.hasNext()) {
			SimilarityResult simres = iter.next();
			TreeSet<ExecutableResultWithDeDuping> exetree = new TreeSet<ExecutableResultWithDeDuping>();
			Iterator<SimilarityNote> noteiter = simres.iterator();
			
			Integer totalNumDuplicates = duplicationInfo.get(simres.getBase());  //should never be null
			if(totalNumDuplicates == null){
				totalNumDuplicates = 1000;
			}
			Map<ExecutableResultWithDeDuping, Integer> dupesInExecutable = new HashMap<ExecutableResultWithDeDuping, Integer>();
			
			while(noteiter.hasNext()) {
				SimilarityNote note = noteiter.next();
				curres.exerecord = note.getFunctionDescription().getExecutableRecord();
				curres.id = curres.exerecord.getRowId();
				ExecutableResultWithDeDuping tmpres = exetree.floor(curres);
				if ((tmpres == null)||(!tmpres.id.equals(curres.id))) {			// Haven't seen this executable before
					tmpres = new ExecutableResultWithDeDuping(curres.exerecord);
					exetree.add(tmpres);
					tmpres.sumsignif = note.getSignificance();
					dupesInExecutable.put(tmpres, 1);
				}
				else {	// Seen this executable before for this SimilarityResult

					if (tmpres.sumsignif < note.getSignificance()){
						tmpres.sumsignif = note.getSignificance();		// Find maximum significance result for this executable
						dupesInExecutable.put(tmpres, 1);               //found a higher significance match - reset the count
					}
					else{
						if( (tmpres.sumsignif == note.getSignificance())  && (dupesInExecutable.get(tmpres) < totalNumDuplicates)){
							tmpres.sumsignif = tmpres.sumsignif + note.getSignificance();
							dupesInExecutable.put(tmpres, dupesInExecutable.get(tmpres) + 1);     //increment the count
						}

					}
				}
			}

			Iterator<ExecutableResultWithDeDuping> finaliter = exetree.iterator();
			while(finaliter.hasNext()) {
				ExecutableResultWithDeDuping eres = finaliter.next();
				ExecutableResultWithDeDuping tmpres = res.floor(eres);
				if ((tmpres == null)||(!tmpres.id.equals(eres.id))) {
					tmpres = new ExecutableResultWithDeDuping(eres.exerecord);
					res.add(tmpres);
				}
				tmpres.addFunction(eres.sumsignif);
			}
		}
		return res;
	}
}
