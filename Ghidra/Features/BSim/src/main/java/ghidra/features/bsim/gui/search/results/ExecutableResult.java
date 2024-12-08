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
package ghidra.features.bsim.gui.search.results;

import java.util.*;

import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;

public class ExecutableResult implements Comparable<ExecutableResult> {
	private ExecutableRecord exerecord;
	private int funccount;					// Number of functions matching into this executable
	private double sumsignif;				// Sum of all matching function significance
	private int hashCode;

	public ExecutableResult() {
		exerecord = null;
		funccount = 0;
		sumsignif = 0.0;
	}

	public ExecutableResult(ExecutableRecord rec) {
		exerecord = rec;
		funccount = 0;
		sumsignif = 0.0;
	}

	public void addFunction(double signif) {
		funccount += 1;
		sumsignif += signif;
	}

	public ExecutableRecord getExecutableRecord() {
		return exerecord;
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
		if (obj == null)
			return false;
		if (this == obj)
			return true;
		ExecutableResult op2 = (ExecutableResult) obj;
		return exerecord.equals(op2.exerecord);
	}

	@Override
	public int compareTo(ExecutableResult o) {
		return exerecord.compareTo(o.exerecord);
	}

	@Override
	public int hashCode() {
		if (hashCode != 0) {
			return hashCode;
		}

		hashCode = exerecord.hashCode();
		return hashCode;
	}

	private static void finalizeExecutableResult(TreeSet<ExecutableResult> singlefunc,
		TreeSet<ExecutableResult> globalfunc) {
		Iterator<ExecutableResult> finaliter = singlefunc.iterator();
		while (finaliter.hasNext()) {
			ExecutableResult eres = finaliter.next();
			ExecutableResult tmpres = globalfunc.floor(eres);
			if ((tmpres == null) || (!tmpres.equals(eres))) {
				tmpres = new ExecutableResult(eres.exerecord);
				globalfunc.add(tmpres);
			}
			tmpres.addFunction(eres.getSignificanceSum());
		}
	}

	public static TreeSet<ExecutableResult> generateFromMatchRows(
		List<BSimMatchResult> filteredrows) {
		TreeSet<ExecutableResult> execrows = new TreeSet<ExecutableResult>();
		ExecutableResult curres = new ExecutableResult();
		TreeSet<ExecutableResult> exetree = new TreeSet<ExecutableResult>();
		FunctionDescription curdescription = null;
		Iterator<BSimMatchResult> iter = filteredrows.iterator();
		while (iter.hasNext()) {
			BSimMatchResult simres = iter.next();
			double signif = simres.getSignificance();
			if (curdescription != simres.getOriginalFunctionDescription()) {
				finalizeExecutableResult(exetree, execrows);
				curdescription = simres.getOriginalFunctionDescription();
				exetree = new TreeSet<ExecutableResult>();
			}
			curres.exerecord = simres.getMatchFunctionDescription().getExecutableRecord();
			ExecutableResult tmpres = exetree.floor(curres);
			if ((tmpres == null) || (!tmpres.equals(curres))) {		// Haven't seen this executable before
				tmpres = new ExecutableResult(curres.exerecord);
				tmpres.sumsignif = signif;
				exetree.add(tmpres);
			}
			else {	// Seen this executable before for this particular function
				if (tmpres.getSignificanceSum() < signif)
					tmpres.sumsignif = signif;
			}
		}
		if (!exetree.isEmpty())
			finalizeExecutableResult(exetree, execrows);
		return execrows;
	}
}
