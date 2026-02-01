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

import static ghidra.features.bsim.gui.search.results.BSimResultStatus.*;

import java.util.*;

import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A possible BSim function match.  The similarity 
 * of this function is scored and denoted by {@link #getSimilarity() similarity}.  The 
 * significance of the match is denoted by {@link #getSignificance()}.
 */
public class BSimMatchResult {

	private final FunctionDescription qfunc; // Original queried function
	private final SimilarityNote note;
	private final FunctionDescription matchfunc;
	private final ExecutableRecord matchexe;
	private Address originalAddress;
	private int hashCode;
	private BSimResultStatus status = BSimResultStatus.NOT_APPLIED;

	public BSimMatchResult(FunctionDescription queriedFunction, Address addr,
		SimilarityNote similarityNote) {
		qfunc = queriedFunction;
		note = similarityNote;
		matchfunc = note.getFunctionDescription();
		matchexe = matchfunc.getExecutableRecord();
		originalAddress = addr;
		hashCode = 0;
	}

	public boolean isFlagSet(int mask) {
		return (matchfunc.getFlags() & mask) != 0;
	}

	public FunctionDescription getOriginalFunctionDescription() {
		return qfunc;
	}

	public FunctionDescription getMatchFunctionDescription() {
		return matchfunc;
	}

	public Address getAddress() {
		return originalAddress;
	}

	public String getExecutableURLString() {
		return matchexe.getURLString();
	}

	public BSimResultStatus getStatus() {
		return status;
	}

	public void setStatus(BSimResultStatus status) {
		if (status == IGNORED) {
			if (this.status == NAME_APPLIED || this.status == SIGNATURE_APPLIED) {
				return;
			}
		}
		this.status = status;
	}

	/**
	 * The name of the input function to which this function is similar.
	 *  
	 * @return name of the input function to which this function is similar.
	 */
	public String getOriginalFunctionName() {
		return qfunc.getFunctionName();
	}

	public long getOriginalFunctionAddress() {
		return qfunc.getAddress();
	}

	/**
	 * The name of the executable containing this function.
	 * 
	 * @return the name of the executable containing this function.
	 */
	public String getExecutableName() {
		return matchexe.getNameExec();
	}

	public String getExeCategoryAlphabetic(String type) {
		return matchexe.getExeCategoryAlphabetic(type);
	}

	public String getArchitecture() {
		return matchexe.getArchitecture();
	}

	public String getCompilerName() {
		return matchexe.getNameCompiler();
	}

	public String getMd5() {
		return matchexe.getMd5();
	}

	/**
	 * The name of this function.
	 * 
	 * @return the name of this function.
	 */
	public String getSimilarFunctionName() {
		return matchfunc.getFunctionName();
	}

	public long getSimilarFunctionAddress() {
		return matchfunc.getAddress();
	}

	/**
	 * The similarity of this function to the input function.   This is a value from 0.0 to 1.0.
	 * 
	 * @return the similarity of this function to the input function.
	 */
	public double getSimilarity() {
		return note.getSimilarity();
	}

	/**
	 * The significance of the similarity of this function to the input function.  This is a value
	 * that starts at 0.0, with no upper bound.  Functions small in size will have a low 
	 * significance score, as there is a chance that many small functions will have a 
	 * similar makeup.
	 * 
	 * @return the significance of the similarity of this function to the input function.
	 */
	public double getSignificance() {
		return note.getSignificance();
	}

	public Date getDate() {
		return matchexe.getDate();
	}

	@Override
	public int hashCode() {
		if (hashCode != 0) {
			return hashCode;
		}

		String executableMd5 = getMd5();
		String originalFunctionName = getOriginalFunctionName();
		long origAddr = getOriginalFunctionAddress();
		String architecture = getArchitecture();
		String similarFunctionName = getSimilarFunctionName();
		long similarAddress = getSimilarFunctionAddress();
		int prime = 31;
		int result = 1;
		result = prime * result + executableMd5.hashCode();
		result = prime * result + originalFunctionName.hashCode();
		result = prime * result + (int) origAddr;
		result = prime * result + architecture.hashCode();
		result = prime * result + similarFunctionName.hashCode();
		result = prime * result + (int) similarAddress;
		result = prime * result + (int) (origAddr >> 32);
		result = prime * result + (int) (similarAddress >> 32);
		hashCode = result;
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null) {
			return false;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		BSimMatchResult other = (BSimMatchResult) obj;
		if (!getMd5().equals(other.getMd5())) {
			return false;
		}

		if (!getOriginalFunctionName().equals(other.getOriginalFunctionName())) {
			return false;
		}

		if (getOriginalFunctionAddress() != other.getOriginalFunctionAddress()) {
			return false;
		}

		if (!getArchitecture().equals(other.getArchitecture())) {
			return false;
		}

		if (!getSimilarFunctionName().equals(other.getSimilarFunctionName())) {
			return false;
		}

		if (getSimilarFunctionAddress() != other.getSimilarFunctionAddress()) {
			return false;
		}

		return true;
	}

	@Override
	public String toString() {
		// @formatter:off
		return getClass().getSimpleName() + getSimilarFunctionName() + 
				"\n\texecutable: " + getExecutableName() +
				"\n\tsimilarity: " + getSimilarity() + 
				"\n\tsignificance: " + getSignificance() +
				"\n\toriginal function: " + getOriginalFunctionName();
		// @formatter:on
	}

	public static List<BSimMatchResult> generate(List<SimilarityResult> results,
		Program prog) {
		List<BSimMatchResult> resultrows = new ArrayList<BSimMatchResult>();
		for (SimilarityResult result : results) {
			FunctionDescription queriedFunction = result.getBase();
			Address origAddr = BSimMatchResultsModel.recoverAddress(queriedFunction, prog);
			for (SimilarityNote note : result) {
				BSimMatchResult similarFunction =
					new BSimMatchResult(queriedFunction, origAddr, note);
				resultrows.add(similarFunction);
			}
		}
		return resultrows;
	}

	public static List<BSimMatchResult> filterMatchRows(BSimFilter filter,
		List<BSimMatchResult> rows) {
		if (filter == null || filter.isEmpty()) {
			return rows;
		}
		List<BSimMatchResult> filteredrows = new ArrayList<BSimMatchResult>();
		for (BSimMatchResult row : rows) {
			if (filter.evaluate(row.getMatchFunctionDescription())) {
				filteredrows.add(row);
			}
		}
		return filteredrows;
	}
}
