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
package ghidra.features.bsim.gui.overview;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.description.SignatureRecord;
import ghidra.features.bsim.query.protocol.SimilarityVectorResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Table row object for BSim Overview results table
 */
public class BSimOverviewRowObject {
	private Address addr;
	private SimilarityVectorResult simvec;
	private double selfsignif;					// Maximum significance score a query with this function could return
	private long vectorHash;
	private Function function;
	
	/**
	 * Constructor.
	 * @param result results for queried function
	 * @param ad address of function
	 * @param vectorFactory vectoryFactory 
	 * @param program program containing queried function
	 */
	public BSimOverviewRowObject(SimilarityVectorResult result, Address ad,
			LSHVectorFactory vectorFactory, Program program) {
		addr = ad;
		simvec = result;
		FunctionDescription func = simvec.getBase();
		selfsignif = 0.0;
		SignatureRecord sigrec = func.getSignatureRecord();
		if (sigrec != null) {
			selfsignif = vectorFactory.getSelfSignificance(sigrec.getLSHVector());
		}
		LSHVector lshVector = func.getSignatureRecord().getLSHVector();
		vectorHash = lshVector.calcUniqueHash();
		function = program.getFunctionManager().getFunctionAt(ad);
	}
	
	public String getFunctionName() {
		if (function == null || function.isDeleted()) {
			return null;
		}
		return function.getName();
	}
	
	public Address getFunctionEntryPoint() {
		return addr;
	}

	public int getHitCount() {
		return simvec.getTotalCount();
	}
	
	public double getSelfSignificance() {
		return selfsignif;
	}

	public long getVectorHash() {
		return vectorHash;
	}
	
	
}
