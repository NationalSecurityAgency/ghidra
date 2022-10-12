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
package ghidra.machinelearning.functionfinding;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * Represents a row in table showing the probabilities that addresses are function starts
 */
public class FunctionStartRowObject {
	private Address address;
	private double probability;
	private Interpretation currentInter;
	private int numDataRefs;
	private int numUnconditionalFlowRefs;
	private int numConditionalFlowRefs;

	/**
	 * Creates a row showing that {@link Address} {@code address} has probability 
	 * {@code probability} of being a function start.  Use setter methods to set the other
	 * entries in the row.
	 * @param address address
	 * @param probability prob of being function start
	 */
	public FunctionStartRowObject(Address address, double probability) {
		this.address = address;
		this.probability = probability;
	}

	/**
	 * Returns the address.
	 * @return address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Returns the probability.
	 * @return probability
	 */
	public double getProbability() {
		return probability;
	}

	/**
	 * Returns the {@link Interpretation}
	 * @return interpretation
	 */
	public Interpretation getCurrentInterpretation() {
		return currentInter;
	}

	/**
	 * Sets the {@link Interpretation}
	 * @param inter interpretation
	 */
	public void setCurrentInterpretation(Interpretation inter) {
		currentInter = inter;
	}

	/**
	 * Returns the number of data references
	 * @return num data refs
	 */
	public int getNumDataRefs() {
		return numDataRefs;
	}

	/**
	 * Sets the number of data references
	 * @param numRefs num data refs
	 */
	public void setNumDataRefs(int numRefs) {
		numDataRefs = numRefs;
	}

	/**
	 * Returns the number of unconditional flow references
	 * @return num unconditional flow refs
	 */
	public int getNumUnconditionalFlowRefs() {
		return numUnconditionalFlowRefs;
	}

	/**
	 * Sets the number of unconditional flow references
	 * @param numRefs num unconditional flow refs
	 */
	public void setNumUnconditionalFlowRefs(int numRefs) {
		numUnconditionalFlowRefs = numRefs;
	}

	/**
	 * Sets the number of conditional flow references
	 * @param numConditionalFlowRefs num conditional refs
	 */
	public void setNumConditionalFlowRefs(int numConditionalFlowRefs) {
		this.numConditionalFlowRefs = numConditionalFlowRefs;
	}

	/**
	 * Returns the number of conditional flow references
	 * @return num conditional flow refs
	 */
	public int getNumConditionalFlowRefs() {
		return numConditionalFlowRefs;
	}

	@Override
	public int hashCode() {
		return address.hashCode();
	}

	@Override
	public boolean equals(Object o) {
		return address.equals(o);
	}

	/**
	 * Determines and sets the number of data, conditional flow, and unconditional flow references
	 * to the addresses corresponding to {@code rowObject}
	 * @param rowObject row 
	 * @param program source program
	 */
	public static void setReferenceData(FunctionStartRowObject rowObject, Program program) {
		int numUnconditionalFlowRefs = 0;
		int numConditionalFlowRefs = 0;
		int numDataRefs = 0;
		ReferenceIterator refIter =
			program.getReferenceManager().getReferencesTo(rowObject.getAddress());
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			RefType type = ref.getReferenceType();
			if (type instanceof DataRefType) {
				numDataRefs++;
				continue;
			}
			if (type instanceof FlowType) {
				if (type.isConditional()) {
					numConditionalFlowRefs++;
				}
				else {
					numUnconditionalFlowRefs++;
				}
			}
		}
		rowObject.setNumDataRefs(numDataRefs);
		rowObject.setNumUnconditionalFlowRefs(numUnconditionalFlowRefs);
		rowObject.setNumConditionalFlowRefs(numConditionalFlowRefs);
	}

}
