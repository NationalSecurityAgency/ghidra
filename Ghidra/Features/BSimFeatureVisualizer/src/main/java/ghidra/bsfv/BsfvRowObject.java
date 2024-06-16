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
package ghidra.bsfv;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.*;

/**
 * The class represents a row in the table of BSim features
 */
public class BsfvRowObject {

	private BsfvFeatureColumnObject feature;
	private SequenceNumber seq;
	private PcodeOpAST definingPcodeOp;
	private PcodeOpAST previousPcodeOp;
	private BSimFeatureType type;
	private Varnode baseVarnode;
	private Address basicBlockStart;
	private Integer blockIndex;

	/**
	 * Creates a row object for a table of BSim features. Note that not all columns are appropriate
	 * for all feature types.  For CONTROL_FLOW features, {@code seq} should be an artificial 
	 * {@link SequenceNumber} corresponding to the start of the appropriate basic block.
	 * @param feature hash value (required)
	 * @param seq sequence number of feature (required)
	 * @param baseVarnode base varnode of DATA_FLOW signature (null otherwise)
	 * @param definingPcodeOp defining op of feature (null for CONTROL_FLOW features)
	 * @param previousPcodeOp previous op (only non-null for DUAL_FLOW features)
	 * @param type BSimFeatureType of feature (required)
	 * @param basicBlockStart start of basic block (null for DATA_FLOW signatures)
	 * @param blockIndex index of basic block (null for DATA_FLOW signatures)
	 */
	public BsfvRowObject(int feature, SequenceNumber seq, Varnode baseVarnode,
			PcodeOpAST definingPcodeOp, PcodeOpAST previousPcodeOp, BSimFeatureType type,
			Address basicBlockStart, Integer blockIndex) {
		this.feature = new BsfvFeatureColumnObject(feature);
		this.seq = seq;
		this.type = type;
		this.baseVarnode = baseVarnode;
		this.basicBlockStart = basicBlockStart;
		this.definingPcodeOp = definingPcodeOp;
		this.previousPcodeOp = previousPcodeOp;
		this.blockIndex = blockIndex;
	}

	/**
	 * Returns the {@SequenceNumber} corresponding to the feature.
	 * @return sequence number
	 */
	public SequenceNumber getSeq() {
		return seq;
	}

	/**
	 * Returns the PcodeOpAST corresponding to the feature.
	 * @return pcodeop ast 
	 */
	public PcodeOpAST getPcodeOpAST() {
		return definingPcodeOp;
	}

	/**
	 * Returns the previous PcodeOpAST correspond to the features.  Only non-null for DUAL_FLOW 
	 * features.
	 * @return previous pcodeop ast
	 */
	public PcodeOpAST getPreviousPcodeOpAST() {
		return previousPcodeOp;
	}

	/**
	 * Returns the mnemonic of the defining pcode op. Returns null if there is no defining pcode op.
	 * @return mnemonic of defining op
	 */
	public String getOpMnemonic() {
		if (definingPcodeOp != null) {
			return definingPcodeOp.getMnemonic();
		}
		return null;
	}

	/**
	 * Returns the {@link BSimFeatureType} of the feature.
	 * @return bsim feature type
	 */
	public BSimFeatureType getBSimFeatureType() {
		return type;
	}

	/**
	 * Returns the base 
	 * @return base varnode
	 */
	public Varnode getBaseVarnode() {
		return baseVarnode;
	}

	/**
	 * Returns the start of the basic block corresponding to the feature
	 * @return basic block start
	 */
	public Address getBasicBlockStart() {
		return basicBlockStart;
	}

	/**
	 * Returns the {@link Address} corresponding to the feature
	 * @return address of feature
	 */
	public Address getAddress() {
		return seq.getTarget();
	}

	/**
	 * Returns the {@BSimFeatureColumnType} wrapping the 32-bit hash 
	 * @return wrapped hash
	 */
	public BsfvFeatureColumnObject getFeature() {
		return feature;
	}

	/**
	 * Returns the index of the basic block corresponding to the features
	 * @return basic block index
	 */
	public Integer getBlockIndex() {
		return blockIndex;
	}

}
