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
package ghidra.app.plugin.core.instructionsearch.model;

import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;

/**
 * Holds information related to a single operand in the {@link InstructionTable}.
 */
public class OperandMetadata {

	private String textRep;
	private int opType;
	private MaskContainer maskContainer;
	private boolean mask = false;

	public String getTextRep() {
		return textRep;
	}

	public void setTextRep(String textRep) {
		this.textRep = textRep;
	}

	public int getOpType() {
		return opType;
	}

	public void setOpType(int opType) {
		this.opType = opType;
	}

	public MaskContainer getMaskContainer() {
		return maskContainer;
	}

	public void setMaskContainer(MaskContainer maskContainer) {
		this.maskContainer = maskContainer;
	}

	public boolean isMasked() {
		return mask;
	}

	public void setMasked(boolean mask) {
		this.mask = mask;
	}
}
