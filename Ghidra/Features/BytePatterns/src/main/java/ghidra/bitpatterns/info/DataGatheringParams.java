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
package ghidra.bitpatterns.info;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

/**
 * This class is a container for the parameters used when collecting function start data to be mined.
 */

public class DataGatheringParams {
	private int numPreBytes;
	private int numFirstBytes;
	private int numReturnBytes;
	private int numPreInstructions;
	private int numFirstInstructions;
	private int numReturnInstructions;
	private List<String> contextRegisters;

	/**
	 * Creates a new {@link DataGatheringParams} object.  Use setter methods to set the values.
	 */
	public DataGatheringParams() {
	}

	/**
	 * Get the number of prebytes, i.e., bytes before a function start.
	 * @return number of prebytes
	 */
	public int getNumPreBytes() {
		return numPreBytes;
	}

	/**
	 * Set the number of prebytes.
	 * @param preBytes number of prebytes
	 */
	public void setNumPreBytes(int preBytes) {
		this.numPreBytes = preBytes;
	}

	/**
	 * Get the number of first bytes, i.e., the number of bytes immediately after (and including )
	 * a function start.
	 * @return number of first bytes
	 */
	public int getNumFirstBytes() {
		return numFirstBytes;
	}

	/**
	 * Set the number of first bytes
	 * @param firstBytes the number of first bytes
	 */
	public void setNumFirstBytes(int firstBytes) {
		this.numFirstBytes = firstBytes;
	}

	/**
	 * Get the number of return bytes, i.e., the number of bytes immediately before (and including)
	 * a return instruction.
	 * @return number of return bytes
	 */
	public int getNumReturnBytes() {
		return numReturnBytes;
	}

	/**
	 * Set the number of return bytes.
	 * @param returnBytes number of return bytes
	 */
	public void setNumReturnBytes(int returnBytes) {
		this.numReturnBytes = returnBytes;
	}

	/**
	 * Get the number of pre Instructions, i.e., the number of instructions immediately before
	 * a function start
	 * @return number of pre Instructions
	 */
	public int getNumPreInstructions() {
		return numPreInstructions;
	}

	/**
	 * Set the number of pre Instructions
	 * @param preInstructions number of pre Instructions
	 */
	public void setNumPreInstructions(int preInstructions) {
		this.numPreInstructions = preInstructions;
	}

	/**
	 * Get the number of first Instructions, i.e., the number of instructions immediately after
	 * (and including) a function start
	 * @return number of first instructions
	 */
	public int getNumFirstInstructions() {
		return numFirstInstructions;
	}

	/**
	 * Set the number of first instructions to collect during data gathering
	 * @param firstInstructions number of first instructions
	 */
	public void setNumFirstInstructions(int firstInstructions) {
		this.numFirstInstructions = firstInstructions;
	}

	/**
	 * Get the number of return instructions, i.e., the number of instructions immediately before
	 * (and including) a return instruction
	 * @return number of return instructions to gather
	 */
	public int getNumReturnInstructions() {
		return numReturnInstructions;
	}

	/**
	 * Set the number of return instructions.
	 * @param returnInstructions number of return instructions to gather
	 */
	public void setNumReturnInstructions(int returnInstructions) {
		this.numReturnInstructions = returnInstructions;
	}

	/**
	 * Get a list of context registers tracked during data gathering
	 * @return list of context registers
	 */
	public List<String> getContextRegisters() {
		return contextRegisters;
	}

	/**
	 * Set the context registers to track during data gathering
	 * @param cRegs registers to track
	 */
	public void setContextRegisters(List<String> cRegs) {
		contextRegisters = cRegs;
	}

	/**
	 * Parse a List of context registers from a CSV string of context register names
	 * 
	 * <p> It is assumed that the list contains no duplicates.
	 * 
	 * @param contextRegsCSV a CSV String of context register names to track during
	 * data gathering
	 *
	 * @return the list
	 */
	public static List<String> getContextRegisterList(String contextRegsCSV) {
		List<String> contextRegisters = new ArrayList<>();

		if (contextRegsCSV == null) {
			return contextRegisters;
		}
		contextRegsCSV = contextRegsCSV.trim();
		//literal string null: this can be a value in a .properties file
		if ((contextRegsCSV.equals("")) || contextRegsCSV.equals("null")) {
			return contextRegisters;
		}

		String[] components = contextRegsCSV.split(",");
		for (String component : components) {
			if (!StringUtils.isEmpty(component.trim())) {
				contextRegisters.add(component.trim());
			}
		}
		return contextRegisters;
	}

}
