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

/**
 * An object of this class stores all the function bit pattern information for an executable.
 * It records the number of bytes and instructions for each category (first, pre, and return), as
 * well as the language ID and ghidraURL of the executable.  Using JAXB, objects of this class converted
 * to/from XML files for analysis and storage.
 */

public class FileBitPatternInfo {

	private int numFirstBytes = 0;
	private int numFirstInstructions = 0;
	private int numPreBytes = 0;
	private int numPreInstructions = 0;
	private int numReturnBytes = 0;
	private int numReturnInstructions = 0;
	private String languageID = null;
	private String ghidraURL = null;
	private List<FunctionBitPatternInfo> funcBitPatternInfo;
	//possible TODO: Use SaveState instead of JAXB to do the XML serialization?

	/**
	 * Default no-arg constructor.  Used by JAXB for XML serialization.
	 */
	public FileBitPatternInfo() {
		funcBitPatternInfo = new ArrayList<FunctionBitPatternInfo>();
	}

	/**
	 * Get the number of bytes gathered, starting at the entry point of a function.
	 * @return number of first bytes
	 */
	public int getNumFirstBytes() {
		return numFirstBytes;
	}

	/**
	 * Set the number of bytes gathered, starting at the entry point of a function
	 * @param numFirstBytes number of bytes
	 */
	public void setNumFirstBytes(int numFirstBytes) {
		this.numFirstBytes = numFirstBytes;
	}

	/**
	 * Get the number of instructions gathered, starting with instruction at the 
	 * entry point of the function
	 * @return number of instructions 
	 */
	public int getNumFirstInstructions() {
		return numFirstInstructions;
	}

	/**
	 * Set the number of initial instructions gathered.
	 * @param numFirstInstructions number of instructions 
	 */
	public void setNumFirstInstructions(int numFirstInstructions) {
		this.numFirstInstructions = numFirstInstructions;
	}

	/**
	 * Get the number of bytes gathered immediately before (but not including) the entry point
	 * of a function
	 * @return number of bytes gathered
	 */
	public int getNumPreBytes() {
		return numPreBytes;
	}

	/**
	 * Set the number of bytes gathered immediately before (but not including) the entry point
	 * of a function
	 * @param numPreBytes number of bytes
	 */
	public void setNumPreBytes(int numPreBytes) {
		this.numPreBytes = numPreBytes;
	}

	/**
	 * Get the number of instructions gathered immediately before (but not including) a function start
	 * @return number of instructions
	 */
	public int getNumPreInstructions() {
		return numPreInstructions;
	}

	/**
	 * Set the number of instructions gathered immediately before (but not including) a function start
	 * 
	 * @param numPreInstructions number of instructions
	 */
	public void setNumPreInstructions(int numPreInstructions) {
		this.numPreInstructions = numPreInstructions;
	}

	/**
	 * Get the list of {@link FunctionBitPatternInfo} objects for the program (one object per function)
	 * @return List whose elements record information about each function start in the program
	 */
	public List<FunctionBitPatternInfo> getFuncBitPatternInfo() {
		return funcBitPatternInfo;
	}

	/**
	 * Set the list of {@link FunctionBitPatternInfo} objects for the program (one object per function)
	 * @param funcStartInfo List whose elements record information about each function start in the
	 * program
	 */
	public void setFuncBitPatternInfo(List<FunctionBitPatternInfo> funcBitPatternInfo) {
		this.funcBitPatternInfo = funcBitPatternInfo;
	}

	/**
	 * Get the language ID string of the program
	 * @return the language ID
	 */
	public String getLanguageID() {
		return languageID;
	}

	/**
	 * Set the language ID string of the program
	 * @param id the language id
	 */
	public void setLanguageID(String id) {
		this.languageID = id;
	}

	/**
	 * Set the GhidraURL of the program
	 * @param url the url
	 */
	public void setGhidraURL(String url) {
		this.ghidraURL = url;
	}

	/**
	 * Get the GhidraURL of the program
	 * @return the url
	 */
	public String getGhidraURL() {
		return ghidraURL;
	}

	/**
	 * Get the number of return bytes gathered, i.e., the number of bytes gathered immediately before
	 * (and including) a return instruction.
	 * @return number of return bytes
	 */
	public int getNumReturnBytes() {
		return numReturnBytes;
	}

	/**
	 * Set the number of return bytes, i.e., the number of bytes gathered immediately before
	 * (and including) a return instruction.
	 * @param numReturnBytes number of return bytes
	 */
	public void setNumReturnBytes(int numReturnBytes) {
		this.numReturnBytes = numReturnBytes;
	}

	/**
	 * Get the number of instructions immediately before (and including) a return instruction 
	 * @return number of return instructions
	 */
	public int getNumReturnInstructions() {
		return numReturnInstructions;
	}

	/**
	 * Set the number of instructions immediately before (and including) a return instruction
	 * @param numReturnInstructions number of return instructions
	 */
	public void setNumReturnInstructions(int numReturnInstructions) {
		this.numReturnInstructions = numReturnInstructions;
	}
}
