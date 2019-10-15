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

import java.util.*;

import org.jdom.Element;

import ghidra.util.xml.XmlUtilities;

/**
 * An object in this class stores a sequence of instructions along with the sizes and operands of each. 
 * These sequences come from function starts, function returns, or immediately before function starts. 
 */

public class InstructionSequence {

	final static String XML_ELEMENT_NAME = "InstructionSequence";

	private String[] instructions;
	private Integer[] sizes;
	private String[] commaSeparatedOperands;

	/**
	 * Default no-arg constructor
	 */
	public InstructionSequence() {
	}

	/**
	 * Create a new InstructionSequence of a given length
	 * @param length length of sequence
	 */
	public InstructionSequence(int length) {
		instructions = new String[length];
		sizes = new Integer[length];
		commaSeparatedOperands = new String[length];
	}

	/**
	 * Returns all the the stored disassembly for an instruction sequence
	 * @param inOrder if true, the instructions are displayed in order.  If false they are reversed.
	 * @return the disassembly as a string
	 */
	public String getCompleteDisassembly(boolean inOrder) {
		return getDisassembly(instructions.length, inOrder);
	}

	/**
	 * Get a string representing the disassembly of the first {@code numInstructions} instructions
	 * in the sequence
	 * @param numInstructions number of instructions to display
	 * @param inOrder if true, the instructions are displayed in order.  If false, they are reversed.
	 * @return disassembly as a String
	 * @throw IllegalArgumentException if the number of instructions requested exceeds the number
	 * of instructions available
	 */
	public String getDisassembly(int numInstructions, boolean inOrder) {
		StringBuilder sb = new StringBuilder();
		int currentInst = 0;
		if (instructions == null || numInstructions <= 0) {
			return null;
		}
		if (numInstructions > instructions.length) {
			throw new IllegalArgumentException("Too many instructions requested!");
		}
		while (currentInst < numInstructions) {
			StringBuilder current = new StringBuilder();
			current.append(" ");
			current.append(instructions[currentInst]);
			current.append(":");
			current.append(sizes[currentInst]);
			current.append("(");
			if (commaSeparatedOperands[currentInst] != null) {
				current.append(commaSeparatedOperands[currentInst]);
			}
			current.append(")");
			current.append(" ");
			if (inOrder) {
				sb.append(current);
			}
			else {
				sb.insert(0, current);
			}
			currentInst++;
		}
		return sb.toString();
	}

	/**
	 * Get the instructions in the sequence
	 * @return instructions
	 */
	public String[] getInstructions() {
		return instructions;
	}

	/**
	 * Set the instructions in the sequence
	 * @param instructions instructions
	 */
	public void setInstructions(String[] instructions) {
		this.instructions = instructions;
	}

	/**
	 * Get the sizes of the instructions in the sequence
	 * @return sizes
	 */
	public Integer[] getSizes() {
		return sizes;
	}

	/**
	 * Set the sizes of the instructions in the sequence
	 * @param sizes sizes
	 */
	public void setSizes(Integer[] sizes) {
		this.sizes = sizes;
	}

	/**
	 * Get the comma-separated operands of the instructions in the sequence
	 * @return array of comma-separated operands
	 */
	public String[] getCommaSeparatedOperands() {
		return commaSeparatedOperands;
	}

	/**
	 * Set the comma-separated operands of the instructions in the sequence
	 * @param commaSeparatedOperands array of comma-separated operands
	 */
	public void setCommaSeparatedOperands(String[] commaSeparatedOperands) {
		this.commaSeparatedOperands = commaSeparatedOperands;
	}

	@Override
	public int hashCode() {
		int hashcode = 17;
		hashcode = 31 * hashcode + Arrays.hashCode(instructions);
		hashcode = 31 * hashcode + Arrays.hashCode(sizes);
		if (commaSeparatedOperands != null) {
			hashcode = 31 * hashcode + Arrays.hashCode(commaSeparatedOperands);
		}
		return hashcode;
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
		InstructionSequence other = (InstructionSequence) obj;
		if (!Arrays.equals(instructions, other.getInstructions())) {
			return false;
		}
		if (!Arrays.equals(sizes, other.getSizes())) {
			return false;
		}
		if (commaSeparatedOperands == null) {
			if (other.getCommaSeparatedOperands() != null) {
				return false;
			}
			if (other.getCommaSeparatedOperands() == null) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (instructions == null) {
			sb.append("null instructions\n");
		}
		else {
			int size = instructions.length;
			for (int i = 0; i < size; ++i) {
				sb.append(instructions[i]);
				sb.append(":");
				sb.append(sizes[i]);
				sb.append(" (");
				sb.append(commaSeparatedOperands[i]);
				sb.append(")");
				if (i != size - 1) {
					sb.append(" ");
				}
			}
		}
		return sb.toString();
	}

	/**
	 * Get the list of all {@link InstructionSequence}s of a given type which pass a given {@link ContextRegisterFilter}
	 * @param fsReader populated {@link FileBitPatternInfoReader} 
	 * @param type desired type of sequence
	 * @param regFilter filter that returned {@link InstructionSequence}s must pass
	 * @return sequences
	 */
	public static List<InstructionSequence> getInstSeqs(FileBitPatternInfoReader fsReader,
			PatternType type, ContextRegisterFilter regFilter) {
		List<InstructionSequence> instSeqs = new ArrayList<InstructionSequence>();
		for (FunctionBitPatternInfo fInfo : fsReader.getFInfoList()) {
			if (regFilter != null && !regFilter.allows(fInfo.getContextRegisters())) {
				continue;
			}
			switch (type) {
				case FIRST:
					InstructionSequence currentSeq = fInfo.getFirstInst();
					if (currentSeq.getInstructions()[0] != null &&
						(fInfo.getFirstBytes() != null)) {
						instSeqs.add(currentSeq);
					}
					break;
				case PRE:
					currentSeq = fInfo.getPreInst();
					//In some cases, bytes can be null while instructions are not
					//happens when you asked for more bytes than were available
					//TODO: verify that this is still an issue
					if (currentSeq.getInstructions()[0] != null && (fInfo.getPreBytes() != null)) {
						instSeqs.add(currentSeq);
					}
					break;
				case RETURN:
					List<InstructionSequence> currentSeqs = fInfo.getReturnInst();
					List<String> currentBytes = fInfo.getReturnBytes();
					if (currentSeqs.size() != currentBytes.size()) {
						continue;
					}
					for (int i = 0, numSeqs = currentSeqs.size(); i < numSeqs; ++i) {
						if (currentSeqs.get(i)
							.getInstructions()[0] != null && currentBytes.get(i)
								.getBytes() != null) {
							instSeqs.add(currentSeqs.get(i));
						}
					}
					break;
				default:
					throw new IllegalArgumentException(
						"unsupported instruction type: " + type.name());
			}
		}
		return instSeqs;
	}

	/**
	 * Convert this object into a XML node, using {@link #XML_ELEMENT_NAME} as the name for the node.
	 * 
	 * @return new XML element
	 */
	public Element toXml() {
		return toXml(XML_ELEMENT_NAME);
	}

	/**
	 * Convert this object into a XML node, using the specified name for the node.
	 * 
	 * @param elementName name for the new XML node
	 * @return new XML element
	 */
	public Element toXml(String elementName) {
		Element result = new Element(elementName);

		Element instructionsListEle = new Element("instructions");
		result.addContent(instructionsListEle);
		if (instructions != null) {
			for (String s : instructions) {
				Element x = new Element("instruction");
				instructionsListEle.addContent(x);
				if (s != null) {
					x.setAttribute("value", s);
				}
			}
		}

		Element sizesListEle = new Element("sizes");
		result.addContent(sizesListEle);
		if (sizes != null) {
			for (Integer s : sizes) {
				Element x = new Element("size");
				sizesListEle.addContent(x);
				if (s != null) {
					XmlUtilities.setIntAttr(x, "value", s);
				}
			}
		}

		Element csoListEle = new Element("commaSeparatedOperands");
		result.addContent(csoListEle);
		if (commaSeparatedOperands != null) {
			for (String s : commaSeparatedOperands) {
				Element x = new Element("operands");
				csoListEle.addContent(x);
				if (s != null) {
					x.setAttribute("value", s);
				}
			}
		}

		return result;
	}

	/**
	 * Creates an {@link InstructionSequence} instance from a XML node.
	 * 
	 * @param element jdom Element to read, null ok
	 * @return new {@link InstructionSequence} or null if element was null
	 */
	public static InstructionSequence fromXml(Element element) {
		if (element == null) {
			return null;
		}

		List<String> instructionsList = new ArrayList<>();
		Element instructionsListEle = element.getChild("instructions");
		if (instructionsListEle != null) {
			for (Element instEle : XmlUtilities.getChildren(instructionsListEle, "instruction")) {
				String val = instEle.getAttributeValue("value");
				instructionsList.add(val);
			}
		}

		List<Integer> sizesList = new ArrayList<>();
		Element sizesListEle = element.getChild("sizes");
		if (sizesListEle != null) {
			for (Element sizeEle : XmlUtilities.getChildren(sizesListEle, "size")) {
				String val = sizeEle.getAttributeValue("value");
				sizesList.add(val != null ? XmlUtilities.parseInt(val) : null);
			}
		}

		List<String> csoList = new ArrayList<>();
		Element csoListEle = element.getChild("commaSeparatedOperands");
		if (csoListEle != null) {
			for (Element csoEle : XmlUtilities.getChildren(csoListEle, "operands")) {
				String val = csoEle.getAttributeValue("value");
				csoList.add(val);
			}
		}

		InstructionSequence result = new InstructionSequence();
		result.setInstructions(instructionsList.toArray(new String[instructionsList.size()]));
		result.setCommaSeparatedOperands(csoList.toArray(new String[csoList.size()]));
		result.setSizes(sizesList.toArray(new Integer[sizesList.size()]));

		return result;
	}
}
