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

import java.math.BigInteger;
import java.util.*;

import org.jdom.Element;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;

/**
 * This class represents information about small neighborhoods around the start and returns of a
 * single function
 */

public class FunctionBitPatternInfo {

	static final String XML_ELEMENT_NAME = "FunctionBitPatternInfo";

	private InstructionSequence firstInst;
	private InstructionSequence preInst;
	private List<InstructionSequence> returnInst;

	private String preBytes = null;//the (hexlified) bytes immediately preceding a function start
	private String firstBytes = null;//the first bytes of a function
	private List<String> returnBytes;//for each return in then function, the nearby bytes
	private String address = null;//the offset of a function

	private List<ContextRegisterInfo> contextRegisters;//the values for each of the specified context registers

	private static String getBytesAsString(byte[] bytes) {
		StringBuilder byteStringBuilder = new StringBuilder();
		for (byte b : bytes) {
			String byteString = Integer.toHexString(b & 0xff);
			if (byteString.length() == 1) {
				byteStringBuilder.append("0");
			}
			byteStringBuilder.append(byteString);
		}
		return byteStringBuilder.toString();
	}

	/**
	 * No-arg constructor
	 */
	public FunctionBitPatternInfo() {
		returnBytes = new ArrayList<String>();
		returnInst = new ArrayList<InstructionSequence>();
	}

	/**
	 * Creates a {@link FunctionBitPatternInfo} object consisting of information gathered
	 * for a given {@link Function} using the specified {@link DataGatheringParams}
	 * @param program {@link Program} containing the {@link Function}
	 * @param func {@link Function} to gather data about
	 * @param params parameters controlling how much data is gathered
	 */
	public FunctionBitPatternInfo(Program program, Function func, DataGatheringParams params) {
		Listing listing = program.getListing();
		//if specified, create ContextRegisterInfo objects for each context register
		//TODO: do this at the end and add the contextRegisterInfo to the 
		if (params.getContextRegisters() != null) {
			contextRegisters =
				recordContextRegisterInfo(program, func, params.getContextRegisters());
		}

		firstInst = getInstructionsFollowFlow(params.getNumFirstInstructions(), program,
			func.getEntryPoint(), listing);
		//retreat to the address immediately before the function start
		Address pre = func.getEntryPoint().subtract(1);
		preInst =
			getInstructionsAgainstFlow(params.getNumPreInstructions(), program, pre, listing, null);
		//record the starting address
		Address start = func.getEntryPoint();
		String addrString = start.toString();
		int colonIndex = addrString.indexOf(":");
		if (colonIndex == -1) {
			this.address = start.toString();
		}
		else {
			//in case the name of the space is part of the address string
			this.address = start.toString().substring(colonIndex + 1);
		}

		//get the first bytes
		Memory mem = program.getMemory();
		int numFirstBytes = 0;
		for (Integer size : firstInst.getSizes()) {
			if (size == null) {
				break;
			}
			numFirstBytes += size;
		}
		//want enough bytes to capture all of the instructions
		numFirstBytes = Math.max(numFirstBytes, params.getNumFirstBytes());
		//but don't want to go outside of the function
		numFirstBytes = Math.min(numFirstBytes, (int) func.getBody().getNumAddresses());
		byte[] firstBytesArray = getBytesWithFlow(numFirstBytes, mem, start);
		if (firstBytesArray != null) {
			this.firstBytes = getBytesAsString(firstBytesArray);
		}

		//get the preBytes
		Address adjustedAddress = start.add(-1);
		int numPreBytes = 0;
		for (Integer size : preInst.getSizes()) {
			if (size == null) {
				break;
			}
			numPreBytes += size;
		}
		numPreBytes = Math.max(numPreBytes, params.getNumPreBytes());

		byte preByteArray[] = getBytesAgainstFlow(numPreBytes, mem, adjustedAddress);
		if (preByteArray != null) {
			this.preBytes = getBytesAsString(preByteArray);
		}

		//get the return bytes and return instructions
		//first iterate through all the instructions to find returns
		//need to record the length of each return instruction to know where to start recording bytes
		returnBytes = new ArrayList<String>();
		returnInst = new ArrayList<InstructionSequence>();
		Map<Address, Integer> returnsToSizes = new HashMap<Address, Integer>();
		InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
		while (instIter.hasNext()) {
			Instruction currentInstruction = instIter.next();
			FlowType currentFlowType = currentInstruction.getFlowType();
			//TODO: is this the complete set of flow types corresponding to function returns?
			if (currentFlowType.equals(RefType.CALL_TERMINATOR) ||
				currentFlowType.equals(RefType.TERMINATOR) ||
				currentFlowType.equals(RefType.CONDITIONAL_CALL_TERMINATOR) ||
				currentFlowType.equals(RefType.CONDITIONAL_TERMINATOR)) {
				returnsToSizes.put(currentInstruction.getAddress(),
					new Integer(currentInstruction.getLength()));
			}
		}

		for (Address currentAddress : returnsToSizes.keySet()) {
			adjustedAddress = currentAddress.add(returnsToSizes.get(currentAddress) - 1);
			InstructionSequence returnInstructions =
				getInstructionsAgainstFlow(params.getNumReturnInstructions(), program,
					currentAddress, listing, func.getBody());
			if (returnInstructions == null) {
				return;
			}
			returnInst.add(returnInstructions);
			int numReturnBytes = 0;
			for (Integer size : returnInstructions.getSizes()) {
				if (size == null) {
					break;
				}
				numReturnBytes += size;
			}
			numReturnBytes = Math.max(numReturnBytes, params.getNumReturnBytes());

			byte[] returnBytesArray = getBytesAgainstFlow(numReturnBytes, mem, adjustedAddress);
			if (returnBytesArray != null) {
				String returnBytesString = getBytesAsString(returnBytesArray);
				returnBytes.add(returnBytesString);
			}
		}
	}

	private byte[] getBytesAgainstFlow(int numBytes, Memory memory, Address start) {
		MemoryBlock currentBlock = memory.getBlock(start);

		if (currentBlock == null) {
			return null;  //there are no bytes immediately before the function
		}

		byte[] bytes = new byte[numBytes];
		Address pre = start.subtract(numBytes - 1);
		//don't want to extend into another section
		MemoryBlock preBlock = memory.getBlock(pre);
		if ((preBlock == null) || (currentBlock.compareTo(preBlock) != 0)) {
			bytes = null;
		}
		else {
			try {
				memory.getBytes(pre, bytes);
			}
			catch (MemoryAccessException e) {
				Msg.info(this, "MemoryAccessException for address" + pre.toString());
				bytes = null;
			}
		}
		return bytes;
	}

	private byte[] getBytesWithFlow(int numBytes, Memory memory, Address start) {
		byte[] bytes = new byte[numBytes];
		try {
			memory.getBytes(start, bytes);
		}
		catch (MemoryAccessException e) {
			Msg.info(this, "MemoryAccessException for address" + start.toString());
		}
		return bytes;
	}

	private InstructionSequence getInstructionsAgainstFlow(int numInstructions, Program program,
			Address startAddress, Listing listing, AddressSetView validAddresses) {
		InstructionSequence instructions = new InstructionSequence(numInstructions);
		CodeUnit cu = listing.getCodeUnitContaining(startAddress);

		if (cu instanceof Instruction) {
			Instruction preInstruction = (Instruction) cu;
			for (int j = 0; j < numInstructions; j++) {
				try {
					if (preInstruction == null) {
						break;
					}
					//if validAddresses is not null, check that the address is
					//in validAddresses 
					if (validAddresses != null) {
						Address preInstStart = preInstruction.getAddress();
						if (!validAddresses.contains(preInstStart)) {
							break;
						}
					}
					instructions.getInstructions()[j] = (preInstruction.getMnemonicString());
					instructions.getSizes()[j] = (preInstruction.getBytes().length);
					StringBuilder sb = new StringBuilder();
					for (int k = 0; k < preInstruction.getNumOperands(); k++) {
						sb.append(preInstruction.getDefaultOperandRepresentation(k));
						if (k != preInstruction.getNumOperands() - 1) {
							sb.append(",");
						}
					}
					instructions.getCommaSeparatedOperands()[j] = (sb.toString());
					preInstruction = preInstruction.getPrevious();

				}
				catch (MemoryAccessException e) {
					//Msg.info(this, "Memory Access Exception at " +
					//	preInstruction.getAddress().toString());
					break;
				}
			}
		}
		return instructions;
	}

	private InstructionSequence getInstructionsFollowFlow(int numInstructions, Program program,
			Address startAddress, Listing listing) {
		InstructionSequence instructions = new InstructionSequence(numInstructions);
		Function func = program.getFunctionManager().getFunctionAt(startAddress);
		InstructionIterator instIter = listing.getInstructions(func.getBody(), true);

		for (int i = 0; i < numInstructions; ++i) {
			Instruction currentInst = instIter.next();
			if (currentInst == null) {
				break;//out of instructions, stop
			}

			//if a function contains a jump to a section of code which comes before its entry point in memory,
			//advance the iterator to the entry point
			while (currentInst.getAddress().compareTo(func.getEntryPoint()) < 0) {
				currentInst = instIter.next();
			}

			try {
				instructions.getInstructions()[i] = (currentInst.getMnemonicString());
				instructions.getSizes()[i] = (currentInst.getBytes().length);
				StringBuilder sb = new StringBuilder();

				//build the csv string of operands for the ith instruction
				for (int j = 0; j < currentInst.getNumOperands(); j++) {
					sb.append(currentInst.getDefaultOperandRepresentation(j));
					if (j != currentInst.getNumOperands() - 1) {
						sb.append(",");
					}
				}
				instructions.getCommaSeparatedOperands()[i] = (sb.toString());
			}
			catch (MemoryAccessException e) {
				//Msg.info(this, "Memory Access Exception at " + currentInst.getAddress().toString());
				break;
			}
		}
		return instructions;
	}

	private List<ContextRegisterInfo> recordContextRegisterInfo(Program program, Function func,
			List<String> contextRegs) {
		List<ContextRegisterInfo> contextRegisterInfo =
			new ArrayList<ContextRegisterInfo>(contextRegs.size());
		int numContextRegs = contextRegs.size();
		for (int i = 0; i < numContextRegs; ++i) {
			contextRegisterInfo.add(new ContextRegisterInfo(contextRegs.get(i)));
		}
		ProgramContext pContext = program.getProgramContext();
		for (ContextRegisterInfo cRegInfo : contextRegisterInfo) {
			Register reg = program.getRegister(cRegInfo.getContextRegister());
			if (reg == null) {
				Msg.info(this, "null returned for register :" + cRegInfo.getContextRegister() +
					" - spelling error?");
				continue;
			}
			BigInteger value = pContext.getValue(reg, func.getEntryPoint(), false);
			cRegInfo.setValue(value);
		}
		return contextRegisterInfo;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (contextRegisters != null) {
			sb.append("Registers: ");
			int size = contextRegisters.size();
			for (int i = 0; i < size; i++) {
				sb.append(contextRegisters.get(i).getContextRegister());
				sb.append(": ");
				sb.append(contextRegisters.get(i).getValue());
				sb.append(" ");
			}
			sb.append("\n");
		}
		sb.append("Prebytes: ");
		sb.append(preBytes);
		sb.append("\n");
		if (preInst != null) {
			sb.append("preInstructions: ");
			sb.append(preInst.toString());
		}
		sb.append("\nAddress: ");
		sb.append(address.toString());
		sb.append("\nfirstInstructions: ");
		sb.append(firstInst.toString());
		sb.append("\nfirstBytes: ");
		sb.append(firstBytes);
		sb.append("\nreturns:");
		int numReturns = returnBytes.size();
		for (int i = 0; i < numReturns; ++i) {
			sb.append("\n  bytes:\n   ");
			sb.append(returnBytes.get(i));
			sb.append("\n  inst:\n   ");
			sb.append(returnInst.get(i));
		}

		return sb.toString();
	}

	//getters/setters needed for JAXB

	/**
	 * Get the sequence of first instructions of the function
	 * @return the first instructions
	 */
	public InstructionSequence getFirstInst() {
		return firstInst;
	}

	/**
	 * Set the sequence of first instructions of the function
	 * 
	 * @param firstInst
	 */
	public void setFirstInst(InstructionSequence firstInst) {
		this.firstInst = firstInst;
	}

	/**
	 * Get the sequence of instructions immediately before the function
	 * @return pre-instructions
	 */
	public InstructionSequence getPreInst() {
		return preInst;
	}

	/**
	 * Set the sequence of instructions immediately before the function
	 * @param preInst pre-instructions 
	 */
	public void setPreInst(InstructionSequence preInst) {
		this.preInst = preInst;
	}

	/**
	 * Get the list of sequences of instructions immediately before a return instruction
	 * @return list of sequences of instructions before a return instruction
	 */
	public List<InstructionSequence> getReturnInst() {
		return returnInst;
	}

	/**
	 * Set the list of sequences of instructions immediately before a return instruction
	 * @param returnInst list of sequences of instructions immediately before a return instruction
	 */
	public void setReturnInst(List<InstructionSequence> returnInst) {
		this.returnInst = returnInst;
	}

	/**
	 * Get a {@link String} representation of the bytes immediately before a function
	 * @return byte string
	 */
	public String getPreBytes() {
		return preBytes;
	}

	/**
	 * Set the {@link String} representation of the bytes immediately before a function
	 * @param preBytes byte string
	 */
	public void setPreBytes(String preBytes) {
		this.preBytes = preBytes;
	}

	/**
	 * Get the {@link String} representation of the first bytes of a function
	 * @return byte string
	 */
	public String getFirstBytes() {
		return firstBytes;
	}

	/**
	 * Set the {@link String} representation of the first bytes of a function
	 * @param firstBytes byte string
	 */
	public void setFirstBytes(String firstBytes) {
		this.firstBytes = firstBytes;
	}

	/**
	 * Get the {@link String} representations of the bytes immediately before (and including) 
	 * a return instruction.
	 * @return byte strings
	 */
	public List<String> getReturnBytes() {
		return returnBytes;
	}

	/**
	 * Set the {@link String} representations of the bytes immediately before (and including)
	 * a return instruction
	 * @param returnBytes byte strings
	 */
	public void setReturnBytes(List<String> returnBytes) {
		this.returnBytes = returnBytes;
	}

	/**
	 * Get the {@link String} representation of the address of the entry point of the function
	 * @return address string
	 */
	public String getAddress() {
		return address;
	}

	/**
	 * Set the {@link String} representation of the address of the entry point of the function
	 * @param address address string
	 */
	public void setAddress(String address) {
		this.address = address;
	}

	/**
	 * Get the context register names and values for a function
	 * @return context register name and values
	 */
	public List<ContextRegisterInfo> getContextRegisters() {
		return contextRegisters;
	}

	/**
	 * Set the context register names and values for a function
	 * @param contextRegisters context register names and values
	 */
	public void setContextRegisters(List<ContextRegisterInfo> contextRegisters) {
		this.contextRegisters = contextRegisters;
	}

	/**
	 * Converts a XML element into a FunctionBitPatternInfo object.
	 * 
	 * @param e xml {@link Element} to convert
	 * @return new {@link FunctionBitPatternInfo} object, never null
	 */
	public static FunctionBitPatternInfo fromXml(Element e) {
		String preBytes = e.getAttributeValue("preBytes");
		String firstBytes = e.getAttributeValue("firstBytes");
		String address = e.getAttributeValue("address");

		List<String> returnBytes = new ArrayList<>();
		Element returnBytesListEle = e.getChild("returnBytesList");
		if (returnBytesListEle != null) {
			for (Element rbEle : XmlUtilities.getChildren(returnBytesListEle, "returnBytes")) {
				returnBytes.add(rbEle.getAttributeValue("value"));
			}
		}

		InstructionSequence firstInst = InstructionSequence.fromXml(e.getChild("firstInst"));
		InstructionSequence preInst = InstructionSequence.fromXml(e.getChild("preInst"));

		List<InstructionSequence> returnInst = new ArrayList<>();
		Element returnInstListEle = e.getChild("returnInstList");
		if (returnInstListEle != null) {
			for (Element isEle : XmlUtilities.getChildren(returnInstListEle,
				InstructionSequence.XML_ELEMENT_NAME)) {
				returnInst.add(InstructionSequence.fromXml(isEle));
			}
		}

		List<ContextRegisterInfo> contextRegisters = new ArrayList<>();
		Element contextRegistersListEle = e.getChild("contextRegistersList");
		if ( contextRegistersListEle != null ) {
			for (Element criElement : XmlUtilities.getChildren(contextRegistersListEle,
				ContextRegisterInfo.XML_ELEMENT_NAME)) {
				contextRegisters.add(ContextRegisterInfo.fromXml(criElement));
			}
		}
		
		FunctionBitPatternInfo result = new FunctionBitPatternInfo();
		result.setPreBytes(preBytes);
		result.setFirstBytes(firstBytes);
		result.setAddress(address);
		result.setReturnBytes(returnBytes);
		result.setFirstInst(firstInst);
		result.setPreInst(preInst);
		result.setReturnInst(returnInst);
		result.setContextRegisters(contextRegisters);

		return result;
	}

	/**
	 * Converts this object instance into XML.
	 * 
	 * @return new jdom Element populated with all the datas
	 */
	public Element toXml() {
		Element result = new Element(XML_ELEMENT_NAME);

		XmlUtilities.setStringAttr(result, "preBytes", preBytes);
		XmlUtilities.setStringAttr(result, "firstBytes", firstBytes);
		XmlUtilities.setStringAttr(result, "address", address);
		Element returnBytesListEle = new Element("returnBytesList");
		result.addContent(returnBytesListEle);
		for (String s : returnBytes) {
			Element rbNode = new Element("returnBytes");
			XmlUtilities.setStringAttr(rbNode, "value", s);
			returnBytesListEle.addContent(rbNode);
		}
		if (firstInst != null) {
			result.addContent(firstInst.toXml("firstInst"));
		}
		if (preInst != null) {
			result.addContent(preInst.toXml("preInst"));
		}
		if (returnInst != null) {
			Element returnInstListEle = new Element("returnInstList");
			result.addContent(returnInstListEle);
			for (InstructionSequence is : returnInst) {
				returnInstListEle.addContent(is.toXml());
			}
		}
		if (contextRegisters != null) {
			Element contextRegistersListEle = new Element("contextRegistersList");
			result.addContent(contextRegistersListEle);
			for (ContextRegisterInfo cri : contextRegisters) {
				contextRegistersListEle.addContent(cri.toXml());
			}
		}

		return result;
	}

}
