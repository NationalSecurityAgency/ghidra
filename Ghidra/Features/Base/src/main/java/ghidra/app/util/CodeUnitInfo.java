/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Container object to keep a relative index, label, and comments. Used
 * in a list for copying/pasting labels and comments from one program to
 * another.
 */
public class CodeUnitInfo {

	private final static long serialVersionUID = 1L;
	private static final String[] emptyStringArray = new String[0];
	private static final int[] emptyIntArray = new int[0];
	private static final Address[] emptyAddrArray = new Address[0];
	private static final SourceType[] emptySourceTypeArray = new SourceType[0];

	private int index;
	private boolean hasDynamicSymbol = false;
	private String primarySymbolName;
	private SourceType primarySymbolSource;
	private boolean primarySymbolInFunctionScope = false;
	private String[] functionScopeSymbolNames = emptyStringArray;
	private SourceType[] functionScopeSymbolSources = emptySourceTypeArray;
	private String[] otherSymbolNames = emptyStringArray;
	private SourceType[] otherSymbolSources = emptySourceTypeArray;
	private String[] plateComment = emptyStringArray;
	private String[] preComment = emptyStringArray;
	private String[] postComment = emptyStringArray;
	private String[] eolComment = emptyStringArray;
	private String[] repeatableComment = emptyStringArray;
	// function stuff
	private String functionName;
	private String[] functionComments = emptyStringArray;

	private String[] stackVarNames = emptyStringArray;
	private SourceType[] stackVarSources = emptySourceTypeArray;
	private int[] stackOffsets = emptyIntArray;
	private int[] stackVarFUOffsets = emptyIntArray;
	private String[] stackVarComments = emptyStringArray; // single line comment only

	// Includes all non-stack variables
	private String[] varNames = emptyStringArray;
	private SourceType[] varSources = emptySourceTypeArray;

// put in place to prevent exception when putting this object on the clipboard (SCR 6159)    
	private Address[] varAddrs = emptyAddrArray;
	private int[] varFUOffsets = emptyIntArray;
	private String[] varComments = emptyStringArray;

	// for each stack/reg/mem variable; comment array may contain "holes"
	// for those variables that do not have comments

	/**
	 * Constructor a new CodeUnitInfo.
	 * @param index relative index added to a base address
	 * for where this information will be placed
	 */
	public CodeUnitInfo(int index) {
		this.index = index;
	}

	/**
	 * Set the symbols to be transferred. 
	 */
	public void setSymbols(Symbol[] symbols) {
		primarySymbolName = null;
		List<String> scopeSymList = new ArrayList<String>();
		List<SourceType> scopeSymSourceList = new ArrayList<SourceType>();
		List<String> otherSymList = new ArrayList<String>();
		List<SourceType> otherSymSourceList = new ArrayList<SourceType>();
		for (int i = 0; i < symbols.length; i++) {
			SymbolType symbolType = symbols[i].getSymbolType();
			if (symbols[i].isDynamic()) {
				hasDynamicSymbol = true;
			}
			else if (symbols[i].isPrimary()) {
				primarySymbolName = symbols[i].getName();
				primarySymbolSource = symbols[i].getSource();
				primarySymbolInFunctionScope = (symbolType == SymbolType.FUNCTION);
			}
			else if (symbolType == SymbolType.FUNCTION) {
				scopeSymList.add(symbols[i].getName());
				scopeSymSourceList.add(symbols[i].getSource());
			}
			else {
				otherSymList.add(symbols[i].getName());
				otherSymSourceList.add(symbols[i].getSource());
			}
		}
		functionScopeSymbolNames = new String[scopeSymList.size()];
		scopeSymList.toArray(functionScopeSymbolNames);
		functionScopeSymbolSources = new SourceType[scopeSymSourceList.size()];
		scopeSymSourceList.toArray(functionScopeSymbolSources);
		otherSymbolNames = new String[otherSymList.size()];
		otherSymList.toArray(otherSymbolNames);
		otherSymbolSources = new SourceType[otherSymSourceList.size()];
		otherSymSourceList.toArray(otherSymbolSources);
	}

	/**
	 * Set the comment to be transferred.
	 * @param commentType CodeUnit.PRE_COMMENT, POST_COMMENT, 
	 * PLATE_COMMENT, EOL_COMMENT, or REPEATABLE.
	 * @param comment comment
	 */
	public void setComment(int commentType, String[] comment) {
		switch (commentType) {
			case CodeUnit.PLATE_COMMENT:
				plateComment = comment;
				break;

			case CodeUnit.PRE_COMMENT:
				preComment = comment;
				break;

			case CodeUnit.POST_COMMENT:
				postComment = comment;
				break;

			case CodeUnit.REPEATABLE_COMMENT:
				repeatableComment = comment;
				break;

			case CodeUnit.EOL_COMMENT:
				eolComment = comment;
		}
	}

	/**
	 * Set the function info.
	 * @param function function used to get function info to transfer 
	 */
	public void setFunction(Function function) {
		functionName = function.getName();
		functionComments = function.getCommentAsArray();

		Variable[] vars = function.getAllVariables();
		Variable[] stackVars = function.getVariables(VariableFilter.STACK_VARIABLE_FILTER);

		stackVarNames = new String[stackVars.length];
		stackVarSources = new SourceType[stackVars.length];
		stackOffsets = new int[stackVars.length];
		stackVarFUOffsets = new int[stackVars.length];
		stackVarComments = new String[stackVars.length];
		setStackVarInfo(stackVars);

		int nonStackVariableCount = vars.length - stackVars.length;
		varNames = new String[nonStackVariableCount];
		varSources = new SourceType[nonStackVariableCount];
		varAddrs = new Address[nonStackVariableCount];
		varFUOffsets = new int[nonStackVariableCount];
		varComments = new String[nonStackVariableCount];
		setNonStackVarInfo(vars);
	}

	/**
	 * Get the relative index for this CodeUnitInfo to add to a base address.
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Return whether this CodeUnitInfo has symbols to copy.
	 */
	public boolean hasSymbols() {
		return primarySymbolName != null || functionScopeSymbolNames.length != 0 ||
			otherSymbolNames.length != 0;
	}

	/**
	 * Return whether this CodeUnitInfo has a dynamic symbol.
	 */
	public boolean hasDynamicSymbol() {
		return hasDynamicSymbol;
	}

	/**
	 * Get the label; may be null.
	 */
	public String getPrimarySymbolName() {
		return primarySymbolName;
	}

	/**
	 * Get the label source
	 */
	public SourceType getPrimarySymbolSource() {
		return primarySymbolSource;
	}

	/**
	 * Is primary symbol in a function scope
	 */
	public boolean isPrimarySymbolInFunctionScope() {
		return primarySymbolInFunctionScope;
	}

	/**
	 * Get the names of the function scope symbols.
	 */
	public String[] getFunctionScopeSymbolNames() {
		return functionScopeSymbolNames;
	}

	/**
	 * Get the sources of the function scope symbols.
	 */
	public SourceType[] getFunctionScopeSymbolSources() {
		return functionScopeSymbolSources;
	}

	/**
	 * Get the names of the other symbols not in a function scope.
	 */
	public String[] getOtherSymbolNames() {
		return otherSymbolNames;
	}

	/**
	 * Get the sources of the other symbols not in a function scope.
	 */
	public SourceType[] getOtherSymbolSources() {
		return otherSymbolSources;
	}

	/**
	 * Get the plate comment.
	 */
	public String[] getPlateComment() {
		return plateComment;
	}

	/**
	 * Get the pre comment.
	 */
	public String[] getPreComment() {
		return preComment;
	}

	/**
	 * Get the post comment.
	 */
	public String[] getPostComment() {
		return postComment;
	}

	/**
	 * Get the EOL comment.
	 */
	public String[] getEOLComment() {
		return eolComment;
	}

	/**
	 * Get the repeatable comment.
	 */
	public String[] getRepeatableComment() {
		return repeatableComment;
	}

	/**
	 * Get the function name.
	 */
	public String getFunctionName() {
		return functionName;
	}

	/**
	 * Get the function comments.
	 */
	public String[] getFunctionComments() {
		return functionComments;
	}

	/**
	 * Get the stack variable names.
	 */
	public String[] getStackVariableNames() {
		return stackVarNames;
	}

	/**
	 * Get the stack variable sources.
	 */
	public SourceType[] getStackVariableSources() {
		return stackVarSources;
	}

	/**
	 * Get the stack offsets.
	 */
	public int[] getStackOffsets() {
		return stackOffsets;
	}

	/**
	 * Get the stack variable "First Use Offsets"
	 */
	public int[] getStackVarFirstUseOffsets() {
		return stackVarFUOffsets;
	}

	/**
	 * Get the stack variable comments.
	 */
	public String[] getStackVariableComments() {
		return stackVarComments;
	}

	/**
	 * Get the non-stack variable names.
	 */
	public String[] getVariableNames() {
		return varNames;
	}

	/**
	 * Get the non-stack variable sources.
	 */
	public SourceType[] getVariableSources() {
		return varSources;
	}

	/**
	 * Get the storage addresses corresponding to each non-stack variable.
	 */
	public Address[] getVarAddresses() {
		return varAddrs;
	}

	/**
	 * Get the non-stack variable "First Use Offsets"
	 */
	public int[] getVarFirstUseOffsets() {
		return varFUOffsets;
	}

	/**
	 * Get the non-stack variable comments.
	 */
	public String[] getVariableComments() {
		return varComments;
	}

	//////////////////////////////////////////////////////////////////
	/**
	 * Set the stack variable info for the function
	 * @param vars all function stack variables
	 */
	private void setStackVarInfo(Variable[] vars) {
		for (int i = 0; i < vars.length; i++) {
			stackVarNames[i] = vars[i].getName();
			stackVarSources[i] = vars[i].getSource();
			stackOffsets[i] = vars[i].getStackOffset();
			stackVarFUOffsets[i] = vars[i].getFirstUseOffset();
			stackVarComments[i] = vars[i].getComment();
		}
	}

	/**
	 * Set the non-stack variable info for the function
	 * @param vars all function variables
	 */
	private void setNonStackVarInfo(Variable[] vars) {
		int variableIndex = 0;
		for (int i = 0; i < vars.length; i++) {
			if (vars[i].isStackVariable()) {
				continue; // skip stack variables
			}
			varNames[variableIndex] = vars[i].getName();
			varSources[variableIndex] = vars[i].getSource();
			Varnode firstVarnode = vars[i].getFirstStorageVarnode();
			varAddrs[variableIndex] =
				firstVarnode != null ? firstVarnode.getAddress() : Address.NO_ADDRESS;
			varFUOffsets[variableIndex] = vars[i].getFirstUseOffset();
			varComments[variableIndex] = vars[i].getComment();
			++variableIndex;
		}
	}
//    
//    private void writeObject( ObjectOutputStream oos ) throws IOException {
//        // write out all of the serializable objects
//        oos.defaultWriteObject();
//        
//        // now write out the non-serializable variables (the ones we've marked as 'transient')
//        oos.writeInt( varAddrs.length );
//        for ( Address address : varAddrs ) {
//            AddressSpace addressSpace = address.getAddressSpace();
//            String spaceName = addressSpace.getName();
//            oos.writeChars( spaceName );
//            
//            int spaceSize = addressSpace.getSize();
//            oos.writeInt( spaceSize );
//            
//            int spaceUnitSize = addressSpace.getAddressableUnitSize();
//            oos.writeInt( spaceUnitSize );
//            
//            int spaceType = addressSpace.getType();
//            oos.writeInt( spaceType );
//            
//            int spaceUniqueValue = addressSpace.getUnique();
//            oos.writeInt( spaceUniqueValue );
//            
//            long addressOffset = address.getOffset();
//            oos.writeLong( addressOffset );
//        }
//    }
//    
//    private void readObject( ObjectInputStream ois ) throws IOException, ClassNotFoundException {
//        // read in all of the serializable objects
//        ois.defaultReadObject();
//        
//        // now read in the non-serializable variables (the ones we've marked as 'transient')
//        int varAddrsSize = ois.readInt();
//        if ( varAddrsSize == 0 ) {
//            varAddrs = emptyAddrArray;
//        }
//        else {
//            varAddrs = new Address[varAddrsSize];
//            for ( int i = 0; i < varAddrsSize; i++ ) {
//                String spaceName = ois.readUTF();
//                int spaceSize = ois.readInt();
//                int spaceUnitSize = ois.readInt();
//                int spaceType = ois.readInt();
//                int spaceUniqueValue = ois.readInt();
//                long addressOffset = ois.readLong();
//                
//                GenericAddressSpace addressSpace = new GenericAddressSpace( spaceName, 
//                    spaceSize, spaceUnitSize, spaceType, spaceUniqueValue );
//                varAddrs[i] = addressSpace.getAddress( addressOffset );
//            }
//        }
//    }
}
