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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;
import java.lang.reflect.Array;
import java.util.*;

import ghidra.app.util.bin.format.dwarf4.DWARFUtil;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * State and methods needed for structure mapped objects to add markup, comments, labels, etc
 * to a program. 
 */
public class MarkupSession {
	protected Program program;
	protected DataTypeMapper mappingContext;
	protected Set<Address> markedupStructs = new HashSet<>();
	protected TaskMonitor monitor;

	/**
	 * Creates a new markup session
	 * 
	 * @param programContext program-level structure mapping context
	 * @param monitor allows user to cancel
	 */
	public MarkupSession(DataTypeMapper programContext, TaskMonitor monitor) {
		this.mappingContext = programContext;
		this.monitor = monitor;
		this.program = programContext.getProgram();
	}

	/**
	 * Returns the Ghidra program
	 * 
	 * @return Ghidra {@link Program}
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns the program level mapping context
	 * 
	 * @return {@link DataTypeMapper}
	 */
	public DataTypeMapper getMappingContext() {
		return mappingContext;
	}

	/**
	 * Decorates the specified object's memory using the various structure mapping tags that 
	 * were applied the object's class definition.
	 * <p>
	 * The object can be a structure mapped object, or a collection, array or iterator of structure
	 * mapped objects.
	 * 
	 * @param <T> structure mapped object type
	 * @param obj structure mapped object instance
	 * @param nested boolean flag, if true the specified object is contained inside another object
	 * who's data type has already been laid down in memory, removing the need for this object's
	 * data type to be applied to memory 
	 * @throws IOException if error or cancelled
	 * @throws IllegalArgumentException if object instance is not a supported type
	 */
	public <T> void markup(T obj, boolean nested) throws IOException {
		if (monitor.isCancelled()) {
			throw new IOException("Markup canceled");
		}
		if (obj == null) {
			return;
		}
		if (obj instanceof Collection<?> list) {
			for (Object listElement : list) {
				markup(listElement, nested);
			}
		}
		else if (obj.getClass().isArray()) {
			int len = Array.getLength(obj);
			for (int i = 0; i < len; i++) {
				markup(Array.get(obj, i), nested);
			}
		}
		else if (obj instanceof Iterator<?> it) {
			while (it.hasNext()) {
				Object itElement = it.next();
				markup(itElement, nested);
			}
		}
		else {
			StructureContext<T> structureContext = mappingContext.getStructureContextOfInstance(obj);
			if (structureContext == null) {
				throw new IllegalArgumentException();
			}
			monitor.incrementProgress(1);
			markupStructure(structureContext, nested);
		}
	}

	/**
	 * Applies the specified {@link DataType} to the specified {@link Address}.
	 * 
	 * @param addr location to place DataType
	 * @param dt {@link DataType}
	 * @throws IOException if error marking up address
	 */
	public void markupAddress(Address addr, DataType dt) throws IOException {
		markupAddress(addr, dt, -1);
	}

	/**
	 * Applies the specified {@link DataType} to the specified {@link Address}.
	 * 
	 * @param addr location to place DataType
	 * @param dt {@link DataType}
	 * @param length length of the data type instance, or -1 if the data type is fixed length
	 * @throws IOException if error marking up address
	 */
	public void markupAddress(Address addr, DataType dt, int length) throws IOException {
		try {
			DataUtilities.createData(program, addr, dt, length, false,
				ClearDataMode.CLEAR_ALL_DEFAULT_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			throw new IOException(e);
		}

	}

	/**
	 * Applies the specified {@link DataType} to the specified {@link Address}.
	 * 
	 * @param addr location to place DataType
	 * @param dt {@link DataType}
	 * @throws IOException if error marking up address
	 */
	public void markupAddressIfUndefined(Address addr, DataType dt) throws IOException {
		Data data = DataUtilities.getDataAtAddress(program, addr);
		if (data == null || Undefined.isUndefined(data.getBaseDataType())) {
			markupAddress(addr, dt);
		}
	}

	/**
	 * Places a label at the specified structure mapped object's address.
	 * 
	 * @param <T> structure mapped object type
	 * @param obj structure mapped object
	 * @param symbolName name
	 * @throws IOException if error
	 */
	public <T> void labelStructure(T obj, String symbolName) throws IOException {
		Address addr = mappingContext.getAddressOfStructure(obj);
		labelAddress(addr, symbolName);
	}

	/**
	 * Places a label at the specified address.
	 * 
	 * @param addr {@link Address}
	 * @param symbolName name
	 * @throws IOException if error
	 */
	public void labelAddress(Address addr, String symbolName) throws IOException {
		try {
			SymbolTable symbolTable = program.getSymbolTable();
			Symbol[] symbols = symbolTable.getSymbols(addr);
			if (symbols.length == 0 || symbols[0].isDynamic()) {
				symbolName = SymbolUtilities.replaceInvalidChars(symbolName, true);
				symbolTable.createLabel(addr, symbolName, SourceType.IMPORTED);
			}
		}
		catch (InvalidInputException e) {
			throw new IOException(e);
		}
	}

	/**
	 * Adds a comment to the specified field, appending to any previous values
	 * already there.  If the existing comment already contains the specified comment value,
	 * the operation is skipped.
	 * 
	 * @param fieldContext the field
	 * @param commentType {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#PLATE_COMMENT},
	 * {@link CodeUnit#POST_COMMENT}, {@link CodeUnit#PRE_COMMENT} 
	 * @param prefix String prefix to place in front of the comment string
	 * @param comment String value to append
	 * @param sep separator to use between existing comments (for example, "\n")
	 * @throws IOException if error adding comment
	 */
	public void appendComment(FieldContext<?> fieldContext, int commentType, String prefix,
			String comment, String sep) throws IOException {
		DWARFUtil.appendComment(program, fieldContext.getAddress(), commentType, prefix, comment,
			sep);
	}

	/**
	 * Adds a comment to the specified structure, appending to any previous values
	 * already there.  If the existing comment already contains the specified comment value,
	 * the operation is skipped.
	 * 
	 * @param structureContext the structure
	 * @param commentType {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#PLATE_COMMENT},
	 * {@link CodeUnit#POST_COMMENT}, {@link CodeUnit#PRE_COMMENT} 
	 * @param prefix String prefix to place in front of the comment string
	 * @param comment String value to append
	 * @param sep separator to use between existing comments (for example, "\n")
	 * @throws IOException if error adding comment
	 */
	public void appendComment(StructureContext<?> structureContext, int commentType, String prefix,
			String comment, String sep) throws IOException {
		DWARFUtil.appendComment(program, structureContext.getStructureAddress(), commentType,
			prefix, comment, sep);
	}

	/**
	 * Decorates a structure mapped structure, and everything it contains.
	 * 
	 * @param <T> structure mapped type
	 * @param structureContext {@link StructureContext}
	 * @param nested if true, it is assumed that the Ghidra data types have already been
	 * placed and only markup needs to be performed.
	 * @throws IOException if error marking up structure
	 */
	public <T> void markupStructure(StructureContext<T> structureContext, boolean nested)
			throws IOException {
		Address addr = structureContext.getStructureAddress();
		if (!nested && !markedupStructs.add(addr)) {
			return;
		}

		T instance = structureContext.getStructureInstance();
		if (!nested) {
			try {
				Structure structDT = structureContext.getStructureDataType();
				markupAddress(addr, structDT);
			}
			catch (IOException e) {
				StructureMappingInfo<T> mappingInfo = structureContext.getMappingInfo();
				throw new IOException("Markup failed for structure %s at %s"
						.formatted(mappingInfo.getDescription(), addr),
					e);
			}

			if (instance instanceof StructureMarkup<?> sm) {
				String structureLabel = sm.getStructureLabel();
				if (structureLabel != null && !structureLabel.isBlank()) {
					labelAddress(addr, structureLabel);
				}
			}
		}

		markupFields(structureContext);

		if (instance instanceof StructureMarkup<?> sm) {
			sm.additionalMarkup(this);
		}

	}

	<T> void markupFields(StructureContext<T> structureContext) throws IOException {
		T structureInstance = structureContext.getStructureInstance();
		StructureMappingInfo<T> mappingInfo = structureContext.getMappingInfo();
		for (FieldMappingInfo<T> fmi : mappingInfo.getFields()) {
			for (FieldMarkupFunction<T> func : fmi.getMarkupFuncs()) {
				FieldContext<T> fieldContext = structureContext.createFieldContext(fmi, false);
				func.markupField(fieldContext, this);
			}
		}
		if (structureInstance instanceof StructureMarkup<?> sm) {
			for (Object externalInstance : sm.getExternalInstancesToMarkup()) {
				markup(externalInstance, false);
			}
		}

		for (StructureMarkupFunction<T> markupFunc : mappingInfo.getMarkupFuncs()) {
			markupFunc.markupStructure(structureContext, this);
		}

	}

	/**
	 * Creates references from each element of an array to a list of target addresses.
	 * 
	 * @param arrayAddr the address of the start of the array
	 * @param elementSize the size of each array element
	 * @param targetAddrs list of addresses that will receive references from each array elements
	 * @throws IOException if error
	 */
	public void markupArrayElementReferences(Address arrayAddr, int elementSize,
			List<Address> targetAddrs) throws IOException {
		if (!targetAddrs.isEmpty()) {
			ReferenceManager refMgr = program.getReferenceManager();

			for (Address targetAddr : targetAddrs) {
				if (targetAddr != null) {
					refMgr.addMemoryReference(arrayAddr, targetAddr, RefType.DATA,
						SourceType.IMPORTED, 0);
				}
				arrayAddr = arrayAddr.add(elementSize);
			}
		}
	}

	/**
	 * Creates a default function at the specified address.
	 * 
	 * @param name name of the new function
	 * @param addr address of the new function
	 * @return {@link Function} that was created
	 */
	public Function createFunctionIfMissing(String name, Address addr) {
		Function function = program.getListing().getFunctionAt(addr);
		if (function == null) {
			try {
				if (!program.getMemory()
						.getLoadedAndInitializedAddressSet()
						.contains(addr)) {
					Msg.warn(this,
						"Unable to create function not contained within loaded memory: %s@%s"
								.formatted(name, addr));
					return null;
				}
				function = program.getFunctionManager()
						.createFunction(name, addr, new AddressSet(addr), SourceType.IMPORTED);
			}
			catch (OverlappingFunctionException | InvalidInputException e) {
				Msg.error(this, e);
			}
		}
		else {
			// TODO: this does nothing.  re-evalulate this logic
			//mappingContext.labelAddress(addr, name);
		}
		return function;
	}

	/**
	 * Creates a reference from the specified field to the specified address.
	 * 
	 * @param fieldContext field, is the source of the reference
	 * @param refDest destination address of the reference
	 */
	public void addReference(FieldContext<?> fieldContext, Address refDest) {
		ReferenceManager refMgr = program.getReferenceManager();

		Address fieldAddr = fieldContext.getAddress();
		refMgr.addMemoryReference(fieldAddr, refDest, RefType.DATA, SourceType.IMPORTED, 0);
	}

}
