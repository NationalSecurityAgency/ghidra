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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.util.*;
import java.util.Stack;
import java.util.function.Consumer;
import java.util.function.Predicate;

import ghidra.app.services.DataTypeReference;
import ghidra.app.services.DataTypeReferenceFinder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.datastruct.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class ReferenceUtils {

	private static final String EMBOLDEN_START =
		"<span style=\"background-color: #a3e4d7; color: black;\"><b><font size=4>";
	private static final String EMBOLDEN_END = "</font></b></span>";

	public static final String CONTEXT_CALLOUT_START = "[|";
	public static final String CONTEXT_CALLOUT_END = "|]";

	public static final String CONTEXT_CALLOUT_START_REGEX = "\\[\\|";
	public static final String CONTEXT_CALLOUT_END_REGEX = "\\|\\]";

	private ReferenceUtils() {
		// utility class
	}

	private static boolean isMemoryAddress(ProgramLocation loc) {
		Program program = loc.getProgram();
		Address addr = loc.getAddress();
		if (loc instanceof FunctionLocation) {
			addr = ((FunctionLocation) loc).getFunctionAddress();
		}

		return isMemoryAddress(program, addr);
	}

	private static boolean isMemoryAddress(Program p, Address a) {
		if (!a.isMemoryAddress()) {
			return false;
		}

		// not external, it must then be in memory
		if (!p.getMemory().contains(a)) {
			return false;
		}
		return true;
	}

	/**
	 * Returns addresses that reference the item at the given location.
	 *
	 * @param accumulator The Accumulator into which LocationReferences will be placed.
	 * @param location The location for which to find references
	 * @param monitor the task monitor used to track progress and cancel the work
	 * @throws CancelledException if the operation was cancelled 
	 */
	public static void getReferences(Accumulator<LocationReference> accumulator,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		Accumulator<LocationReference> asSet = asSet(accumulator);

		Program program = location.getProgram();
		Address address = location.getAddress();
		Consumer<LocationReference> consumer = ref -> accumulator.add(ref);
		accumulateDirectReferences(consumer, program, address);
		accumulateThunkReferences(asSet, program, address, monitor);

		if (isMemoryAddress(location)) {
			accumulateOffcutReferencesToCodeUnitAt(asSet, location, monitor);
		}
	}

	/**
	 * Returns a set references to the given address.
	 *
	 * @param location the location for which to find references
	 * @param monitor the task monitor used to track progress and cancel the work
	 * @return A set of addresses or an empty set if there are no references.
	 * @throws CancelledException if the operation was cancelled
	*/
	public static Set<Address> getReferenceAddresses(ProgramLocation location, TaskMonitor monitor)
			throws CancelledException {
		SetAccumulator<Address> accumulator = new SetAccumulator<>();
		getReferenceAddresses(accumulator, location, monitor);
		return accumulator.asSet();
	}

	/**
	 * Gets addresses that refer to the given address.
	 * <p>
	 * Note: this method will return all offcut references to any data containing the given
	 * address.
	 *
	 * @param accumulator the results accumulator
	 * @param location the location for which to find references
	 * @param monitor the task monitor used to track progress and cancel the work
	 * @throws CancelledException if the operation was cancelled
	 */
	private static void getReferenceAddresses(Accumulator<Address> accumulator,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		Program program = location.getProgram();
		Address address = location.getAddress();

		Consumer<LocationReference> consumer = ref -> accumulator.add(ref.getLocationOfUse());
		accumulateDirectReferences(consumer, program, address);
		accumulateThunkReferenceAddresses(accumulator, program, address, monitor);

		if (isMemoryAddress(location)) {
			accumulateOffcutReferenceAddresses(accumulator, location, monitor);
		}
	}

	/**
	 * Returns true if the given address does not point to the minimum address of the containing
	 * {@link CodeUnit}.
	 *
	 * @param program the program containing the address
	 * @param address the address to check
	 * @return true if the address is offcut
	 */
	public static boolean isOffcut(Program program, Address address) {

		if (!address.isMemoryAddress()) {
			return false;
		}

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return false;
		}

		if (cu instanceof Data) {
			// Update the code unit for the composite data like structures and arrays, as the
			// call to getCodeUnitContaining() gets the outermost data, not the inner-most.
			cu = getDeepestDataContaining(address, program);
		}

		if (cu.getMinAddress().equals(address)) {
			return false;
		}

		return true;
	}

	/**
	 * Returns all references (locations) that use the given datatype.
	 * <br>
	 * <b>Note: </b> This method call may take a long time, as it must search all of the
	 * data within the program and may also perform long running tasks, like decompiling every
	 * function in the program.
	 * <br>
	 * @param accumulator the results storage
	 * @param dataType The datatype for which to find references.
	 * @param fieldName optional field name for which to search; the <tt>dataType</tt> must be
	 *                  a {@link Composite} to search for a field
	 * @param program The program from within which to find references.
	 * @param monitor A task monitor to be updated as data is searched; if this is null, then a
	 *        dummy monitor will be used.
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static void findDataTypeReferences(Accumulator<LocationReference> accumulator,
			DataType dataType, String fieldName, Program program, TaskMonitor monitor)
			throws CancelledException {
		findDataTypeReferences(accumulator, dataType, fieldName, program, true, monitor);
	}

	/**
	 * Returns all references (locations) that use the given datatype.
	 * <br>
	 * <b>Note: </b> This method call may take a long time, as it must search all of the
	 * data within the program and may also perform long running tasks, like decompiling every
	 * function in the program.
	 * <br>
	 * @param accumulator the results storage
	 * @param dataType The datatype for which to find references.
	 * @param fieldName optional field name for which to search; the <tt>dataType</tt> must be
	 *                  a {@link Composite} to search for a field
	 * @param program The program from within which to find references.
	 * @param discoverTypes if true, the {@link DataTypeReferenceFinder} service 
	 *                will be used to search for data types that are not applied in memory.  
	 *                Using the service will be slower, but will recover type usage that could
	 *                not be found by examining the Listing.
	 * @param monitor A task monitor to be updated as data is searched; if this is null, then a
	 *        dummy monitor will be used.
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static void findDataTypeReferences(Accumulator<LocationReference> accumulator,
			DataType dataType, String fieldName, Program program, boolean discoverTypes,
			TaskMonitor monitor) throws CancelledException {

		// Note: none of the params can be null, but this one gets used much later, so check now
		Objects.requireNonNull(dataType, () -> "Data Type cannot be null");

		// sanity check
		if (fieldName != null && !(dataType instanceof Composite)) {
			throw new IllegalArgumentException("Can only search for a field with a Composite type");
		}

		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		Listing listing = program.getListing();

		long dataCount = listing.getNumDefinedData();
		int functionCount = program.getFunctionManager().getFunctionCount();
		int totalCount = (int) dataCount + functionCount;

		monitor.initialize(totalCount);

		// Mimic a set in case the client passes in an accumulator that allows duplicates.  This
		// seems a bit cleaner than adding checks for 'accumulator.contains(ref)' throughout
		// the code.
		Accumulator<LocationReference> asSet = asSet(accumulator);

		if (fieldName == null) {
			// It only makes sense to search here when we do not have a field

			boolean localsOnly = discoverTypes;
			FunctionIterator iterator = listing.getFunctions(false);
			findDataTypeMatchesInFunctionHeaders(asSet, iterator, dataType, localsOnly, monitor);

			// external functions don't get searched by type discovery  
			localsOnly = false;
			iterator = listing.getExternalFunctions();
			findDataTypeMatchesInFunctionHeaders(asSet, iterator, dataType, localsOnly, monitor);
		}

		Predicate<Data> dataMatcher = data -> {
			DataType baseType = getBaseDataType(data.getDataType());
			boolean matches = dataTypesMatch(dataType, baseType);
			return matches;
		};
		findDataTypeMatchesInDefinedData(asSet, program, dataMatcher, fieldName, monitor);

		if (discoverTypes) {
			findDataTypeMatchesOutsideOfListing(asSet, program, dataType, fieldName, monitor);
		}

		monitor.checkCanceled();
	}

	private static Accumulator<LocationReference> asSet(
			Accumulator<LocationReference> accumulator) {

		if (accumulator instanceof SetAccumulator) {
			return accumulator;
		}

		return new FilteringAccumulatorWrapper<>(accumulator, ref -> !accumulator.contains(ref));
	}

	private static void findDataTypeMatchesOutsideOfListing(
			Accumulator<LocationReference> accumulator, Program program, DataType dataType,
			String fieldName, TaskMonitor monitor) throws CancelledException {

		List<DataTypeReferenceFinder> finders =
			ClassSearcher.getInstances(DataTypeReferenceFinder.class);

		Consumer<DataTypeReference> callback = ref -> {

			String context = emboldenBracketedText(ref.getContext());
			LocationReference locationReference = new LocationReference(ref.getAddress(), context);
			accumulator.add(locationReference);
		};

		if (fieldName != null && !(dataType instanceof Composite)) {
			throw new AssertException(
				"Must have a Composite data type to perform a field search.  Found " + dataType +
					"; field '" + fieldName + "'");
		}

		if (finders.isEmpty()) {
			Msg.debug(ReferenceUtils.class, "Unable to find any implementations of " +
				DataTypeReferenceFinder.class.getSimpleName());
			return;
		}

		for (DataTypeReferenceFinder finder : finders) {
			if (fieldName == null) {
				finder.findReferences(program, dataType, callback, monitor);
			}
			else {
				finder.findReferences(program, (Composite) dataType, fieldName, callback, monitor);
			}
		}
	}

	/**
	 * A recursive function to get the base highest level data type for the given data type.  For
	 * example, if the give data type is an {@link Array}, then this
	 * method will be called again on its data type.
	 * <p>
	 * It is not always appropriate to find the base data type. This method contains the
	 * logic for determining when it is appropriate the seek out the
	 * base data type, as in the case of an Array object.
	 *
	 * @param dataType The data type for which to find the highest level data type.
	 * @return The highest level data type for the given data type.
	 */
	public static DataType getBaseDataType(DataType dataType) {
		return getBaseDataType(dataType, false);
	}

	/**
	 * A recursive function to get the base highest level data type for the given data type.  For
	 * example, if the give data type is an {@link Array}, then this
	 * method will be called again on its data type.
	 * <p>
	 * It is not always appropriate to find the base data type. This method contains the
	 * logic for determining when it is appropriate the seek out the
	 * base data type, as in the case of an Array object.
	 *
	 * @param dataType The data type for which to find the highest level data type
	 * @param includeTypedefs if true, then Typedef data types will be replaced with their base
	 *        data type
	 * @return The highest level data type for the given data type
	 * @see #getBaseDataType(DataType)
	 */
	public static DataType getBaseDataType(DataType dataType, boolean includeTypedefs) {
		if (dataType instanceof Array) {
			return getBaseDataType(((Array) dataType).getDataType(), includeTypedefs);
		}
		else if (dataType instanceof Pointer) {
			DataType baseDataType = ((Pointer) dataType).getDataType();
			if (baseDataType != null) {
				return getBaseDataType(baseDataType, includeTypedefs);
			}
		}
		else if (includeTypedefs && dataType instanceof TypeDef) {
			DataType baseDataType = ((TypeDef) dataType).getBaseDataType();
			return getBaseDataType(baseDataType, includeTypedefs);
		}
		return dataType;
	}

	/**
	 * Gets all variables for the given function including all parameters and local variables.
	 * @param function The function from which to get the variables
	 * @param localsOnly true signals to return only local variables (not parameters); false
	 *        will return parameters and local variables
	 * @return A list of Variable objects.
	 * @throws NullPointerException if the function is null.
	 */
	public static List<Variable> getVariables(Function function, boolean localsOnly) {
		if (function == null) {
			throw new NullPointerException("Function may not be null.");
		}

		List<Variable> list = new ArrayList<>();
		if (localsOnly) {
			list.addAll(Arrays.asList(function.getLocalVariables()));
		}
		else {
			list.addAll(Arrays.asList(function.getAllVariables()));
		}

		return list;
	}

	/**
	 * Creates a LocationDescriptor for the given location
	 *
	 * @param location The program location for which to get a descriptor
	 * @return a LocationDescriptor for the given location
	 */
	public static LocationDescriptor getLocationDescriptor(ProgramLocation location) {

		try {
			return getLocationDescriptorWhileWatchingForExplosiveNavigationCondition(location);
		}
		catch (Exception e) {
			Msg.debug(ReferenceUtils.class,
				"Unexpected exception getting descriptor for location: " + location, e);
			return null; // TODO: remove this block and rename the method it calls for 4642
		}
	}

	/**
	 * HACK: We are watching for a condition where the goto service can send out goto locations
	 * that are not correct for a program, but can still be handled by that program.
	 * <p>
	 * As an example, the goto service may be trying to handle a
	 * FunctionSignatureFieldLocation.  Further, let's
	 * say that the address for that location is 100.  Now suppose that program 'foo' has an
	 * address '100', but does not have a function at that location.  'foo' will decide  to
	 * handle the location event regardless.  In this scenario, where a program handles a location
	 * that is not correct (a function location where there is no function), the
	 * LocationDescriptor objects will not work and will throw exceptions.
	 *
	 * see SCR 4642
	 */
	private static LocationDescriptor getLocationDescriptorWhileWatchingForExplosiveNavigationCondition(
			ProgramLocation location) {

		Program program = location.getProgram();
		if (location instanceof FunctionSignatureFieldLocation) {
			LocationDescriptor result = createFunctionSignatureFieldLocationDescriptor(
				(FunctionSignatureFieldLocation) location);
			return result;
		}
		else if (location instanceof MnemonicFieldLocation) {
			return createMnemonicLocationDescriptor((MnemonicFieldLocation) location);
		}
		else if (location instanceof OperandFieldLocation) {
			return createOperandLocationDescriptor((OperandFieldLocation) location);
		}
		else if (location instanceof LabelFieldLocation) {
			return new LabelLocationDescriptor(location, program);
		}
		else if (location instanceof XRefFieldLocation) {
			return createXRefLocationDescriptor(location);
		}
		else if (location instanceof VariableXRefFieldLocation) {
			return createVariableXRefLocationDescriptor(location);
		}
		else if (location instanceof VariableNameFieldLocation) {
			return new VariableNameLocationDescriptor((VariableNameFieldLocation) location,
				program);
		}
		else if (location instanceof VariableTypeFieldLocation) {
			return new VariableTypeLocationDescriptor(location, program);
		}
		else if (location instanceof AddressFieldLocation) {
			return new AddressLocationDescriptor(location, program);
		}
		else if (location instanceof GenericCompositeDataTypeProgramLocation) {
			// Note: this 'if' must be before the one below for 'GenericDataTypeProgramLocation',
			//       as that one is more generic
			GenericCompositeDataTypeProgramLocation dataTypeLocation =
				(GenericCompositeDataTypeProgramLocation) location;
			return new GenericCompositeDataTypeLocationDescriptor(dataTypeLocation, program);
		}
		else if (location instanceof GenericDataTypeProgramLocation) {
			GenericDataTypeProgramLocation dataTypeLocation =
				(GenericDataTypeProgramLocation) location;
			DataType dataType = dataTypeLocation.getDataType();

			if (dataType instanceof FunctionDefinition) {
				FunctionDefinition functionDefinition = (FunctionDefinition) dataType;
				return new FunctionDefinitionLocationDescriptor(location, program,
					functionDefinition);
			}
			return new GenericDataTypeLocationDescriptor(location, program, dataType);
		}
		else if (location instanceof FieldNameFieldLocation) {
			FieldNameFieldLocation fieldLocation = (FieldNameFieldLocation) location;
			LocationDescriptor dataMemberDescriptor =
				createDataMemberLocationDescriptor(fieldLocation);
			return dataMemberDescriptor;
		}
		// keep this last because some of the above locations extend CodeUnitLocation
		else if (location instanceof CodeUnitLocation) {
			return new AddressLocationDescriptor(location, program);
		}

		return null;
	}

	private static LocationDescriptor createVariableXRefLocationDescriptor(
			ProgramLocation location) {
		if (location instanceof VariableXRefHeaderFieldLocation) {
			return null;
		}
		return new VariableXRefLocationDescriptor(location, location.getProgram());
	}

	private static LocationDescriptor createXRefLocationDescriptor(ProgramLocation location) {
		if (location instanceof XRefHeaderFieldLocation) {
			return null;
		}

		return new XRefLocationDescriptor(location, location.getProgram());
	}

	private static LocationDescriptor createFunctionSignatureFieldLocationDescriptor(
			FunctionSignatureFieldLocation location) {

		Program program = location.getProgram();
		if (location instanceof FunctionReturnTypeFieldLocation) {
			return new FunctionReturnTypeLocationDescriptor(location, program);
		}
		else if (location instanceof FunctionParameterFieldLocation) {
			if (location instanceof FunctionParameterNameFieldLocation) {
				return new FunctionParameterNameLocationDescriptor(location, program);
			}
			return new FunctionParameterTypeLocationDescriptor(location, program);
		}

		return new FunctionSignatureFieldLocationDescriptor(location, program);
	}

	private static LocationDescriptor createMnemonicLocationDescriptor(
			MnemonicFieldLocation location) {

		Program program = location.getProgram();
		Data data = getDataContainingAddress(program, location.getAddress());
		if (data == null) {
			return createInstructionLocationDescriptor(location);
		}

		if (!data.isDefined()) {
			return null;
		}

		return new MnemonicLocationDescriptor(location, program);
	}

	private static Data getDataContainingAddress(Program program, Address address) {
		Listing listing = program.getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(address);

		if (codeUnit == null) {
			codeUnit = listing.getCodeUnitContaining(address);
		}

		if (!(codeUnit instanceof Data)) {
			return null;
		}

		return (Data) codeUnit;
	}

	private static LocationDescriptor createInstructionLocationDescriptor(
			MnemonicFieldLocation location) {

		Program program = location.getProgram();
		Listing listing = program.getListing();
		Instruction instruction = listing.getInstructionAt(location.getAddress());
		if (instruction == null) {
			return null; // not sure if this can happens
		}

		AddressFieldLocation addressLocation =
			new AddressFieldLocation(program, location.getAddress());
		return new AddressLocationDescriptor(addressLocation, program);
	}

	/*
	 * Creates a location descriptor from a field location 
	 * (which has more info than just an address).  A
	 * {@link FieldNameFieldLocation} can be tied to a {@link Composite} field or it can
	 * be an array index subscript.
	 */
	private static LocationDescriptor createDataMemberLocationDescriptor(
			FieldNameFieldLocation location) {

		Address address = location.getAddress();
		Program program = location.getProgram();
		Data outermostData = getDataContainingAddress(program, address);
		if (outermostData == null) {
			return null;
		}

		Data subData = outermostData.getComponent(location.getComponentPath());
		LocationDescriptor descriptor =
			createSubDataMemberLocationDescriptor(program, address, location, subData);
		return descriptor;
	}

	// Sub-data locations are within other types, like Composites or Arrays
	private static LocationDescriptor createSubDataMemberLocationDescriptor(Program program,
			Address address, FieldNameFieldLocation location, Data subData) {

		Data parent = subData.getParent();
		DataType type = parent.getDataType();

		// Check for Union first, as it is a more specialized Composite, in terms of how we
		// find its references
		if (type instanceof Union) {
			return new UnionLocationDescriptor(location, program);
		}

		if (type instanceof Composite) {
			String fieldName = location.getFieldName();
			return new StructureMemberLocationDescriptor(location, fieldName, program);
		}

		if (type instanceof DynamicDataType) {
			//
			// Note:  For now, have dynamic data types work like the Address descriptors, as
			//        that is reasonable behavior.   If we find that the decompiler will treat
			//        dynamic types the same way as Composite types, then we can create a new
			//        descriptor type for the dynamic type that behaves the same way as the
			//        StructureMemberLocationDescriptor.  This would allow us to get any
			//        references to dynamic data types as found by the Decompiler.
			//
			AddressFieldLocation addressLocation =
				new AddressFieldLocation(program, address, location.getComponentPath(), "", 0);
			return new AddressLocationDescriptor(addressLocation, program);
		}

		if (type instanceof Array) {

			AddressFieldLocation addressLocation = new AddressFieldLocation(program, address);
			AddressLocationDescriptor descriptor =
				new AddressLocationDescriptor(addressLocation, program);
			return descriptor;
		}

		return null;
	}

	/*
	 * Creates a location descriptor from just an address (which has less info than an 
	 * actual location)  A {@link FieldNameFieldLocation} can be tied to 
	 * a {@link Composite} field or it can be an array index subscript.
	 *
	 * Since this method is handed only an address and not a ProgramLocation, we have to do
	 * some digging to see what is buried at the given address.
	 */
	private static LocationDescriptor createDataMemberLocationDescriptor(
			OperandFieldLocation location, Address refAddress) {

		// TODO we don't support data types on external addresses; this could change in the future
		if (refAddress.isExternalAddress()) {
			return null;
		}

		Program program = location.getProgram();
		Data outermostData = getDataContainingAddress(program, refAddress);
		if (outermostData == null) {
			// no data
			return null;
		}

		String fieldPath = getFieldPath(location);
		if (!fieldPath.contains(".")) {

			// no field reference, so don't create a structure member reference, but just 
			// a generic data type reference
			DataType type = outermostData.getDataType();
			if (type == DataType.DEFAULT || Undefined.isUndefined(type)) {
				// nobody wants to search for undefined usage; too many (this is the case 
				// where the user is not on an actual data type)
				return null;
			}

			LocationDescriptor dtDescriptor =
				createGenericDataTypeLocationDescriptor(program, type, fieldPath);
			return dtDescriptor;
		}

		String fieldName = getFieldName(location);
		Address parentAddress = outermostData.getMinAddress();
		Data subData = outermostData.getComponentAt((int) refAddress.subtract(parentAddress));
		if (subData != null) {

			int[] componentPath = subData.getComponentPath();
			FieldNameFieldLocation fieldLocation =
				new FieldNameFieldLocation(program, refAddress, componentPath, fieldName, 0);
			LocationDescriptor descriptor =
				createSubDataMemberLocationDescriptor(program, refAddress, fieldLocation, subData);
			return descriptor;
		}

		//
		// No sub-data.  See if we know how to handle the containing data.
		//
		DataType dt = outermostData.getDataType();
		if (dt instanceof Union) {
			AddressFieldLocation addressLocation = new AddressFieldLocation(program, refAddress,
				new int[] { 0 }, refAddress.toString(), 0);
			return new UnionLocationDescriptor(addressLocation, program);
		}

		return null;
	}

	/*
	 * Creates a location descriptor using the String display markup and type information 
	 * found inside of the VariableOffset object.
	 * 
	 * This method differs from createDataMemberLocationDescriptor() in that this method
	 * will create locations that represent DataTypes that are not applied in memory.
	 */
	private static LocationDescriptor createGenericDataTypeLocationDescriptor(Program program,
			VariableOffset variableOffset) {

		if (variableOffset == null) {
			return null;
		}

		Variable variable = variableOffset.getVariable();
		DataType type = variable.getDataType();
		String string = variableOffset.getDataTypeDisplayText();
		GenericDataTypeLocationDescriptor descriptor =
			createGenericDataTypeLocationDescriptor(program, type, string);
		return descriptor;
	}

	private static GenericDataTypeLocationDescriptor createGenericDataTypeLocationDescriptor(
			Program program, DataType type, String fieldPath) {

		//
		// Ugh.  We must figure out what data type (and maybe field) is being referenced.
		//
		if (fieldPath.contains("->")) {
			// convert pointer to object notation
			fieldPath = fieldPath.replace("->", ".");
		}

		DataType baseType = getBaseDataType(type);

		String[] parts = fieldPath.split("\\.");
		if (parts.length == 1) {
			// have a single variable, no data member
			GenericDataTypeProgramLocation location =
				new GenericDataTypeProgramLocation(program, baseType);
			return new GenericDataTypeLocationDescriptor(location, program, baseType);
		}

		if (!(baseType instanceof Composite)) {
			// not sure if this can happen
			return null;
		}

		Composite composite = (Composite) baseType;
		if (parts.length == 2) {
			// must have a type with a field name
			GenericCompositeDataTypeProgramLocation location =
				new GenericCompositeDataTypeProgramLocation(program, composite, parts[1]);
			return new GenericCompositeDataTypeLocationDescriptor(location, program);
		}

		//
		// Parse the type info.  In the example below, the user will be searching for the 'baz'
		// field inside of the 'bar' composite type.  We need to find the type of 'bar'.
		//
		// examples: foo.bar.baz
		// 
		Stack<String> path = new Stack<>();
		for (int i = parts.length - 1; i >= 0; i--) {
			path.push(parts[i]);
		}

		// stack is now: baz, foo, bar
		String fieldName = path.remove(0); // pull off the first name; it is the field we seek
		path.pop();     // pop the last item; we already know the type

		DataType dataType = findLeafDataType(baseType, path);
		composite = (Composite) dataType;
		GenericCompositeDataTypeProgramLocation location =
			new GenericCompositeDataTypeProgramLocation(program, composite, fieldName);
		return new GenericCompositeDataTypeLocationDescriptor(location, program);
	}

	/**
	 * Gets the data that is contains the given address.
	 * This is in contrast to {@link Listing#getDataContaining(Address)}, which returns
	 * the outer-most data for an address.
	 *
	 * @param addr the address potentially contained by some data
	 * @param program the program
	 * @return the data containing the address; null if no data contains the address
	 */
	private static Data getDeepestDataContaining(Address addr, Program program) {
		Listing listing = program.getListing();
		Data dataContaining = listing.getDataContaining(addr);
		Address start = dataContaining.getAddress();
		long depth = addr.subtract(start);
		Data primitiveAtAddr = dataContaining.getPrimitiveAt((int) depth);
		return primitiveAtAddr;
	}

	private static Data getDataAt(ProgramLocation location) {

		Program p = location.getProgram();
		Listing l = p.getListing();
		Data dataContaining = l.getDataContaining(location.getAddress());
		Data data = dataContaining.getComponent(location.getComponentPath());
		return data;
	}

	/*
	 * Finds the data type represented by the lowest-level value in the stack.  This is done
	 * by using the given parent and the item on the top of the stack to find a matching 
	 * field (the parent must be a Composite).
	 */
	private static DataType findLeafDataType(DataType parent, Stack<String> path) {

		DataType baseParent = getBaseDataType(parent, true);
		if (path.isEmpty()) {
			return baseParent; // this must be the one
		}

		if (!(baseParent instanceof Composite)) {
			return null;
		}

		Composite composite = (Composite) baseParent;
		DataTypeComponent[] components = composite.getDefinedComponents();
		String name = path.pop();
		for (DataTypeComponent component : components) {
			if (component.getFieldName().equals(name)) {
				// found match--keep looking
				DataType newParent = component.getDataType();
				return findLeafDataType(newParent, path);
			}
		}

		return null;
	}

	private static LocationDescriptor createOperandLocationDescriptor(
			OperandFieldLocation location) {

		Address refAddress = getReferenceAddress(location);
		if (refAddress == null) {
			return null; // no reference and no variable-offset
		}

		Address operandAddress = location.getAddress();
		int operandIndex = location.getOperandIndex();
		Program program = location.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference reference =
			referenceManager.getReference(operandAddress, refAddress, operandIndex);

		if (reference == null) {

			// Prefer using the reference, for consistency.  Without that, the 
			// VariableOffset object contains markup and type information we can use.
			// Having a VariableOffset without a reference occurs when a
			// register variable reference is inferred during instruction operand formatting.
			VariableOffset variableOffset = location.getVariableOffset();
			return createGenericDataTypeLocationDescriptor(program, variableOffset);
		}

		// note: not sure why we are ignoring external references.  It seems like that is
		//       a thing you may want to find refs to.  If you figure it out, update this
		//       comment.
		// if (reference.isExternalReference()) {
		//	  return null;
		// }

		//
		// Using the reference, we can heck for the 'Extended Markup' style reference, such as:
		// 		instruction ...=>Foo.bar.baz
		//                     -------------
		// Note: these references are to labels (not sure why the reference isn't to a data 
		//       symbol)
		//

		// check to see if the reference is to a structure member...
		LocationDescriptor dataMemberDescriptor =
			createDataMemberLocationDescriptor(location, refAddress);
		if (dataMemberDescriptor != null) {
			return dataMemberDescriptor;
		}

		// ...how about a function member (variable/param)?
		LocationDescriptor functionMemberDescriptor =
			createFunctionMemberLocationDescriptor(location, reference, operandAddress);
		if (functionMemberDescriptor != null) {
			return functionMemberDescriptor;
		}

		return new OperandLocationDescriptor(location, program);
	}

	private static Address getReferenceAddress(OperandFieldLocation location) {
		Address refAddress = location.getRefAddress();
		if (refAddress != null) {
			return refAddress;
		}

		VariableOffset variableOffset = location.getVariableOffset();
		if (variableOffset == null) {
			return null;
		}

		Variable variable = variableOffset.getVariable();
		refAddress = variable.getMinAddress();
		return refAddress;
	}

	private static String getFieldPath(OperandFieldLocation location) {
		// Sigh.  At this point all we have is a representation String.  What we really need
		// from the OperandLocation is an object that knows more information about where the
		// operand is pointing.  This would make it easier to avoid parsing the display text
		// to try and find structure members.
		String rep = location.getOperandRepresentation();

		// normalize on dots so that follow-on processing is easier
		String path = rep.replace("->", ".");
		return path;
	}

	private static String getFieldName(OperandFieldLocation location) {
		// Sigh.  At this point all we have is a representation String.  What we really need
		// from the OperandLocation is an object that knows more information about where the
		// operand is pointing.  This would make it easier to avoid parsing the display text
		// to try and find structure members.
		String rep = location.getOperandRepresentation();
		String fieldName = rep;
		if (fieldName.contains(".")) {
			String[] path = fieldName.split("\\.");
			fieldName = path[path.length - 1];
		}

		return fieldName;
	}

	private static LocationDescriptor createFunctionMemberLocationDescriptor(
			OperandFieldLocation location, Reference reference, Address operandAddress) {

		Program program = location.getProgram();
		if (reference.isStackReference() || reference.isRegisterReference()) {
			ReferenceManager referenceManager = program.getReferenceManager();
			Variable referencedVariable = referenceManager.getReferencedVariable(reference);
			if (referencedVariable == null) {
				// a reference with no actual variable on the other side
				return null;
			}

			return new VariableNameLocationDescriptor(new VariableNameFieldLocation(
				referencedVariable.getProgram(), referencedVariable, 0), location, program);
		}
		return null;
	}

	/**
	 * Searches defined data for types that match, according to the given predicate.
	 * 
	 * @param accumulator the results accumulator
	 * @param program the program
	 * @param dataMatcher the predicate that determines a successful match
	 * @param fieldName the optional field name for which to search
	 * @param monitor the task monitor used to track progress and cancel the work
	 * @throws CancelledException if the operation was cancelled 
	 */
	public static void findDataTypeMatchesInDefinedData(Accumulator<LocationReference> accumulator,
			Program program, Predicate<Data> dataMatcher, String fieldName, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = program.getListing();
		DataIterator dataIter = listing.getDefinedData(true);
		while (dataIter.hasNext() && !monitor.isCancelled()) {
			monitor.checkCanceled();

			Data data = dataIter.next();
			getMatchingDataTypesReferencesFromDataAndSubData(accumulator, data, fieldName,
				dataMatcher, monitor);

			monitor.incrementProgress(1);
		}
	}

	private static LocationReference createReferenceFromDefinedData(Data data, String fieldName) {
		Address dataAddress = data.getMinAddress();
		if (fieldName == null) {
			// no field--include the hit
			return new LocationReference(dataAddress, data.getPathName());
		}

		DataTypeComponent component = getDataTypeComponent(data, fieldName);
		if (component == null) {
			// this implies the given data does not contain our field--do not include the hit
			return null;
		}

		// Note: just check the current type; we may have to unroll it, looking for pointers
		//       along the way if this is not sufficient
		DataType dt = data.getDataType();
		if (dt instanceof Pointer) {
			// For defined data, do not include pointer types when we have a field name.  A
			// pointer to the base composite type is not a direct usage of the given field.
			return null;
		}

		Address componentAddress;
		try {
			componentAddress = dataAddress.addNoWrap(component.getOffset());
			return new LocationReference(componentAddress, data.getPathName() + "." + fieldName);
		}
		catch (AddressOverflowException e) {
			// shouldn't happen
			Msg.error(ReferenceUtils.class, "Unable to create address for sub-component of " +
				data.getPathName() + " at " + dataAddress, e);
		}
		return null;
	}

	private static DataTypeComponent getDataTypeComponent(Data data, String fieldName) {
		DataType dt = getBaseDataType(data.getDataType());
		if (!(dt instanceof Composite)) {
			Msg.debug(ReferenceUtils.class,
				"Somehow searched for a field name on a Data Type that is not a Composite");
			return null;
		}

		Composite c = (Composite) dt;
		DataTypeComponent[] components = c.getDefinedComponents();
		for (DataTypeComponent component : components) {
			if (SystemUtilities.isEqual(component.getFieldName(), fieldName)) {
				return component;
			}
		}

		// Note: sometimes this happens if the user searches on an array element field, which
		//       exists only in the Listing markup
		return null;
	}

	private static void getMatchingDataTypesReferencesFromDataAndSubData(
			Accumulator<LocationReference> accumulator, Data data, String fieldName,
			Predicate<Data> dataMatcher, TaskMonitor monitor) throws CancelledException {

		if (dataMatcher.test(data)) {
			getMatchingDataTypesReferencesFromData(accumulator, data, fieldName, monitor);
		}

		// We know that arrays are all the same element; we decided to just mark the beginning.
		// This will provide an immense speed-up for large arrays (like 10s-100s of thousands
		// of array elements).
		if (data.getBaseDataType() instanceof Array) {
			return;
		}

		int numComponents = data.getNumComponents();
		for (int i = 0; i < numComponents; i++) {
			monitor.checkCanceled();

			Data subData = data.getComponent(i);
			getMatchingDataTypesReferencesFromDataAndSubData(accumulator, subData, fieldName,
				dataMatcher, monitor);
		}
	}

	private static void getMatchingDataTypesReferencesFromData(
			Accumulator<LocationReference> accumulator, Data data, String fieldName,
			TaskMonitor monitor) throws CancelledException {

		LocationReference ref = createReferenceFromDefinedData(data, fieldName);
		if (ref == null) {
			return;
		}

		if (!accumulator.contains(ref)) {
			accumulator.add(ref);
		}

		// this address will either be the data, or the field's, if it exists
		Address dataAddress = ref.getLocationOfUse();
		Consumer<LocationReference> consumer =
			locationReference -> accumulator.add(locationReference);
		Program program = data.getProgram();
		accumulateDirectReferences(consumer, program, dataAddress);

		Consumer<Reference> referenceConsumer = reference -> {
			Address toAddress = reference.getToAddress();
			if (fieldName == null) {
				accumulator.add(new LocationReference(reference, isOffcut(program, toAddress)));
				return;
			}

			// only add the reference if it is directly to the field
			if (toAddress.equals(dataAddress)) {
				accumulator.add(new LocationReference(reference, false));
			}
		};
		accumulateOffcutReferences(referenceConsumer, data, monitor);
	}

	private static void findDataTypeMatchesInFunctionHeaders(
			Accumulator<LocationReference> accumulator, FunctionIterator iterator,
			DataType locationDataType, boolean localsOnly, TaskMonitor monitor)
			throws CancelledException {

		//
		// Historical Note: we used to check all parts of the function (like return type and
		//                  params.  However, that is now handled by the data type finder service.
		//                  So, get the parts that the service does not, which is the local
		//                  variables.
		//

		while (iterator.hasNext()) {
			monitor.checkCanceled();

			Function function = iterator.next();
			Address entryPoint = function.getEntryPoint();
			Program program = function.getProgram();

			DataType returnType = function.getReturnType();
			if (!localsOnly && dataTypesMatch(locationDataType, returnType)) {
				accumulator.add(new LocationReference(entryPoint));
			}

			List<Variable> variables = getVariables(function, localsOnly);
			for (Variable variable : variables) {
				DataType variableDataType = getBaseDataType(variable.getDataType());
				if (dataTypesMatch(locationDataType, variableDataType)) {

					ProgramLocation location =
						new VariableTypeFieldLocation(program, entryPoint, variable, 0);
					location = new VariableTypeFieldLocation(program, entryPoint, variable, 0);
					String context = variable.toString();
					accumulator.add(new LocationReference(entryPoint, context, location));
				}
			}

			monitor.incrementProgress(1);
		}
	}

	private static String emboldenBracketedText(String context) {
		String updated = fixBreakingSpaces(context);
		updated = updated.replaceFirst(CONTEXT_CALLOUT_START_REGEX, EMBOLDEN_START);
		updated = updated.replaceFirst(CONTEXT_CALLOUT_END_REGEX, EMBOLDEN_END);
		return "<html>" + updated;
	}

	private static String fixBreakingSpaces(String s) {
		String updated = s.replaceAll("\\s", "&nbsp;");
		return updated;
	}

	private static boolean dataTypesMatch(DataType searchType, DataType possibleType) {

		if (isBuiltIn(searchType)) {
			Class<? extends DataType> clazz = searchType.getClass();
			return clazz.equals(possibleType.getClass());
		}

		UniversalID uid1 = searchType.getUniversalID();
		UniversalID uid2 = possibleType.getUniversalID();
		boolean equal = SystemUtilities.isEqual(uid1, uid2);
		return equal;
	}

	private static boolean isBuiltIn(DataType dt) {
		SourceArchive sourceArchive = dt.getSourceArchive();
		if (sourceArchive == null) {
			// must be the program archive
			return false;
		}

		if (DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID.equals(
			sourceArchive.getSourceArchiveID())) {
			return true;
		}
		return false;
	}

	/**
	 * Returns all references to the given variable
	 * 
	 * @param accumulator the results accumulator
	 * @param program the program
	 * @param variable the variable
	 */
	public static void getVariableReferences(Accumulator<LocationReference> accumulator,
			Program program, Variable variable) {

		Address variableAddress = variable.getMinAddress();
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference[] variableRefsTo = referenceManager.getReferencesTo(variable);
		for (Reference ref : variableRefsTo) {
			accumulator.add(
				new LocationReference(ref, !ref.getToAddress().equals(variableAddress)));
		}
	}

	private static void accumulateOffcutReferenceAddresses(Accumulator<Address> accumulator,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		Consumer<Reference> consumer = ref -> accumulator.add(ref.getFromAddress());
		accumulateOffcutReferences(consumer, location, monitor);
	}

	private static void accumulateOffcutReferencesToCodeUnitAt(
			Accumulator<LocationReference> accumulator, ProgramLocation location,
			TaskMonitor monitor) throws CancelledException {

		Program program = location.getProgram();
		Consumer<Reference> consumer = ref -> {
			boolean isOffcut = isOffcut(program, ref.getToAddress());
			accumulator.add(new LocationReference(ref, isOffcut));
		};
		accumulateOffcutReferences(consumer, location, monitor);
	}

	private static void accumulateOffcutReferences(Consumer<Reference> consumer,
			ProgramLocation location, TaskMonitor monitor) throws CancelledException {

		Program program = location.getProgram();
		Listing l = program.getListing();
		CodeUnit cu = l.getCodeUnitContaining(location.getAddress());
		if (cu == null || cu.getLength() <= 1) {
			return;
		}

		if (cu instanceof Data) {
			Data data = getDataAt(location);
			if (data != null) {
				cu = data;
			}
		}

		accumulateOffcutReferences(consumer, cu, monitor);
	}

	private static void accumulateOffcutReferences(Consumer<Reference> consumer, CodeUnit cu,
			TaskMonitor monitor) throws CancelledException {

		Program program = cu.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();

		if (cu.getLength() == 1) {
			// a length of 1 cannot have offcut refs
			return;
		}

		AddressSet offcut = new AddressSet(cu.getMinAddress().add(1), cu.getMaxAddress());
		AddressIterator addresses = referenceManager.getReferenceDestinationIterator(offcut, true);
		Address codeUnitAddress = cu.getAddress();
		while (addresses.hasNext()) {
			monitor.checkCanceled();

			Address addr = addresses.next();
			if (addr.equals(codeUnitAddress)) {
				// Assumption: the client has already retrieved references to the given address
				continue;
			}

			ReferenceIterator refs = referenceManager.getReferencesTo(addr);
			while (refs.hasNext()) {
				Reference ref = refs.next();
				consumer.accept(ref);
			}
		}
	}

	private static void accumulateDirectReferences(Consumer<LocationReference> consumer,
			Program program, Address address) {

		boolean isOffcut = isOffcut(program, address);
		ReferenceIterator iter = program.getReferenceManager().getReferencesTo(address);
		while (iter.hasNext()) {
			Reference ref = iter.next();
			consumer.accept(new LocationReference(ref, isOffcut));
		}
	}

	private static void accumulateThunkReferenceAddresses(Accumulator<Address> accumulator,
			Program program, Address address, TaskMonitor monitor) throws CancelledException {

		Consumer<LocationReference> consumer = ref -> accumulator.add(ref.getLocationOfUse());
		accumulateThunkReferences(consumer, program, address, monitor);
	}

	private static void accumulateThunkReferences(Accumulator<LocationReference> accumulator,
			Program program, Address address, TaskMonitor monitor) throws CancelledException {

		Consumer<LocationReference> consumer = ref -> accumulator.add(ref);
		accumulateThunkReferences(consumer, program, address, monitor);
	}

	private static void accumulateThunkReferences(Consumer<LocationReference> consumer,
			Program program, Address address, TaskMonitor monitor) throws CancelledException {

		Function func = program.getFunctionManager().getFunctionAt(address);
		if (func == null) {
			return;
		}

		Address[] thunkAddrs = func.getFunctionThunkAddresses();
		if (thunkAddrs == null) {
			return;
		}

		for (Address thunkAddr : thunkAddrs) {
			monitor.checkCanceled();

			Reference ref = new ThunkReference(thunkAddr, func.getEntryPoint());
			consumer.accept(new LocationReference(ref, false));
		}
	}
}
