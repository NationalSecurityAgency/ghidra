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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mdemangler.*;
import mdemangler.object.MDObjectCPP;

/**
 * This class is for developer research into various areas.  Anything in this class that needs to
 * end up as part of any usable output should be moved into another class.  This class just
 * aggregates various items being investigated, and will eventually be eliminated from the code
 * base.
 */
public class PdbResearch {

	//==============================================================================================
	private static Set<Integer> debugIndexNumbers;
	private static Set<Integer> developerDebugOrderIndexNumbers;

	//==============================================================================================
	// This method exists so we can place breakpoints on call locations to it wherever we
	// would like to break during debugging.
	private static void doNothingSetBreakPointHere() {
		// Do nothing.
	}

	/**
	 * This method is used to populate debugIndexNumbers set that gets used by
	 * {@link #checkBreak(int recordNumber)} in which we set a breakpoint on
	 * {@code #doNothingSetBreakPointHere();} to then allow us to debug into other code.
	 */
	static void initBreakPointRecordNumbers() {
		debugIndexNumbers = new TreeSet<>();

		debugIndexNumbers.add(9715);

//		debugIndexNumbers.add(9696);
//		debugIndexNumbers.add(9700);
//		debugIndexNumbers.add(9709);
//		debugIndexNumbers.add(9783);
//		debugIndexNumbers.add(216012);
//		debugIndexNumbers.add(216055);
//		debugIndexNumbers.add(216058);

//		debugIndexNumbers.add(9703);
//		debugIndexNumbers.add(9709);
//		debugIndexNumbers.add(9782);

//		debugIndexNumbers.add(12527);

//		debugIndexNumbers.add(180462);

//		debugIndexNumbers.add(4673); //flex array

//		debugIndexNumbers.add(4469);
//		debugIndexNumbers.add(4470);

//		debugIndexNumbers.add(11843); //chrome
//		debugIndexNumbers.add(12720); //chrome

//		debugIndexNumbers.add(4385);

//		debugIndexNumbers.add(4825);

//		debugIndexNumbers.add(4246);

//		debugIndexNumbers.add(4389);

//		debugIndexNumbers.add(4380);

//		debugIndexNumbers.add(4332);

//		debugIndexNumbers.add(11843);

//		debugIndexNumbers.add(2972763);
//		debugIndexNumbers.add(2972764);
//		debugIndexNumbers.add(2972766);
//		debugIndexNumbers.add(2972769);

//		debugIndexNumbers.add(87810);
//		debugIndexNumbers.add(218584);

//		debugIndexNumbers.add(4126);

//		debugIndexNumbers.add(2960288);

//		// nested classes.
//		debugIndexNumbers.add(7895);
//		debugIndexNumbers.add(7895);
//
//		debugIndexNumbers.add(4549);

		// chrome
//		debugIndexNumbers.add(9696);
//		debugIndexNumbers.add(9697);
//		debugIndexNumbers.add(9699);
//		debugIndexNumbers.add(9700);
//		debugIndexNumbers.add(9701);
//		debugIndexNumbers.add(9708);
//		debugIndexNumbers.add(9709);
//		debugIndexNumbers.add(216056);
//		debugIndexNumbers.add(216012);
//		debugIndexNumbers.add(216013);
//		debugIndexNumbers.add(216016);
//		debugIndexNumbers.add(216058);

//		// chrome: enum fwdref def
//		debugIndexNumbers.add(5809); //field list with enumerate

//		// chrome: enum fwdref def
//		debugIndexNumbers.add(9631);
//		debugIndexNumbers.add(30695);

//		// chrome: last fwdref ummatched
//		debugIndexNumbers.add(216055);

//		// chrome: enum namespace broken
//		debugIndexNumbers.add(17034);

//		// chrome: anon func and function pointer
//		debugIndexNumbers.add(197736);
//		debugIndexNumbers.add(197737);

//		// nt: composite
//		debugIndexNumbers.add(4499);
//		debugIndexNumbers.add(4760);

//		// chrome: anon func
//		debugIndexNumbers.add(6577);

//		// chrome: argument
//		debugIndexNumbers.add(42433);

//		// gray: tagLOCALETAB array
//		debugIndexNumbers.add(4887);

//		// gray: tagPARAMDESCEX and tagVARIANT
//		debugIndexNumbers.add(6033);
//		debugIndexNumbers.add(6037);
//		debugIndexNumbers.add(6039);
//		debugIndexNumbers.add(6075);

//		// gray: _IMAGE_OPTIONAL_HEADER64 and _IMAGE_DATA_DIRECTORY (array)
//		debugIndexNumbers.add(4974);
//		debugIndexNumbers.add(4975);
//		debugIndexNumbers.add(4977);
//		debugIndexNumbers.add(4982);
//		debugIndexNumbers.add(4992);

//		// gray: def before fwdref
//		debugIndexNumbers.add(4859);
//		debugIndexNumbers.add(4876);

//		debugIndexNumbers.add(5367);
//		// ********* NEXT SET **********
//		debugIndexNumbers.add(6660);
//		debugIndexNumbers.add(6835);
//		debugIndexNumbers.add(129037);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(236516);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(117107);
//		debugIndexNumbers.add(117125);

		// ********* NEXT SET **********
		//GRAY
//		debugIndexNumbers.add(4176);
//		debugIndexNumbers.add(4188);
//		debugIndexNumbers.add(4199);
//		debugIndexNumbers.add(4257);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(111583);
//		debugIndexNumbers.add(111585);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(195850);
//		debugIndexNumbers.add(195851);
//		debugIndexNumbers.add(195853);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(11180);
//		debugIndexNumbers.add(192618);
//		debugIndexNumbers.add(192619);
//		debugIndexNumbers.add(192620);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(4111);
//		debugIndexNumbers.add(42432);
//		debugIndexNumbers.add(42433);
//		debugIndexNumbers.add(29156);
//		debugIndexNumbers.add(29157);
//		debugIndexNumbers.add(29194);
//		debugIndexNumbers.add(214780);
//		debugIndexNumbers.add(237308);
//
//		debugIndexNumbers.add(232902);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(5980);
//		debugIndexNumbers.add(6224);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(6331);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(81379);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(251910);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(33617);
//		debugIndexNumbers.add(33621);

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(183821); //fwd ref
//		debugIndexNumbers.add(183828); //def 1
//		debugIndexNumbers.add(214748); //def 2
//		debugIndexNumbers.add(228395); //def 3
//		debugIndexNumbers.add(235802); //def 4

//		// ********* NEXT SET **********
//		debugIndexNumbers.add(4193);
//		debugIndexNumbers.add(4203);
//		debugIndexNumbers.add(4280);

		// ********* NEXT SET **********
//		// big class
//		debugIndexNumbers.add(108379);
//
//		debugIndexNumbers.add(105594); // fwdref is 105430
//
//		debugIndexNumbers.add(105444);

		// ********* NEXT SET **********
//		// big class
//		debugIndexNumbers.add(105212);
//
//		// member 2 (def) of big class (fwdref 105103)
//		debugIndexNumbers.add(105444);
//
//		// member 3 (def) of big class (fwdref 105104)
//		debugIndexNumbers.add(105594);
//
//		// base classes of 105444 (field list 105443)
//		debugIndexNumbers.add(5251); // fwdref is 5072
//		debugIndexNumbers.add(105594); // fwdref is 105430
//
//		// first and only member of 5251
//		debugIndexNumbers.add(5051); // fwdref is 4505

		// ********* NEXT SET **********
//		// big class
//		debugIndexNumbers.add(7624); // fwdref is 7619
//
//		debugIndexNumbers.add(6116); // fwdref is 5956
//
//		debugIndexNumbers.add(6189); // fwdref is 6086
//
//		// base class of 6189
//		debugIndexNumbers.add(6236); // fwdref is 6168
//
//		// member of 6236
//		debugIndexNumbers.add(6251); // fwdref is 6220
//
//		// member of 6251
//		debugIndexNumbers.add(6263); // fwdref is 6237
//
//		// base class / member of 6263
//		debugIndexNumbers.add(6284); // fwdref is 6252
//
//		// base class / member of 6284
//		debugIndexNumbers.add(6328); // fwdref is 6264
//
//		// member of 6328
//		debugIndexNumbers.add(6335); // fwdref is 6285
//
//		// base class of 6335
//		debugIndexNumbers.add(6341); // fwdref is 6329
	}

	/**
	 * Developmental method for breakpoints.  TODO: will delete this from production.
	 * Set breakpoint on {@code #doNothingSetBreakPointHere();}
	 * @param recordNumber the record number that is being processed (set negative to ignore)
	 * <p>
	 * This code is useful for developer debugging because the PDB is records-based and we often
	 * need to set breakpoints elsewhere, determine what RecordNumber we are interested in, and
	 * then use this method to set a breakpoint to catch when the record number is being seen
	 * earlier in the state of processing.  The numbers in {@link #debugIndexNumbers} is set
	 * by {@link #initBreakPointRecordNumbers()}.
	 */
	static void checkBreak(int recordNumber) {
		if (debugIndexNumbers.contains(recordNumber)) {
			doNothingSetBreakPointHere();
		}
	}

	/**
	 * Developmental method for breakpoints.  TODO: will delete this from production.
	 * @param recordNumber the record number tha is being processed (set negative to ignore)
	 * @param applier the applier that might have additional, such as the name of the type of
	 * interest
	 */
	static void checkBreak(int recordNumber, MsTypeApplier applier) {

		String nn = applier.getMsType().getName();
		if ("std::__1::__map_value_compare<std::__1::basic_string<char>,std::__1::__value_type<std::__1::basic_string<char>,std::__1::basic_string<wchar_t> >,std::__1::less<void>,1>".equals(
			nn)) {
			doNothingSetBreakPointHere();
		}
		if ("class std::__1::__iostream_category".equals(nn)) {
			doNothingSetBreakPointHere();
		}
		if ("std::__1::__do_message".equals(nn)) {
			doNothingSetBreakPointHere();
		}

		//checkBreak(recordNumber);
	}

	//==============================================================================================
	//==============================================================================================
	static private void initDeveloperOrderRecordNumbers() {
		developerDebugOrderIndexNumbers = new TreeSet<>();

		developerDebugOrderIndexNumbers.add(9696);
		developerDebugOrderIndexNumbers.add(9697);
		developerDebugOrderIndexNumbers.add(9700);
		developerDebugOrderIndexNumbers.add(9701);
		developerDebugOrderIndexNumbers.add(9704);
		developerDebugOrderIndexNumbers.add(9707);
		developerDebugOrderIndexNumbers.add(9709);
		developerDebugOrderIndexNumbers.add(9714);
		developerDebugOrderIndexNumbers.add(9715);
		developerDebugOrderIndexNumbers.add(9773);
		developerDebugOrderIndexNumbers.add(9774);
		developerDebugOrderIndexNumbers.add(9775);
		developerDebugOrderIndexNumbers.add(9776);
		developerDebugOrderIndexNumbers.add(9777);
		developerDebugOrderIndexNumbers.add(9778);
		developerDebugOrderIndexNumbers.add(9779);
		developerDebugOrderIndexNumbers.add(9780);
		developerDebugOrderIndexNumbers.add(9781);
		developerDebugOrderIndexNumbers.add(9782);
		developerDebugOrderIndexNumbers.add(9783);
		developerDebugOrderIndexNumbers.add(216012);
		developerDebugOrderIndexNumbers.add(216055);
		developerDebugOrderIndexNumbers.add(216058);

//		// big class
//		developerDebugOrderIndexNumbers.add(105212);
//
//		// member 2 (def) of big class (fwdref 105103)
//		developerDebugOrderIndexNumbers.add(105444);
//
//		// member 3 (def) of big class (fwdref 105104)
//		developerDebugOrderIndexNumbers.add(105594);
//
//		// base classes of 105444 (field list 105443)
//		developerDebugOrderIndexNumbers.add(5251); // fwdref is 5072
//		developerDebugOrderIndexNumbers.add(105594); // fwdref is 105430
//
//		// first and only member of 5251
//		developerDebugOrderIndexNumbers.add(5051); // fwdref is 4505
	}

	static void developerDebugOrder(PdbApplicator applicator, TaskMonitor monitor)
			throws CancelledException, PdbException {
		initDeveloperOrderRecordNumbers();
		for (int indexNumber : developerDebugOrderIndexNumbers) {
			monitor.checkCanceled();
			PdbResearch.checkBreak(indexNumber);
			MsTypeApplier applier =
				applicator.getTypeApplier(RecordNumber.typeRecordNumber(indexNumber));
			applier.apply();
		}

	}

	//==============================================================================================
	//==============================================================================================
	static void childWalk(PdbApplicator applicator, TaskMonitor monitor)
			throws CancelledException, PdbException {
		SymbolGroup symbolGroup = applicator.getSymbolGroup();
		GlobalSymbolInformation globalSymbolInformation =
			applicator.getPdb().getDebugInfo().getGlobalSymbolInformation();
		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		applicator.setMonitorMessage("PDB: Applying typedefs...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			if (!childWalkSym(applicator, symbolGroup.getModuleNumber(), iter)) {
				break;
			}
			monitor.incrementProgress(1);
		}
	}

	static private boolean childWalkSym(PdbApplicator applicator, int moduleNumber,
			AbstractMsSymbolIterator iter) throws PdbException, CancelledException {
		if (!iter.hasNext()) {
			return false;
		}
		AbstractMsSymbol symbol = iter.peek(); //temporary during development
		MsSymbolApplier applier = applicator.getSymbolApplier(iter);
		if (applier instanceof TypedefSymbolApplier) {
			TypedefSymbolApplier typedefApplier = (TypedefSymbolApplier) applier;
			MsTypeApplier typeApplier =
				applicator.getTypeApplier(typedefApplier.getTypeRecordNumber());
			System.out.println("UDT " + typedefApplier.getName() + " depends on " +
				typeApplier.getMsType().toString());
//			applier.apply();
//			procSym(symbolGroup);
		}
		else if (applier instanceof ReferenceSymbolApplier) {
			ReferenceSymbolApplier refSymbolApplier = (ReferenceSymbolApplier) applier;
			AbstractMsSymbolIterator refIter =
				refSymbolApplier.getInitializedReferencedSymbolGroupIterator();
			// recursion
			childWalkSym(applicator, refIter.getModuleNumber(), refIter);
		}
		else if (applier instanceof DataSymbolApplier) {
			DataSymbolApplier dataSymbolApplier = (DataSymbolApplier) applier;
			MsTypeApplier typeApplier = dataSymbolApplier.getTypeApplier();
			childWalkType(moduleNumber, typeApplier);
		}
		else if (applier instanceof FunctionSymbolApplier) {
			FunctionSymbolApplier functionSymbolApplier = (FunctionSymbolApplier) applier;
			functionSymbolApplier.getFunction();
//			AbstractMsTypeApplier typeApplier = functionSymbolApplier.getTypeApplier();
//			childWalkType(symbolGroup.getModuleNumber(), typeApplier);
		}
//		else if (applier instanceof ConstanctSymbolApplier) {
//			ConstantSymbolApplier constantSymbolApplier = (ConstantSymbolApplier) applier;
//		}
		else {
			doNothingSetBreakPointHere();
		}
		return true;
	}

	//==============================================================================================
	static private boolean childWalkType(int moduleNumber, MsTypeApplier applier) {
		doNothingSetBreakPointHere();
		if (applier instanceof AbstractFunctionTypeApplier) {
			doNothingSetBreakPointHere();
		}
		return true;
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	static void studyDataTypeConflicts(PdbApplicator applicator, TaskMonitor monitor)
			throws CancelledException {
		DataTypeConflictHandler handler =
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER;
		DataTypeManager dtm = applicator.getDataTypeManager();

		// First set
		Composite testStruct1 = createComposite(dtm, "____blah____");
		Pointer pointer1 = new PointerDataType(testStruct1, -1, dtm);

		FunctionDefinitionDataType fn1 =
			new FunctionDefinitionDataType(CategoryPath.ROOT, "____fn1____", dtm);
		fn1.setReturnType(pointer1);
		fn1.setGenericCallingConvention(GenericCallingConvention.cdecl);
		fn1.setArguments(new ParameterDefinition[0]);

		Composite internalStruct1 = createComposite(dtm, "____internal____");
		Pointer internalPointer1 = new PointerDataType(internalStruct1, -1, dtm);

		fillComposite(testStruct1, monitor, internalPointer1);
		fillComposite(internalStruct1, monitor, null);

		// Second set
		Composite testStruct2 = createComposite(dtm, "____blah____");
		Pointer pointer2 = new PointerDataType(testStruct2, -1, dtm);

		FunctionDefinitionDataType fn2 =
			new FunctionDefinitionDataType(CategoryPath.ROOT, "____fn2____", dtm);
		fn2.setReturnType(pointer2);
		fn2.setGenericCallingConvention(GenericCallingConvention.cdecl);
		fn2.setArguments(new ParameterDefinition[0]);

		Composite internalStruct2 = createComposite(dtm, "____internal____");
		Pointer internalPointer2 = new PointerDataType(internalStruct2, -1, dtm);

		fillComposite(testStruct2, monitor, internalPointer2);
//		fillComposite(internalStruct2, monitor, null);

		// Resolve
		DataType t1 = dtm.resolve(testStruct1, handler);
		DataType f1 = dtm.resolve(fn1, handler);

		DataType t2 = dtm.resolve(testStruct2, handler);
		DataType f2 = dtm.resolve(fn2, handler);

		PdbLog.message(t1.toString());
		PdbLog.message(f1.toString());
		PdbLog.message(t2.toString());
		PdbLog.message(f2.toString());
	}

	private static Composite createComposite(DataTypeManager dtm, String name) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm);
		return composite;
	}

	private static void fillComposite(Composite composite, TaskMonitor monitor, DataType extra)
			throws CancelledException {
		List<DefaultTestPdbMember> members = new ArrayList<>();
		DefaultTestPdbMember member;
		int size = 8;
		DataType intxy = IntegerDataType.dataType;
		member = new DefaultTestPdbMember("x", intxy, 0);
		members.add(member);
		member = new DefaultTestPdbMember("y", intxy, 4);
		members.add(member);
		if (extra != null) {
			member = new DefaultTestPdbMember("z", extra, 8);
			members.add(member);
			size += extra.getLength();
		}
		if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, size, members,
			msg -> reconstructionWarn(msg), monitor)) {
			((Structure) composite).deleteAll();
		}
	}

	private static void reconstructionWarn(String msg) {
		Msg.warn(null, msg);
	}

	private static class DefaultTestPdbMember extends PdbMember {

		private DataType dataType;

		/**
		 * Default PDB member construction
		 * @param name member field name.
		 * @param dataType for the field.
		 * @param offset member's byte offset within the root composite.
		 */
		DefaultTestPdbMember(String name, DataType dataType, int offset) {
			super(name, dataType.getName(), offset, null);
			this.dataType = dataType;
		}

		@Override
		public String getDataTypeName() {
			return dataType.getName();
		}

		@Override
		protected WrappedDataType getDataType() throws CancelledException {
			if (dataType instanceof ArrayDataType) {
				int size = 1; // mocking for now
				if (size == 0) {
					return new WrappedDataType(dataType, true, false);
				}
			}
			return new WrappedDataType(dataType, false, false);
		}

	}

	//==============================================================================================
	//==============================================================================================
	/*
	 * Studying names of functions where they might involve function definition
	 * reuse caused by Templates and/or Identical Code Folding.
	 */
	static void studyAggregateSymbols(PdbApplicator applicator, TaskMonitor monitor)
			throws CancelledException {
		Map<Address, List<Stuff>> mapByAddress = new HashMap<>();
		processPublicSymbols(applicator, mapByAddress, monitor);
		processGlobalSymbols(applicator, mapByAddress, monitor);
		processModuleSymbols(applicator, mapByAddress, monitor);
		dumpMap(mapByAddress);
	}

	private static void processPublicSymbols(PdbApplicator applicator,
			Map<Address, List<Stuff>> map, TaskMonitor monitor) throws CancelledException {
		AbstractPdb pdb = applicator.getPdb();
		SymbolGroup symbolGroup = applicator.getSymbolGroup();

		PublicSymbolInformation publicSymbolInformation =
			pdb.getDebugInfo().getPublicSymbolInformation();
		List<Long> offsets = publicSymbolInformation.getModifiedHashRecordSymbolOffsets();
		applicator.setMonitorMessage(
			"PDB: Applying " + offsets.size() + " public symbol components...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			AbstractMsSymbol symbol = iter.peek();
			//applicator.getPdbApplicatorMetrics().witnessPublicSymbolType(symbol);
			processPublicSymbol(applicator, map, symbol);
			processProcedureSymbol(applicator, map, symbol);
			monitor.incrementProgress(1);
		}
	}

	private static void processGlobalSymbols(PdbApplicator applicator,
			Map<Address, List<Stuff>> map, TaskMonitor monitor) throws CancelledException {
		AbstractPdb pdb = applicator.getPdb();
		SymbolGroup symbolGroup = applicator.getSymbolGroup();

		GlobalSymbolInformation globalSymbolInformation =
			pdb.getDebugInfo().getGlobalSymbolInformation();
		List<Long> offsets = globalSymbolInformation.getModifiedHashRecordSymbolOffsets();
		applicator.setMonitorMessage("PDB: Applying global symbols...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			AbstractMsSymbol symbol = iter.peek();
			//applicator.getPdbApplicatorMetrics().witnessGlobalSymbolType(symbol);
			processPublicSymbol(applicator, map, symbol);
			processProcedureSymbol(applicator, map, symbol);
			monitor.incrementProgress(1);
		}
	}

	private static void processModuleSymbols(PdbApplicator applicator,
			Map<Address, List<Stuff>> map, TaskMonitor monitor) throws CancelledException {
		AbstractPdb pdb = applicator.getPdb();
		int totalCount = 0;
		int num = pdb.getDebugInfo().getNumModules();
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCanceled();
			SymbolGroup symbolGroup = applicator.getSymbolGroupForModule(moduleNumber);
			if (symbolGroup == null) {
				continue;
			}
			totalCount += symbolGroup.size();
		}
		applicator.setMonitorMessage(
			"PDB: Applying " + totalCount + " module symbol components...");
		monitor.initialize(totalCount);

		// Process symbols list for each module
		for (int moduleNumber = 1; moduleNumber <= num; moduleNumber++) {
			monitor.checkCanceled();

//			String moduleName =
//				pdb.getDebugInfo().getModuleInformation(index).getModuleName();

			// Process module symbols list
			SymbolGroup symbolGroup = applicator.getSymbolGroupForModule(moduleNumber);
			if (symbolGroup == null) {
				continue;
			}
			AbstractMsSymbolIterator iter = symbolGroup.iterator();
			processSymbolGroup(applicator, map, moduleNumber, iter, monitor);
			// do not call monitor.incrementProgress(1) here, as it is updated inside of
			//  processSymbolGroup.
		}
	}

	private static void processSymbolGroup(PdbApplicator applicator, Map<Address, List<Stuff>> map,
			int moduleNumber, AbstractMsSymbolIterator iter, TaskMonitor monitor)
			throws CancelledException {
		iter.initGet();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			AbstractMsSymbol symbol = iter.next();
			if (symbol != null) {
				processPublicSymbol(applicator, map, symbol);
				processProcedureSymbol(applicator, map, symbol);
			}
			monitor.incrementProgress(1);
		}
	}

	private static void processPublicSymbol(PdbApplicator applicator, Map<Address, List<Stuff>> map,
			AbstractMsSymbol symbol) {
		Stuff stuff;
		if (!(symbol instanceof AbstractPublicMsSymbol)) {
			return;
		}
		// If it can be known and determined to not be a function, then return.
		if (symbol instanceof AbstractPublic32MsSymbol &&
			!((AbstractPublic32MsSymbol) symbol).isFunction()) {
			return;
		}
		String name = ((AbstractPublicMsSymbol) symbol).getName();
		Address address = applicator.getAddress((AbstractPublicMsSymbol) symbol);
		if (applicator.isInvalidAddress(address, name)) {
			return;
		}
		String demangledName = getDemangledQualifiedName(name);
		if (demangledName != null) {
			stuff = new Stuff(symbol, demangledName, What.PUBLIC_QUAL_FROM_MANGLED);
		}
		else {
			stuff = new Stuff(symbol, name, What.PUBLIC_NOT_MANGLED);
		}
		addStuff(map, address, stuff);
	}

	private static void processProcedureSymbol(PdbApplicator applicator,
			Map<Address, List<Stuff>> map, AbstractMsSymbol symbol) {
		if (symbol instanceof AbstractProcedureMsSymbol) {
			String name = ((AbstractProcedureMsSymbol) symbol).getName();
			Address address = applicator.getAddress((AbstractProcedureMsSymbol) symbol);
			if (applicator.isInvalidAddress(address, name)) {
				return;
			}
			Stuff stuff = new Stuff(symbol, name, What.GLOBAL);
			addStuff(map, address, stuff);
		}
	}

	private static void addStuff(Map<Address, List<Stuff>> map, Address address, Stuff stuff) {
		List<Stuff> list = map.get(address);
		if (list == null) {
			list = new ArrayList<>();
			map.put(address, list);
		}
		list.add(stuff);
	}

	private static void dumpMap(Map<Address, List<Stuff>> map) {
		for (Map.Entry<Address, List<Stuff>> entry : map.entrySet()) {
			Address address = entry.getKey();
			List<Stuff> list = entry.getValue();
			for (Stuff stuff : list) {
				PdbLog.message(address + " " + stuff.getWhat() + " " + stuff.getName());
			}
		}
	}

	/**
	 * Gets a demangles the name and returns the qualified name. Returns null if not mangled
	 * or if error in demangling.
	 * @param mangledString the mangled string to be decoded
	 * @return the qualified name of the demangled string or null if not mangled or error.
	 */
	private static String getDemangledQualifiedName(String mangledString) {
		if (mangledString.charAt(0) != '?') {
			return null;
		}
		MDMangGhidra demangler = new MDMangGhidra();
		try {
			MDParsableItem parsableItem = demangler.demangle(mangledString, true);
			if (parsableItem instanceof MDObjectCPP) {
				MDObjectCPP mdObject = (MDObjectCPP) parsableItem;
				return mdObject.getQualifiedName().toString();
			}
			return parsableItem.toString();
		}
		catch (MDException e) {
			// Couldn't demangle.
			Msg.info(null, e.getMessage());
			return null;
		}
	}

	//----------------------------------------------------------------------------------------------
	private static enum What {
		PUBLIC_NOT_MANGLED, PUBLIC_QUAL_FROM_MANGLED, GLOBAL
	}

	private static class Stuff {
		AbstractMsSymbol symbol;
		String name;
		What what;

		Stuff(AbstractMsSymbol symbol, String name, What what) {
			this.symbol = symbol;
			this.name = name;
			this.what = what;
		}

		AbstractMsSymbol getSymbol() {
			return symbol;
		}

		String getName() {
			return name;
		}

		What getWhat() {
			return what;
		}
	}

	//==============================================================================================
	//==============================================================================================
	static void studyCompositeForwardReferenceAndDefinition(AbstractPdb pdb, TaskMonitor monitor)
			throws CancelledException {
		int indexNumber = pdb.getTypeProgramInterface().getTypeIndexMin();
		int indexLimit = pdb.getTypeProgramInterface().getTypeIndexMaxExclusive();
		int num = indexLimit - indexNumber;
		boolean covered[] = new boolean[indexLimit];

		monitor.initialize(num);
		monitor.setMessage("Study: NAMES_START " + (indexLimit - indexNumber));
		PdbLog.message("STUDY_START: studyCompositeFwdRefDef");
		//System.out.println("STUDY_START");
		while (indexNumber < indexLimit) {
			monitor.checkCanceled();
			if (!covered[indexNumber]) {
				AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(indexNumber));
				covered[indexNumber] = true;
				String name = getSpecialRecordStart(type);
				if (name != null) {
					MsProperty p;
					String ps;
					int c;
					boolean isForwardReference = false;
					Map<Integer, Set<String>> map = new HashMap<>();
					if (type instanceof AbstractCompositeMsType) {
						AbstractCompositeMsType compType = (AbstractCompositeMsType) type;
						c = compType.getNumElements();
						p = compType.getMsProperty();
						isForwardReference = p.isForwardReference();
						if (c == 0 && !isForwardReference) {
							doNothingSetBreakPointHere();
							// For PDBs that we have looked at, if count is zero
							// for a forward reference, then the field list record number is zero;
							// if count is zero for a definition, then, the field list record
							// number refers to an actual field list.
							// So... seems we can trust forward reference and ignore count.
							if (compType.getFieldDescriptorListRecordNumber() == RecordNumber.NO_TYPE) {
								doNothingSetBreakPointHere();
							}
						}
						else if (c != 0 && isForwardReference) {
							doNothingSetBreakPointHere();
						}
//					ps = c + (p.isForwardReference() ? "fwdref" : "");
					}
					else { //type instanceof AbstractEnumMsType
						AbstractEnumMsType enumType = (AbstractEnumMsType) type;
						c = 0; // made up.
//					p = enumType.getMsProperty();
//					ps = p.toString();
					}
					ps = type.toString();
					Set<String> set = new HashSet<>();
					set.add(ps);
					map.put(c, set);
					PdbLog.message(
						"----------\n" + name + "\n" + c + (isForwardReference ? " fwdref" : ""));
					//System.out.println("----------\n" + name + "\n" + c);
					int innerIndexNumber = indexNumber + 1;
					while (innerIndexNumber < indexLimit) {
						monitor.checkCanceled();
						if (!covered[innerIndexNumber]) {
							AbstractMsType innerType =
								pdb.getTypeRecord(RecordNumber.typeRecordNumber(innerIndexNumber));
							String innerName = getSpecialRecordStart(innerType);
							if (name.equals(innerName)) {
								covered[innerIndexNumber] = true;
								isForwardReference = false;
								if (type instanceof AbstractCompositeMsType) {
									AbstractCompositeMsType compType =
										(AbstractCompositeMsType) innerType;
									c = compType.getNumElements();
									p = compType.getMsProperty();
									isForwardReference = p.isForwardReference();
									if (c == 0 && !isForwardReference) {
										// For PDBs that we have looked at, if count is zero
										// for a forward reference, then the field list record
										// number is zero; if count is zero for a definition, then,
										// the field list record number refers to an actual field
										// list. So... seems we can trust forward reference and
										// ignore count.
										if (compType.getFieldDescriptorListRecordNumber() == RecordNumber.NO_TYPE) {
											doNothingSetBreakPointHere();
										}
									}
									else if (c != 0 && isForwardReference) {
										doNothingSetBreakPointHere();
									}
//								ps = c + (p.isForwardReference() ? "fwdref" : "");
								}
								else { //type instanceof AbstractEnumMsType
									AbstractEnumMsType enumType = (AbstractEnumMsType) type;
									c = 0; // made up.
//								p = enumType.getMsProperty();
//								ps = "" + c;
								}
								String psi = innerType.toString();
								set = map.get(c);
								String message = "";
								if (set == null) {
									set = new HashSet<>();
									map.put(c, set);
									set.add(psi);
								}
								else if (!set.contains(psi)) { // conflict
									message = " <-- conflict";
									set.add(psi);
								}
								else {
									message = " <-- repeat";
								}
								PdbLog.message(c + (isForwardReference ? " fwdref" : "") + message);
								if (c == 0 && isForwardReference) {
									PdbLog.message("Orig: " + ps + "\nNew: " + psi);
								}
								//System.out.println(c + message);
							}
						}
						innerIndexNumber++;
					}
				}

			}
			indexNumber++;
			monitor.incrementProgress(1);
		}
		PdbLog.message("STUDY_END: studyCompositeFwdRefDef");
		//System.out.println("STUDY_END");
	}

	private static String getSpecialRecordStart(AbstractMsType type) {
		if (!((type instanceof AbstractCompositeMsType || type instanceof AbstractEnumMsType))) {
			return null;
		}

		String name;
		if (type instanceof AbstractCompositeMsType) {
			AbstractCompositeMsType compType = (AbstractCompositeMsType) type;
			if (compType instanceof AbstractClassMsType) {
				name = "class " + compType.getName();
			}
			else if (compType instanceof AbstractStructureMsType) {
				name = "struct " + compType.getName();
			}
			else if (compType instanceof AbstractUnionMsType) {
				name = "union " + compType.getName();
			}
			else {
				name = "interface " + compType.getName();
			}
		}
		else { //type instanceof AbstractEnumMsType
			AbstractEnumMsType enumType = (AbstractEnumMsType) type;
			name = "enum " + enumType.getName();
		}
		return name;
	}

	//==============================================================================================
	//==============================================================================================
	static void study1(AbstractPdb pdb, TaskMonitor monitor) throws CancelledException {
		int indexNumber = pdb.getTypeProgramInterface().getTypeIndexMin();
		int indexLimit = pdb.getTypeProgramInterface().getTypeIndexMaxExclusive();

		Set<String> uniqueNames = new HashSet<>();
		List<String> orderedNames = new ArrayList<>();
		List<String> orderedRecords = new ArrayList<>();

		monitor.initialize(indexLimit - indexNumber);
		monitor.setMessage("Study: NAMES_START");
		while (indexNumber < indexLimit) {
			monitor.checkCanceled();
			String name;
			String record;
			AbstractMsType type = pdb.getTypeRecord(RecordNumber.typeRecordNumber(indexNumber));
			if (type instanceof AbstractCompositeMsType || type instanceof AbstractEnumMsType) {
				if (type instanceof AbstractCompositeMsType) {
					AbstractCompositeMsType compType = (AbstractCompositeMsType) type;
					if (compType instanceof AbstractClassMsType) {
						name = "class " + compType.getName();
					}
					else if (compType instanceof AbstractStructureMsType) {
						name = "struct " + compType.getName();
					}
					else if (compType instanceof AbstractUnionMsType) {
						name = "union " + compType.getName();
					}
					else {
						name = "interface " + compType.getName();
					}
					record = compType.toString();
				}
				else { //type instanceof AbstractEnumMsType
					AbstractEnumMsType enumType = (AbstractEnumMsType) type;
					name = "enum " + enumType.getName();
					record = enumType.toString();
				}
				if (!uniqueNames.contains(name)) {
					uniqueNames.add(name);
					orderedNames.add(name);
				}
				orderedRecords.add(record);
			}
			indexNumber++;
			monitor.incrementProgress(1);
		}

		System.out.println("DUMP_START");
		monitor.setMessage("Study: DUMP_START");
		monitor.initialize(orderedNames.size());
		for (String name : orderedNames) {
			for (String record : orderedRecords) {
				monitor.checkCanceled();
				if (record.startsWith(name)) {
					System.out.println(record);
				}
			}
			System.out.println("----------");
			monitor.incrementProgress(1);
		}
		System.out.println("DUMP_END");

	}

}
