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
// Developer script to dump certain Program and PDB information for use in testing products.
//
//@category PDB
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.SymbolPathParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.*;
import ghidra.app.util.pdb.classtype.*;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import pdb.PdbPlugin;
import pdb.symbolserver.FindOption;

/**
 * Developer script to capture items from Program and PDB for developing tests
 */
public class CaptureHelperScript extends GhidraScript {

	private AddressFactory addressFactory;
	private Memory memory;
	private Address progMaxAddr;
	private SymbolManager symbolManager;
	private FunctionManager functionManager;
	private DataOrganization dataOrganization;
	private DataConverter dataConverter;
	private int pointerSize;

	private Map<Address, NameAndBytes> vbtInfo;
	private Map<Address, NameAndBytes> vftInfo;
	private Map<Address, NameAndBytes> functionInfo;
	private Map<Address, FunctionSignature> signatureInfo;

	// The following can have extra non-target address since we do not know the real table lenths.
	//  For instance, any table that comes before a vftable could run into the a vftable "meta"
	//  pointer before the vftable symbol.
	private Set<Address> vftTargetAddresses;

	@Override
	public void run() throws Exception {
		if (!init()) {
			return;
		}
		String vbtInfoString = getVbTables();
		String vftInfoString = getVfTables();
		String functionInfoString = getFunctions();
		String signatureInfoString = getSignatures();
		String pdbVirtualMethods = getPdbVirtualMethods();
		print(vbtInfoString);
		print(vftInfoString);
		print(functionInfoString);
		print(signatureInfoString);
		print(pdbVirtualMethods);
	}

	private boolean init() {
		if (currentProgram == null) {
			println("No Program Open");
			return false;
		}
		addressFactory = currentProgram.getAddressFactory();
		memory = currentProgram.getMemory();
		progMaxAddr = memory.getMaxAddress();
		symbolManager = (SymbolManager) currentProgram.getSymbolTable();
		functionManager = currentProgram.getFunctionManager();
		dataOrganization = currentProgram.getDataTypeManager().getDataOrganization();
		dataConverter = DataConverter.getInstance(dataOrganization.isBigEndian());
		pointerSize = dataOrganization.getPointerSize();
		vbtInfo = new TreeMap<>();
		vftInfo = new TreeMap<>();
		functionInfo = new TreeMap<>();
		signatureInfo = new TreeMap<>();
		return true;
	}

	private String getVbTables() {
		getVxTables(vbtInfo, "??_8*");
		return dumpBytes(vbtInfo);
	}

	private String getVfTables() {
		getVxTables(vftInfo, "??_7*");
		return dumpBytes(vftInfo);
	}

	private String getFunctions() {
		vftTargetAddresses = getFunctionAddressesFromVfts(vftInfo);
		for (Address addr : vftTargetAddresses) {
			getFunctionInfo(addr);
		}
		return dumpBytes(functionInfo);
	}

	private void getVxTables(Map<Address, NameAndBytes> info, String pattern) {
		SymbolIterator iter = symbolManager.getSymbolIterator(pattern, true);
		while (iter.hasNext()) {
			Symbol symbol = iter.next();
			Address addr = symbol.getAddress();
			Symbol any;
			Address anyAddr = progMaxAddr;
			SymbolIterator anyIter = symbolManager.getSymbolIterator(addr, true);
			while (anyIter.hasNext()) {
				any = anyIter.next();
				anyAddr = any.getAddress();
				if (anyAddr.compareTo(addr) > 0) {
					break;
				}
			}
			Long length = anyAddr.getUnsignedOffset() - addr.getUnsignedOffset();
			String name = symbol.getName();
			byte[] bytes = new byte[length.intValue()];
			try {
				memory.getBytes(addr, bytes);
			}
			catch (MemoryAccessException e) {
				Msg.warn(this, "Memory access error");
			}
			info.put(addr, new NameAndBytes(name, bytes));
		}
	}

	private String dumpBytes(Map<Address, NameAndBytes> info) {
		StringBuilder builder = new StringBuilder();
		for (Map.Entry<Address, NameAndBytes> entry : info.entrySet()) {
			Address addr = entry.getKey();
			NameAndBytes nab = entry.getValue();
			builder.append(String.format("new AddressNameBytes(\"%s\",\"%s\",\"%s\"),\n",
				addr.toString(), nab.name(),
				NumericUtilities.convertBytesToString(nab.bytes, " ")));
		}
		return builder.toString();
	}

	private Set<Address> getFunctionAddressesFromVfts(Map<Address, NameAndBytes> info) {
		Set<Address> results = new TreeSet<>();
		for (Map.Entry<Address, NameAndBytes> entry : info.entrySet()) {
			Address addr = entry.getKey();
			int spaceId = addr.getAddressSpace().getSpaceID();
			NameAndBytes nab = entry.getValue();
			byte[] bytes = nab.bytes();
			if (bytes.length % pointerSize != 0) {
				// problem
			}
			int num = bytes.length / pointerSize;
			for (int ordinal = 0; ordinal < num; ordinal++) {
				long offset = getOffset(bytes, ordinal);
				Address functionAddress = addressFactory.getAddress(spaceId, offset);
				if (ignoreAddress(functionAddress)) {
					break;
				}
				results.add(functionAddress);
			}
		}
		return results;
	}

	private boolean ignoreAddress(Address addr) {
		if (addr.getOffset() == 0L) {
			return true;
		}
		for (Symbol symbol : symbolManager.getSymbols(addr)) {
			if (symbol.getName().startsWith("??_R4")) {
				return true;
			}
		}
		return false;
	}

	private long getOffset(byte[] bytes, int ordinal) {
		int index = pointerSize * ordinal;
		if (pointerSize == 4) {
			return dataConverter.getInt(bytes, index);
		}
		else if (pointerSize == 8) {
			return dataConverter.getLong(bytes, index);
		}
		else {
			return 0;
		}
	}

	private void getFunctionInfo(Address addr) {
		Function function = functionManager.getFunctionAt(addr);
		AddressSetView asv = function.getBody();
		Address maxAddr = asv.getMaxAddress();
		Long length = maxAddr.getUnsignedOffset() - addr.getUnsignedOffset();
		byte[] bytes = new byte[length.intValue()];
		try {
			memory.getBytes(addr, bytes);
		}
		catch (MemoryAccessException e) {
			Msg.warn(this, "Memory access error");
		}
		FunctionSignature sig = function.getSignature(true);
		Symbol symbol = symbolManager.getPrimarySymbol(addr);
		String name = symbol.getName(true);
		functionInfo.put(addr, new NameAndBytes(name, bytes));
		signatureInfo.put(addr, sig);
	}

	private String getSignatures() {
		return dumpSignatures(signatureInfo);
	}

	private String dumpSignatures(Map<Address, FunctionSignature> signatures) {
		StringBuilder builder = new StringBuilder();
		for (Map.Entry<Address, FunctionSignature> entry : signatureInfo.entrySet()) {
			Address addr = entry.getKey();
			FunctionSignature sig = entry.getValue();
			builder.append(String.format("\"%s\",\"%s\"\n", addr.toString(), sig.toString()));
		}
		return builder.toString();
	}

	private record NameAndBytes(String name, byte[] bytes) {}

	private String getPdbVirtualMethods() throws CancelledException {
		File pdbFile = locatePdbFile();
		if (pdbFile == null) {
			return "";
		}
		Map<SymbolPath, List<String>> info = getPdbMethodInfo(pdbFile);
		StringBuilder builder = new StringBuilder();
		for (Map.Entry<SymbolPath, List<String>> entry : info.entrySet()) {
			SymbolPath classPath = entry.getKey();
			builder.append("------------------------------\n");
			builder.append(classPath.getPath());
			builder.append('\n');
			for (String methodInfo : entry.getValue()) {
				builder.append(methodInfo);
				builder.append('\n');
			}
		}
		return builder.toString();
	}

	private File locatePdbFile() {
		File pdbFile = PdbPlugin.findPdb(currentProgram, FindOption.NO_OPTIONS, monitor);
		return pdbFile;
	}

	private Map<SymbolPath, List<String>> getPdbMethodInfo(File pdbFile) throws CancelledException {
		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions();
		Map<SymbolPath, List<String>> results = new LinkedHashMap<>();
		try (AbstractPdb pdb = PdbParser.parse(pdbFile, pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			TypeProgramInterface tpi = pdb.getTypeProgramInterface();
			if (tpi == null) {
				return results;
			}
			for (int indexNumber = tpi.getTypeIndexMin(); indexNumber < tpi
					.getTypeIndexMaxExclusive(); indexNumber++) {
				monitor.checkCancelled();
				RecordNumber recordNumber = RecordNumber.typeRecordNumber(indexNumber);
				AbstractMsType msType = pdb.getTypeRecord(recordNumber);
				if (msType instanceof AbstractComplexMsType acms) {
					String className = acms.getName();
					SymbolPath classSymbolPath = new SymbolPath(SymbolPathParser.parse(className));
					RecordNumber listRecordNumber = acms.getFieldDescriptorListRecordNumber();
					AbstractMsType type = pdb.getTypeRecord(listRecordNumber);
					if (type instanceof PrimitiveMsType primitive && primitive.isNoType()) {
						continue;
					}
					else if (type instanceof AbstractFieldListMsType fieldListType) {
						List<String> commandStrings = new ArrayList<>();
						commandStrings.add("length: " + acms.getLength());
						List<AbstractVirtualFunctionTablePointerMsType> vftPtrs =
							fieldListType.getVftPointers();
						processVftPtrs(commandStrings, pdb, vftPtrs);
						processBases(commandStrings, pdb, fieldListType.getBaseClassList());
						processNonstaticMembers(commandStrings, pdb,
							fieldListType.getNonStaticMembers());
						processMethods(commandStrings, pdb, fieldListType.getMethodList());
						if (!commandStrings.isEmpty()) {
							results.put(classSymbolPath, commandStrings);
						}
					}
					else {
						throw new PdbException(type.getClass().getSimpleName() + " seen where " +
							FieldListMsType.class.getSimpleName() + " expected for record number " +
							recordNumber);
					}
				}
			}

		}
		catch (PdbException | IOException e) {
			Msg.warn(this, e);
		}
		return results;
	}

	private void processVftPtrs(List<String> commandStrings, AbstractPdb pdb,
			List<AbstractVirtualFunctionTablePointerMsType> vftPtrs) {
		for (AbstractVirtualFunctionTablePointerMsType vftPtr : vftPtrs) {
			commandStrings.add(getVftPtrString(vftPtr));
		}
	}

	private String getVftPtrString(AbstractVirtualFunctionTablePointerMsType vftPtr) {
		return String.format("struct.addVirtualFunctionTablePointer(ClassUtils.VXPTR_TYPE, %d);",
			vftPtr.getOffset());
	}

	private void processBases(List<String> commandStrings, AbstractPdb pdb,
			List<MsTypeField> bases) {
		for (MsTypeField base : bases) {
			commandStrings.add(getBaseString(pdb, base));
		}
	}

	private String getBaseString(AbstractPdb pdb, MsTypeField baseType) {
		if (baseType instanceof AbstractBaseClassMsType base) {
			RecordNumber recordNumber = base.getBaseClassRecordNumber();
			AbstractMsType ut = pdb.getTypeRecord(recordNumber);
			if (!(ut instanceof AbstractCompositeMsType underlyingType)) {
				Msg.warn(this, "Composite not found for base class: " + ut);
				return "";
			}
			String underlyingName = underlyingType.getName();
			List<String> parts = SymbolPathParser.parse(underlyingName);
			String name = parts.getLast();
			return String.format(
				"struct.addDirectBaseClass(%s_struct.getComposite(), %s_struct, %s, %d);",
				name, name, getAttsString(base.getAttributes()), base.getOffset());
		}
		else if (baseType instanceof AbstractVirtualBaseClassMsType base) {
			RecordNumber recordNumber = base.getBaseClassRecordNumber();
			AbstractMsType ut = pdb.getTypeRecord(recordNumber);
			if (!(ut instanceof AbstractCompositeMsType underlyingType)) {
				Msg.warn(this, "Composite not found for base class: " + ut);
				return "";
			}
			String underlyingName = underlyingType.getName();
			List<String> parts = SymbolPathParser.parse(underlyingName);
			String name = parts.getLast();
			return String.format(
				"struct.addDirectVirtualBaseClass(%s_struct.getComposite()" +
					", %s_struct, %s, %d, ClassUtils.VXPTR_TYPE, %d);",
				name, name, getAttsString(base.getAttributes()),
				base.getBasePointerOffset().intValue(), base.getBaseOffsetFromVbt().intValue());
		}
		else if (baseType instanceof AbstractIndirectVirtualBaseClassMsType base) {
			RecordNumber recordNumber = base.getBaseClassRecordNumber();
			AbstractMsType ut = pdb.getTypeRecord(recordNumber);
			if (!(ut instanceof AbstractCompositeMsType underlyingType)) {
				Msg.warn(this, "Composite not found for base class: " + ut);
				return "";
			}
			String underlyingName = underlyingType.getName();
			List<String> parts = SymbolPathParser.parse(underlyingName);
			String name = parts.getLast();
			return String.format(
				"struct.addIndirectVirtualBaseClass(%s_struct.getComposite()" +
					", %s_struct, %s, %d, ClassUtils.VXPTR_TYPE, %d);",
				name, name, getAttsString(base.getAttributes()),
				base.getBasePointerOffset().intValue(), base.getBaseOffsetFromVbt().intValue());
		}
		else {
			throw new AssertException(
				"Unknown base class type: " + baseType.getClass().getSimpleName());
		}
	}

	private void processNonstaticMembers(List<String> commandStrings, AbstractPdb pdb,
			List<AbstractMemberMsType> members) {
		for (AbstractMemberMsType member : members) {
			commandStrings.add(getMemberString(pdb, member));
		}
	}

	private String getMemberString(AbstractPdb pdb, AbstractMemberMsType member) {
		RecordNumber r = member.getFieldTypeRecordNumber();
		AbstractMsType t = pdb.getTypeRecord(r);
		boolean isZeroLengthArray =
			t instanceof AbstractArrayMsType a && BigInteger.ZERO.equals(a.getSize());
		return String.format(
			"struct.addMember(\"%s\", %sT, %s, %s, %d, null);",
			member.getName(), getTypeName(pdb, r), isZeroLengthArray,
			getAttsString(member.getAttribute()), member.getOffset().intValue());
	}

	private String getTypeName(AbstractPdb pdb, RecordNumber r) {
		int num = r.getNumber();
		return switch (num) {
			case 0x13 -> "longlong";
			case 0x20 -> "unsignedchar";
			case 0x21 -> "unsignedshort";
			case 0x22 -> "unsignedlong";
			case 0x40 -> "float";
			case 0x41 -> "double";
			case 0x42 -> "longdouble";
			case 0x467 -> "pvoid";
			case 0x470 -> "pchar";
			case 0x603 -> "pvoid";
			case 0x670 -> "pchar";
			default -> getOther(pdb, r);
		};
	}

	private String getOther(AbstractPdb pdb, RecordNumber r) {
		AbstractMsType type = pdb.getTypeRecord(r);
		StringBuilder builder = new StringBuilder();
		if (type instanceof PrimitiveMsType pt) {
			// Place to set break point during development
			int a = 1;
			a = a + 1;
		}
		if (type instanceof AbstractPointerMsType pt) {
			builder.append('p');
			AbstractMsType t = pdb.getTypeRecord(pt.getUnderlyingRecordNumber());
			if (t instanceof AbstractModifierMsType mt) {
				AbstractMsType modified = pdb.getTypeRecord(mt.getModifiedRecordNumber());
				String str = mt.toString();
				if (str.contains("const")) {
					builder.append("const");
				}
				if (str.contains("volatile")) {
					builder.append("volatile");
				}
				builder.append(modified.toString());
			}
			else {
				builder.append(t.toString());
			}
		}
		else {
			builder.append(type.toString());
		}
		return builder.toString();
	}

	private void processMethods(List<String> commandStrings, AbstractPdb pdb,
			List<MsTypeField> methods) {
		for (MsTypeField methodType : methods) {
			if (methodType instanceof AbstractOneMethodMsType oneMethodType) {
				String name = oneMethodType.getName();
				ClassFieldMsAttributes attributes = oneMethodType.getAttributes();
				RecordNumber procedureTypeRn = oneMethodType.getProcedureTypeRecordNumber();
				AbstractMsType t = pdb.getTypeRecord(procedureTypeRn);
				if (!(t instanceof AbstractMemberFunctionMsType memberFunc)) {
					Msg.warn(this, "Unexpected type found: " + t.getClass().getSimpleName());
					continue;
				}
				int adjuster = memberFunc.getThisAdjuster();
				Long offset = oneMethodType.getOffsetInVFTableIfIntroVirtual();
				ClassFieldAttributes atts =
					ClassFieldAttributes.convert(attributes, Access.BLANK);
				if (atts.getProperty() == Property.VIRTUAL) {
					commandStrings.add(
						getMethodString(pdb, adjuster, offset.intValue(), name, memberFunc));
				}
			}
			else if (methodType instanceof AbstractOverloadedMethodMsType overloadedMethodType) {
				String name = overloadedMethodType.getName();
				RecordNumber methodsListRn =
					overloadedMethodType.getTypeMethodListRecordNumber();
				AbstractMsType methodsListTry = pdb.getTypeRecord(methodsListRn);
				if (methodsListTry instanceof AbstractMethodListMsType methodsListType) {
					List<AbstractMethodRecordMs> recordList = methodsListType.getList();
					for (AbstractMethodRecordMs methodRecord : recordList) {
						Long offset = methodRecord.getOptionalOffset();
						RecordNumber procedureTypeRn = methodRecord.getProcedureTypeRecordNumber();
						ClassFieldMsAttributes attributes = methodRecord.getAttributes();
						AbstractMsType t = pdb.getTypeRecord(procedureTypeRn);
						if (!(t instanceof AbstractMemberFunctionMsType memberFunc)) {
							Msg.warn(this,
								"Unexpected type found: " + t.getClass().getSimpleName());
							continue;
						}
						int adjuster = memberFunc.getThisAdjuster();
						ClassFieldAttributes atts =
							ClassFieldAttributes.convert(attributes, Access.BLANK);
						if (atts.getProperty() == Property.VIRTUAL) {
							commandStrings.add(getMethodString(pdb, adjuster, offset.intValue(),
								name, memberFunc));
						}
					}
				}
				else {
					Msg.warn(this, "Unexexpected method list type: " +
						methodsListTry.getClass().getSimpleName());
				}
			}
			else {
				Msg.warn(this,
					"Unexexpected method type: " + methodType.getClass().getSimpleName());
			}
		}
	}

	private String getMethodString(AbstractPdb pdb, int adjuster, int offset, String methodName,
			AbstractMemberFunctionMsType memberFunc) {
		return String.format(
			"struct.addVirtualMethod(%d, %d, new SymbolPath(classSp, \"%s\"), %s);",
			adjuster, offset, methodName, getSig(pdb, memberFunc));
	}

	private String getSig(AbstractPdb pdb, AbstractMemberFunctionMsType type) {
		RecordNumber rn = type.getArgListRecordNumber();
		StringBuilder builder = new StringBuilder();
		builder.append('f');
		String rString = getTypeName(pdb, type.getReturnRecordNumber());
		builder.append(rString);
		type.getReturnRecordNumber();
		AbstractMsType lType = pdb.getTypeRecord(rn);
		if (lType instanceof PrimitiveMsType primitive && primitive.isNoType()) {
			// Arguments list is empty. (There better not have been any arguments up until
			//  now.)
			builder.append("void");
		}
		else if (lType instanceof AbstractArgumentsListMsType argsList) {
			List<RecordNumber> argNumbers = argsList.getArgRecordNumbers();
			if (argNumbers.isEmpty()) {
				builder.append("void");
			}
			else {
				for (RecordNumber argNumber : argNumbers) {
					AbstractMsType aType = pdb.getTypeRecord(argNumber);
					if (aType instanceof PrimitiveMsType primitive && primitive.isNoType()) {
						// Arguments list is empty. (There better not have been any arguments
						// up until now.)
						builder.append("void");
						break;
					}
					String aString = getTypeName(pdb, argNumber);
					builder.append(aString);
				}
			}
		}
		builder.append('T');
		return builder.toString();
	}

	private String getAttsString(ClassFieldMsAttributes msAtts) {
		// Note that the conversion here incorporates multiple MS atts into Virtual.  If that
		//  changes, we need to change logic here too
		ClassFieldAttributes atts = ClassFieldAttributes.convert(msAtts, Access.BLANK);
		if (atts.getAccess().equals(Access.PUBLIC)) {
			return Property.VIRTUAL.equals(atts.getProperty()) ? "publicVirtualAttributes"
					: "publicDirectAttributes";
		}
		if (atts.getAccess().equals(Access.PRIVATE)) {
			return Property.VIRTUAL.equals(atts.getProperty()) ? "privateVirtualAttributes"
					: "privateDirectAttributes";
		}
		if (atts.getAccess().equals(Access.PROTECTED)) {
			return Property.VIRTUAL.equals(atts.getProperty()) ? "protectedVirtualAttributes"
					: "protectedDirectAttributes";
		}
		return "UNHANDLED_ATTRIBUTES";
	}

}
