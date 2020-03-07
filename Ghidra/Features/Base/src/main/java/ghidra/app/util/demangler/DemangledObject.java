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
package ghidra.app.util.demangler;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import util.demangler.GenericDemangledObject;
import util.demangler.GenericDemangledType;

/**
 * A class to represent a demangled object.
 */
public abstract class DemangledObject {

	protected static final String SPACE = " ";
	protected static final Pattern SPACE_PATTERN = Pattern.compile(SPACE);

	protected static final String NAMESPACE_SEPARATOR = Namespace.DELIMITER;
	protected static final String EMPTY_STRING = "";

	protected String originalMangled;
	protected String utilDemangled;
	protected String specialPrefix;
	protected String specialMidfix;
	protected String specialSuffix;
	protected DemangledType namespace;
	protected String visibility;//public, protected, etc.

	//TODO: storageClass refers to things such as "static" but const and volatile are 
	// typeQualifiers.  Should change this everywhere(?).
	protected String storageClass; //const, volatile, etc

	//TODO: see above regarding this belonging to the "true" storageClass items.
	protected boolean isStatic;

	//TODO: determine what type of keyword this is (not type qualifier or storage class).
	protected boolean isVirtual;
	private String demangledName;
	private String name;
	private boolean isConst;
	private boolean isVolatile;
	private boolean isPointer64;

	protected boolean isThunk;
	protected boolean isUnaligned;
	protected boolean isRestrict;
	protected String basedName;
	protected String memberScope;

	private String signature;

	DemangledObject() {
		// default
	}

	DemangledObject(GenericDemangledObject other) {
		originalMangled = other.getOriginalMangled();
		specialPrefix = other.getSpecialPrefix();
		specialMidfix = other.getSpecialMidfix();
		specialSuffix = other.getSpecialSuffix();

		GenericDemangledType otherNamespace = other.getNamespace();
		if (otherNamespace != null) {
			namespace = DemangledType.convertToNamespace(otherNamespace);
		}

		visibility = other.getVisibility();
		storageClass = other.getStorageClass();
		setName(other.getName());
		isConst = other.isConst();
		isVolatile = other.isVolatile();
		isPointer64 = other.isPointer64();
		isStatic = other.isStatic();
		isVirtual = other.isVirtual();
		isThunk = other.isThunk();

		isUnaligned = other.isUnaligned();
		isRestrict = other.isRestrict();
		basedName = other.getBasedName();
		memberScope = other.getMemberScope();
	}

	/** 
	 * Returns the unmodified demangled name of this object.
	 * This name may contain whitespace and other characters not
	 * supported for symbol or data type creation.  See {@link #getName()} 
	 * for the same name modified for use within Ghidra.
	 * @return name of this DemangledObject
	 */
	public String getDemangledName() {
		return demangledName;
	}

	/**
	 * Returns the original mangled name
	 * @return the name
	 */
	public String getMangledName() {
		return originalMangled;
	}

	/** 
	 * Returns the demangled name of this object.
	 * NOTE: unsupported symbol characters, like whitespace, will be
	 * converted to an underscore.
	 * @return name of this DemangledObject with unsupported characters converted to underscore
	 */
	public String getName() {
		return name;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setConst(boolean isConst) {
		this.isConst = isConst;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setVolatile(boolean isVolatile) {
		this.isVolatile = isVolatile;
	}

	public boolean isPointer64() {
		return isPointer64;
	}

	public void setPointer64(boolean isPointer64) {
		this.isPointer64 = isPointer64;
	}

	public boolean isStatic() {
		return isStatic;
	}

	public void setStatic(boolean isStatic) {
		this.isStatic = isStatic;
	}

	public boolean isVirtual() {
		return isVirtual;
	}

	public void setVirtual(boolean isVirtual) {
		this.isVirtual = isVirtual;
	}

	public boolean isThunk() {
		return isThunk;
	}

	public void setThunk(boolean isThunk) {
		this.isThunk = isThunk;
	}

	public void setUnaligned() {
		isUnaligned = true;
	}

	public boolean isUnaligned() {
		return isUnaligned;
	}

	public void setRestrict() {
		isRestrict = true;
	}

	public boolean isRestrict() {
		return isRestrict;
	}

	public String getBasedName() {
		return basedName;
	}

	public void setBasedName(String basedName) {
		this.basedName = basedName;
	}

	public String getMemberScope() {
		return memberScope;
	}

	public void setMemberScope(String memberScope) {
		this.memberScope = memberScope;
	}

	/**
	 * Sets the name of the demangled object
	 * @param name the new name
	 */
	public void setName(String name) {
		this.demangledName = name;
		this.name = name;
		if (name != null) {
			// Use safe name and omit common spaces where they are unwanted in names.
			// Trim leading/trailing whitespace which may have been improperly included by demangler
			this.name =
				DemanglerUtil.stripSuperfluousSignatureSpaces(name).trim().replace(' ', '_');
		}
	}

	/**
	 * Sets the original mangled name
	 * @param mangled the original mangled name
	 */
	public void setOriginalMangled(String mangled) {
		this.originalMangled = mangled;
	}

	/**
	 * Sets the demangled output from a supplemental utility.
	 * @param utilDemangled the demangled string
	 */
	public void setUtilDemangled(String utilDemangled) {
		this.utilDemangled = utilDemangled;
	}

	/**
	 * Gets the demangled output from a supplemental utility.
	 * @return the demangled String created for this object.
	 */
	public String getUtilDemangled() {
		return utilDemangled;
	}

	/**
	 * Returns the namespace containing this demangled object.
	 * @return the namespace containing this demangled object
	 */
	public DemangledType getNamespace() {
		return namespace;
	}

	public void setNamespace(DemangledType namespace) {
		this.namespace = namespace;
	}

	public String getVisibility() {
		return visibility;
	}

	public void setVisibilty(String visibility) {
		this.visibility = visibility;
	}

	public String getStorageClass() {
		return storageClass;
	}

	public void setStorageClass(String storageClass) {
		this.storageClass = storageClass;
	}

	public String getSpecialPrefix() {
		return specialPrefix;
	}

	public void setSpecialPrefix(String special) {
		this.specialPrefix = special;
	}

	public String getSpecialMidfix() {
		return specialMidfix;
	}

	public void setSpecialMidfix(String chargeType) {
		this.specialMidfix = chargeType;
	}

	public String getSpecialSuffix() {
		return specialSuffix;
	}

	public void setSpecialSuffix(String specialSuffix) {
		this.specialSuffix = specialSuffix;
	}

	/**
	 * Returns a complete signature for the demangled symbol.
	 * <br>For example:
	 *            "unsigned long foo"
	 *            "unsigned char * ClassA::getFoo(float, short *)"
	 *            "void * getBar(int **, MyStruct &amp;)"
	 * <br><b>Note: based on the underlying mangling scheme, the
	 * return type may or may not be specified in the signature.</b>
	 * @param format true if signature should be pretty printed
	 * @return a complete signature for the demangled symbol
	 */
	public abstract String getSignature(boolean format);

	/**
	 * Sets the signature. Calling this method will
	 * override the auto-generated signature.
	 * @param signature the signature
	 */
	public void setSignature(String signature) {
		this.signature = signature;
	}

	@Override
	public String toString() {
		return getSignature(false);
	}

	/**
	 * Determine if the symbol at address has already been demangled.  While memory symbols
	 * check for presence of demangledName, external symbols simply check if demangled/alternate
	 * name has already been assigned.
	 * @param program the program being modified
	 * @param address address of demangled symbol
	 * @return true if symbol at address has already been demangled
	 */
	protected boolean isAlreadyDemangled(Program program, Address address) {
		String symbolName = ensureNameLength(name);
		if (address.isExternalAddress()) {
			Symbol extSymbol = program.getSymbolTable().getPrimarySymbol(address);
			if (extSymbol == null) {
				return false;
			}
			ExternalLocation extLoc = program.getExternalManager().getExternalLocation(extSymbol);
			return extLoc.getOriginalImportedName() != null;
		}

		Symbol[] symbols = program.getSymbolTable().getSymbols(address);
		for (Symbol symbol : symbols) {
			if (symbol.getName().equals(symbolName) && !symbol.getParentNamespace().isGlobal()) {
				SymbolType symbolType = symbol.getSymbolType();
				if (symbolType == SymbolType.LABEL || symbolType == SymbolType.FUNCTION) {
					return true;
				}
			}
		}
		return false;
	}

	public boolean applyTo(Program program, Address address, DemanglerOptions options,
			TaskMonitor monitor) throws Exception {
		if (originalMangled.equals(name)) {
			return false;
		}
		String comment = program.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
		String newComment = generatePlateComment();
		if (comment == null || comment.indexOf(newComment) < 0) {
			if (comment == null) {
				comment = newComment;
			}
			else {
				comment = comment + '\n' + newComment;
			}
			program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
		}
		return true;
	}

	protected String generatePlateComment() {
		if (utilDemangled != null) {
			return utilDemangled;
		}
		return (signature == null) ? getSignature(true) : signature;
	}

	protected String pad(int len) {
		StringBuffer buffer = new StringBuffer();
		for (int i = 0; i < len; i++) {
			buffer.append(' ');
		}
		return buffer.toString();
	}

	protected Symbol applyDemangledName(Address addr, boolean setPrimary,
			boolean functionNamespacePermitted, Program prog) throws InvalidInputException {
		return applyDemangledName(name, addr, setPrimary, functionNamespacePermitted, prog);
	}

	protected Symbol applyDemangledName(String symbolName, Address addr, boolean setPrimary,
			boolean functionNamespacePermitted, Program prog) throws InvalidInputException {

		symbolName = ensureNameLength(symbolName);

		if (addr.isExternalAddress()) {
			return updateExternalSymbol(prog, addr, symbolName, namespace);
		}

		SymbolTable symbolTable = prog.getSymbolTable();

		// NOTE: If the original mangled symbol incorrectly resides within a non-global
		// namespace, that namespace will be ignored when applying the demangled symbol
		Namespace ns = createNamespace(prog, namespace, null, functionNamespacePermitted);

		// Create the demangled symbol.  If the name already exists at the address in
		// the global space, it will be moved into the specified namespace by the symbol
		// table
		Symbol demangledSymbol = SymbolUtilities.createPreferredLabelOrFunctionSymbol(prog, addr,
			ns, symbolName, SourceType.ANALYSIS);
		if (demangledSymbol == null || !setPrimary) {
			return demangledSymbol;
		}

		SetLabelPrimaryCmd cmd = new SetLabelPrimaryCmd(addr, symbolName, ns);
		cmd.applyTo(prog);

		return symbolTable.getPrimarySymbol(addr);
	}

	private Symbol updateExternalSymbol(Program program, Address externalAddr, String symbolName,
			DemangledType demangledNamespace) {

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s = symbolTable.getPrimarySymbol(externalAddr);
		if (s == null) {
			Msg.error(DemangledObject.class,
				"No such external address " + externalAddr + " for " + symbolName);
		}

		try {
			Namespace ns =
				createNamespace(program, demangledNamespace, s.getParentNamespace(), false);
			ExternalLocation extLoc = s.getProgram().getExternalManager().getExternalLocation(s);
			extLoc.setName(ns, symbolName, SourceType.IMPORTED);
		}
		catch (Exception e) {
			Msg.error(DemangledObject.class,
				"Unexpected Exception setting name and namespace for " + symbolName + " in " +
					s.getParentNamespace(),
				e);
		}
		return s;
	}

	/**
	 * Build namespace name list
	 * @param typeNamespace demangled namespace object
	 * @return list of namespace names
	 */
	private static List<String> getNamespaceList(DemangledType typeNamespace) {
		ArrayList<String> list = new ArrayList<>();
		DemangledType ns = typeNamespace;
		while (ns != null) {
			list.add(0, ns.getName());
			ns = ns.getNamespace();
		}
		return list;
	}

	// TODO needs updating. Couldn't determine what getResigualNamespacePath was changed to.
	/**
	 * Get or create the specified typeNamespace.  The returned namespace may only be a partial 
	 * namespace if errors occurred.  The caller should check the returned namespace and adjust
	 * any symbol creation accordingly.  Caller should use 
	 * <code>getResidualNamespacePath(DemangledType, Namespace)</code> to handle the case where
	 * only a partial namespace has been returned.
	 * @param program
	 * @param typeNamespace demangled namespace
	 * @param parentNamespace root namespace to be used (e.g., library, global, etc.)
	 * @param functionPermitted if true an existing function may be used as a namespace
	 * @return namespace or partial namespace if error occurs
	 */
	public static Namespace createNamespace(Program program, DemangledType typeNamespace,
			Namespace parentNamespace, boolean functionPermitted) {

		Namespace namespace = parentNamespace;
		if (namespace == null) {
			namespace = program.getGlobalNamespace();
		}

		for (String namespaceName : getNamespaceList(typeNamespace)) {

			// TODO - This is compensating for too long templates.  We should probably genericize
			//        templates so that any class with the same number of template parameters and
			//        same name is the same class--would that reflect reality?
			namespaceName = ensureNameLength(namespaceName);

			SymbolTable symbolTable = program.getSymbolTable();

			List<Symbol> symbols = symbolTable.getSymbols(namespaceName, namespace);
			Symbol namespaceSymbol =
				symbols.stream()
						.filter(s -> (s.getSymbolType() == SymbolType.NAMESPACE ||
							s.getSymbolType() == SymbolType.CLASS))
						.findFirst()
						.orElse(null);
			if (namespaceSymbol == null) {
				try {
					namespace =
						symbolTable.createNameSpace(namespace, namespaceName, SourceType.IMPORTED);
				}
				catch (DuplicateNameException e) {
					Msg.error(DemangledObject.class,
						"Failed to create namespace due to name conflict: " +
							NamespaceUtils.getNamespaceQualifiedName(namespace, namespaceName,
								false));
					break;
				}
				catch (InvalidInputException e) {
					Msg.error(DemangledObject.class,
						"Failed to create namespace: " + e.getMessage());
					break;
				}
			}
			else if (isPermittedNamespaceSymbol(namespaceSymbol, functionPermitted)) {
				namespace = (Namespace) namespaceSymbol.getObject();
			}
			else {
				Msg.error(DemangledObject.class,
					"Failed to create namespace due to name conflict: " +
						NamespaceUtils.getNamespaceQualifiedName(namespace, namespaceName, false));
				break;
			}
		}
		return namespace;
	}

	private static boolean isPermittedNamespaceSymbol(Symbol symbol, boolean functionPermitted) {
		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType == SymbolType.CLASS || symbolType == SymbolType.NAMESPACE) {
			return true;
		}
		return functionPermitted && symbolType == SymbolType.FUNCTION;
	}

	/** 
	 * Ensure name does not pass the limit defined by Ghidra
	 * 
	 * @param name the name whose length to restrict 
	 * @return the name, updated as needed
	 */
	protected static String ensureNameLength(String name) {
		int length = name.length();
		if (length <= SymbolUtilities.MAX_SYMBOL_NAME_LENGTH) {
			return name;
		}

		// These names are usually API methods that are templated in such a way as the
		// names become too large, really to much so to even read.  Not sure of the best
		// way to trim these names without losing the type specificity provided by the
		// template arguments.  For now, just trim the name to some length that still
		// leaves us with some of the template arguments.  Also, throw on some of the
		// trailing data, in case that is helpful.
		StringBuilder buffy = new StringBuilder();
		buffy.append(name.substring(0, SymbolUtilities.MAX_SYMBOL_NAME_LENGTH / 2));
		buffy.append("...");
		buffy.append(name.substring(length - 100)); // trailing data
		return buffy.toString();
	}

	protected Structure createClassStructure(Program prog, Function func) {
		DataTypeManager dataTypeManager = prog.getDataTypeManager();

		if (namespace == null) {
			// unexpected
			return null;
		}
		String structureName = namespace.getName();

		Symbol parentSymbol = func.getSymbol().getParentSymbol();
		if (parentSymbol.getSymbolType() == SymbolType.NAMESPACE) {
			try {
				NamespaceUtils.convertNamespaceToClass((Namespace) parentSymbol.getObject());
			}
			catch (InvalidInputException e) {
				throw new AssertException(e); // unexpected condition
			}
		}

		// Store class structure in parent namespace
		DemangledType classStructureNamespace = namespace.getNamespace();

		Structure classStructure = (Structure) DemangledDataType.findDataType(dataTypeManager,
			classStructureNamespace, structureName);
		if (classStructure == null) {
			classStructure = DemangledDataType.createPlaceHolderStructure(structureName,
				classStructureNamespace);
		}
		classStructure = (Structure) dataTypeManager.resolve(classStructure,
			DataTypeConflictHandler.DEFAULT_HANDLER);
		return classStructure;
	}

}
