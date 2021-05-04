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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A class to represent a demangled object.
 */
public abstract class DemangledObject implements Demangled {

	protected static final String SPACE = " ";
	protected static final Pattern SPACE_PATTERN = Pattern.compile(SPACE);

	protected static final String NAMESPACE_SEPARATOR = Namespace.DELIMITER;
	protected static final String EMPTY_STRING = "";

	protected final String mangled; // original mangled string
	protected final String originalDemangled;
	protected String specialPrefix;
	protected Demangled namespace;
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

	private String plateComment;

	// Status of mangled String converted successfully to demangled String
	private boolean demangledNameSucceeded = false;

	DemangledObject(String mangled, String originalDemangled) {
		this.mangled = mangled;
		this.originalDemangled = originalDemangled;
	}

	@Override
	public String getDemangledName() {
		return demangledName;
	}

	@Override
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
	@Override
	public void setName(String name) {
		this.demangledName = name;
		this.name = name;
		if (name != null) {
			// Use safe name and omit common spaces where they are unwanted in names.
			// Trim leading/trailing whitespace which may have been improperly included by demangler
			this.name =
				DemanglerUtil.stripSuperfluousSignatureSpaces(name).trim().replace(' ', '_');
		}
		demangledNameSucceeded = !mangled.equals(name);
	}

	/**
	 * Returns the success state of converting a mangled String into a demangled String
	 * @return true succeeded creating demangled String
	 */
	public boolean demangledNameSuccessfully() {
		return demangledNameSucceeded;
	}

	@Override
	public String getMangledString() {
		return mangled;
	}

	@Override
	public String getOriginalDemangled() {
		return originalDemangled;
	}

	@Override
	public Demangled getNamespace() {
		return namespace;
	}

	@Override
	public void setNamespace(Demangled namespace) {
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

	@Override
	public final String getSignature() {
		return getSignature(false);
	}

	@Override
	public String getNamespaceName() {
		return getName();
	}

	@Override
	public String toString() {
		return getSignature(false);
	}

	@Override
	public String getNamespaceString() {
		StringBuilder buffer = new StringBuilder();
		if (namespace != null) {
			buffer.append(namespace.getNamespaceString());
			buffer.append(Namespace.DELIMITER);
		}
		buffer.append(getNamespaceName());
		return buffer.toString();
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
		return applyPlateCommentOnly(program, address);
	}

	/**
	 * @param program The program for which to apply the comment
	 * @param address The address for the comment
	 * @return {@code true} if a comment was applied
	 * @throws Exception if the symbol could not be demangled or if the address is invalid
	 */
	public boolean applyPlateCommentOnly(Program program, Address address) throws Exception {
		if (!demangledNameSuccessfully()) {
			throw new DemangledException("Symbol did not demangle at address: " + address);
		}
		if (!address.isMemoryAddress() || !program.getMemory().contains(address)) {
			return true; // skip this symbol
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

	/**
	 * Sets the plate comment to be used if the {@link #getOriginalDemangled()} string is not 
	 * available
	 * 
	 * @param plateComment the plate comment text
	 */
	public void setBackupPlateComment(String plateComment) {
		this.plateComment = plateComment;
	}

	/**
	 * Creates descriptive text that is intended to be used as documentation.  The text defaults
	 * to the original demangled text.  If that is not available, then any text set by
	 * {@link #setBackupPlateComment(String)} will be used.  The last choice for this text is
	 * the signature generated by {@link #getSignature(boolean)}.
	 * 
	 * @return the text
	 */
	protected String generatePlateComment() {
		if (originalDemangled != null) {
			return originalDemangled;
		}
		return (plateComment == null) ? getSignature(true) : plateComment;
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
			Demangled demangledNamespace) {

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
	private static List<String> getNamespaceList(Demangled typeNamespace) {
		List<String> list = new ArrayList<>();
		Demangled ns = typeNamespace;
		while (ns != null) {
			list.add(0, ns.getNamespaceName());
			ns = ns.getNamespace();
		}
		return list;
	}

	/**
	 * Get or create the specified typeNamespace.  The returned namespace may only be a partial
	 * namespace if errors occurred.  The caller should check the returned namespace and adjust
	 * any symbol creation accordingly.
	 *
	 * @param program the program
	 * @param typeNamespace demangled namespace
	 * @param parentNamespace root namespace to be used (e.g., library, global, etc.)
	 * @param functionPermitted if true an existing function may be used as a namespace
	 * @return namespace or partial namespace if error occurs
	 */
	public static Namespace createNamespace(Program program, Demangled typeNamespace,
			Namespace parentNamespace, boolean functionPermitted) {

		Namespace namespace = parentNamespace;
		if (namespace == null) {
			namespace = program.getGlobalNamespace();
		}

		SymbolTable symbolTable = program.getSymbolTable();
		for (String namespaceName : getNamespaceList(typeNamespace)) {

			// TODO - This is compensating for too long templates.  We should probably genericize
			//        templates so that any class with the same number of template parameters and
			//        same name is the same class--would that reflect reality?
			namespaceName = ensureNameLength(namespaceName);

			try {
				namespace =
					symbolTable.getOrCreateNameSpace(namespace, namespaceName, SourceType.IMPORTED);
			}
			catch (DuplicateNameException e) {
				Msg.error(DemangledObject.class,
					"Failed to create namespace due to name conflict: " +
						NamespaceUtils.getNamespaceQualifiedName(namespace, namespaceName, false));
				break;
			}
			catch (InvalidInputException e) {
				Msg.error(DemangledObject.class, "Failed to create namespace: " + e.getMessage());
				break;
			}

			Symbol nsSymbol = namespace.getSymbol();
			if (!isPermittedNamespaceType(nsSymbol.getSymbolType(), functionPermitted)) {

				String allowedTypes = "SymbolType.CLASS, SymbolType.NAMESPACE";
				if (functionPermitted) {
					allowedTypes += ", SymbolType.FUNCTION";
				}

				Msg.error(DemangledObject.class,
					"Bad namespace type - must be one of: " + allowedTypes +
						NamespaceUtils.getNamespaceQualifiedName(namespace, namespaceName, false));
				break;
			}
		}
		return namespace;
	}

	private static boolean isPermittedNamespaceType(SymbolType symbolType,
			boolean functionPermitted) {
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

}
