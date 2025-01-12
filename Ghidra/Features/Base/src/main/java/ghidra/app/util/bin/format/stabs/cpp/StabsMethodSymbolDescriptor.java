package ghidra.app.util.bin.format.stabs.cpp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;

import ghidra.app.util.bin.format.stabs.StabsClassSymbolDescriptor;
import ghidra.app.util.bin.format.stabs.StabsParseException;
import ghidra.app.util.bin.format.stabs.StabsToken;
import ghidra.app.util.bin.format.stabs.StabsTokenizer;
import ghidra.app.util.bin.format.stabs.StabsClassSymbolDescriptor.Visibility;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledDataType;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemangledType;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;

import static ghidra.app.util.demangler.DemanglerUtil.demangle;
import static ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory.getTypeDescriptor;

/**
 * Helper Class for C++ Class Methods
 */
public final class StabsMethodSymbolDescriptor {

	private static enum NestedGroups {
		NAME,
		GROUP
	}
	private static enum Groups {
		STAB,
		MANGLED,
		VISIBILITY,
		MODIFIER,
		METHODTYPE,
		OFFSET,
		BASE
	}

	private static final String NESTED_PATTERN =
		"(?<%s>[^\\s;]+?)\\s*::(?<%s>((((\\d+)|(\\((\\d+),(\\d+)\\))).+?)"
		+"((?<=:)\\w+?);([0129])([A-D\\*\\.\\?])([\\.\\*\\?])(\\-\\d+;)?(?:(\\d+);)?)+)";

	private static final String PATTERN =
		"(?<%s>((\\d+)|(\\((\\d+),(\\d+)\\))).*?)"
		+"(?<=:)(?<%s>\\w+?);(?<%s>[0129])(?<%s>[A-D\\*\\.\\?])(?<%s>[\\.\\*\\?])"
		+"(?<%s>\\-\\d+;)?(?:(?<%s>\\d+);)?";

	private static final StabsTokenizer<NestedGroups> NESTED_TOKENIZER =
		new StabsTokenizer<>(NESTED_PATTERN, NestedGroups.class);

	private static final StabsTokenizer<Groups> TOKENIZER =
		new StabsTokenizer<>(PATTERN, Groups.class);

	private final Program program;
	private final StabsToken<Groups> token;
	private final StabsTypeDescriptor type;
	private final DemangledFunction demangled;

	/**
	 * Gets a list of all found class methods in the provided stab
	 * @param symbol the stab descriptor
	 * @return a list of all found methods
	 * @throws StabsParseException if an error occurs while parsing the stab
	 */
	public static List<StabsMethodSymbolDescriptor> getMethods(StabsClassSymbolDescriptor symbol)
		throws StabsParseException {
			List<StabsToken<NestedGroups>> tokens =
				NESTED_TOKENIZER.getTokens(symbol.getStab());
			if (!tokens.isEmpty()) {
				List<StabsMethodSymbolDescriptor> methods = new LinkedList<>();
				for (StabsToken<NestedGroups> token : tokens) {
					methods.addAll(getSubMethods(symbol, token));
				}
				methods = new ArrayList<>(methods);
				return Collections.unmodifiableList(methods);
			}
			return Collections.emptyList();
	}

	/**
	 * Checks if the stab contains any method descriptors
	 * @param stab the stab string
	 * @return true if a method descriptor is found
	 */
	public static boolean containsMethods(String stab) {
		Pattern pattern = NESTED_TOKENIZER.getPattern();
		return pattern.matcher(stab).find();
	}

	private static List<StabsMethodSymbolDescriptor> getSubMethods(StabsClassSymbolDescriptor symbol,
		StabsToken<NestedGroups> token) throws StabsParseException {
			List<StabsToken<Groups>> tokens =
				TOKENIZER.getTokens(token.get(NestedGroups.GROUP));
			List<StabsMethodSymbolDescriptor> methods = new ArrayList<>(tokens.size());
			for (StabsToken<Groups> subToken : tokens) {
				methods.add(new StabsMethodSymbolDescriptor(
					symbol, subToken, token.get(NestedGroups.NAME)));
			}
			return methods;
	}

	private StabsMethodSymbolDescriptor(StabsClassSymbolDescriptor symbol, StabsToken<Groups> token,
		String name) throws StabsParseException {
			this.program = symbol.getFile().getProgram();
			this.token = token;
			this.demangled = doGetDemangledFunction(program, token);
			this.type = getTypeDescriptor(symbol, token.get(Groups.STAB));
			if (demangled != null) {
				fixupDemangled();
			}
	}

	private void fixupDemangled() {
		switch (getModifier()) {
			case CONST:
				demangled.setTrailingConst();
				break;
			case CONST_VOLATILE:
				demangled.setTrailingConst();
			case VOLATILE:
				demangled.setTrailingVolatile();
			default:
				break;
		}
		if (getVisibility() != Visibility.NONE) {
			demangled.setVisibilty(getVisibility().getDeclaration());
		}
		demangled.setVirtual(isVirtual());
		demangled.setStatic(isStatic());
		if (getDataType() instanceof FunctionDefinition) {
			DataType retType = ((FunctionDefinition) getDataType()).getReturnType();
			Demangled ns = convertToNamespaces(retType.getCategoryPath());
			DemangledDataType ddt = new DemangledDataType(null, null, retType.getName());
			ddt.setNamespace(ns);
			demangled.setReturnType(ddt);
		}
	}

	private static Demangled convertToNamespaces(CategoryPath path) {
		Demangled prev = null;
		for (String s : path.asList()) {
			Demangled current = new DemangledType(null, null, s);
			if (prev != null) {
				current.setNamespace(prev);
			}
			prev = current;
		}
		return prev;
	}

	/**
	 * Gets the first demangled function found in the symbol descriptors stab.
	 * Useful for determining the correct namespace of a C++ Class.
	 * @param symbol the symbol descriptor
	 * @return the first found demangled function or null if none
	 * @throws StabsParseException if an error occurs parsing the stab
	 */
	public static DemangledFunction getDemangledFunction(StabsClassSymbolDescriptor symbol)
		throws StabsParseException {
			Program program = symbol.getFile().getProgram();
			List<StabsToken<Groups>> tokens = TOKENIZER.getTokens(symbol.getStab());
			if (!tokens.isEmpty()) {
				for (StabsToken<Groups> token : tokens) {
					DemangledFunction fun = doGetDemangledFunction(program, token);
					if (fun != null) {
						return fun;
					}
				}
			}
			return null;
	}

	private static DemangledFunction doGetDemangledFunction(Program program,
		StabsToken<Groups> token) throws StabsParseException {
			try {
				DemangledObject result = demangle(program, token.get(Groups.MANGLED));
				if (result instanceof DemangledFunction) {
					return (DemangledFunction) result;
				}
				return null;
			} catch (RuntimeException e) {
				// #1457
				Msg.error(StabsMethodSymbolDescriptor.class, e);
				return null;
			}
	}

	/**
	 * Gets the DataType for this class method
	 * @return the class method's data type
	 */
	public DataType getDataType() {
		return type.getDataType();
	}

	/**
	 * @return the demangled function
	 */
	public DemangledFunction getDemangledFunction() {
		return demangled;
	}

	/**
	 * Attempts to locate the address of the described method
	 * @return the address of the method if found else {@link Address#NO_ADDRESS}
	 */
	public Address locateMethod() {
		SymbolTable table = program.getSymbolTable();
		List <Symbol> symbols = table.getGlobalSymbols(token.get(Groups.MANGLED));
		if (symbols.size() == 1) {
			return symbols.get(0).getAddress();
		}
		return Address.NO_ADDRESS;
	}

	/**
	 * Gets the visibility of this method
	 * @return the method's visibility
	 */
	public Visibility getVisibility() {
		return Visibility.getVisibility(token.getChar(Groups.VISIBILITY));
	}

	/**
	 * Gets the modifier for this method
	 * @return the method's modifier
	 */
	public MethodModifier getModifier() {
		return MethodModifier.getModifier(token.getChar(Groups.MODIFIER));
	}

	/**
	 * Checks if this is a virtual method
	 * @return true if this is a virtual method
	 */
	public boolean isVirtual() {
		return token.getChar(Groups.METHODTYPE) == '*';
	}

	/**
	 * Checks if this is a static method
	 * @return true if this is a static method
	 */
	public boolean isStatic() {
		return token.getChar(Groups.METHODTYPE) == '?';
	}

	/**
	 * Gets the index of this method in the vtable
	 * @return the vtable index or -1 if this method is not virtual
	 */
	public int getVtableIndex() {
		if (isVirtual()) {
			return Integer.parseInt(token.get(Groups.OFFSET)) & Integer.MAX_VALUE;
		}
		return -1;
	}

	/** Potential Method Modifiers */
	public static enum MethodModifier {
		NONE,
		/** const */
		CONST,
		/** volatile */
		VOLATILE,
		/** const volatile */
		CONST_VOLATILE;

		private static MethodModifier getModifier(char c) {
			switch (c) {
				case 'B':
					return CONST;
				case 'C':
					return VOLATILE;
				case 'D':
					return CONST_VOLATILE;
				default:
					return NONE;
			}
		}

		/**
		 * Gets the declaration of this visibility modifier
		 * @return the visibility declaration or an empty string if none
		 */
		public String getDeclaration() {
			switch (this) {
				case CONST:
					return "const";
				case VOLATILE:
					return "volatile";
				case CONST_VOLATILE:
					return "const volatile";
				default:
					return "";
			}
		}
	}

}
