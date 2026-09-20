package ghidra.app.util.bin.format.stabs;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.stabs.cpp.*;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptor;
import ghidra.app.util.bin.format.stabs.types.StabsTypeDescriptorFactory;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * C++ Class Type (Structure, Union) implementation of the StabSymbolDescriptor
 */
public final class StabsClassSymbolDescriptor extends AbstractStabsSymbolDescriptor
	implements StabsTypeDescriptor{

	private static final String SUPER_CLASS = "super_%s";
	private static final String CONSTRUCTOR_NAME = "__ct_base";
	private static final Pattern COMPOSITE_START = Pattern.compile("(?<==)([su]\\d+)");
	private static final Pattern FIRST_BASE_PATTERN =
		Pattern.compile(String.format("~%%(%s.*?);", StabsTypeNumber.TYPE_NUMBER_PATTERN));

	private final Program program;
	private final GhidraClass gc;
	private final List<StabsBaseClassDescriptor> bases;
	private final List<StabsMemberSymbolDescriptor> members;
	private final List<StabsMethodSymbolDescriptor> methods;
	private final StabsTypeDescriptor firstBase;

	/**
	 * Constructs a new StabsClassSymbolDescriptor
	 * @param stab the portion of the stab containing this descriptor
	 * @param file the file containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsClassSymbolDescriptor(String stab, StabsFile file) throws StabsParseException {
		super(stab, file);
		StabsTypeNumber typeNum = new StabsTypeNumber(stab);
		file.addType(this, typeNum);
		this.program = file.getProgram();
		this.gc = doGetGhidraClass();
		this.bases = StabsBaseClassDescriptor.getBases(this, getCompositeStart());
		this.members = StabsMemberSymbolDescriptor.getMembers(this, getMembersStart());
		this.methods = StabsMethodSymbolDescriptor.getMethods(this);
		this.firstBase = doGetFirstBase();
		fixupGhidraClass();
		doAddBases();
		doAddMembers();
	}

	@Override
	public DataType getDataType() {
		// don't change the category path as it causes problems
		return VariableUtilities.findOrCreateClassStruct(gc, dtm);
	}

	@Override
	public StabsSymbolDescriptorType getSymbolDescriptorType() {
		return StabsSymbolDescriptorType.CLASS;
	}

	@Override
	public StabsSymbolDescriptor getSymbolDescriptor() {
		return this;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.COMPOSITE;
	}

	@Override
	public int getLength() {
		throw new UnsupportedOperationException("A class cannot hava an inline definition");
	}

	private StabsTypeDescriptor doGetFirstBase() throws StabsParseException {
		Matcher matcher = FIRST_BASE_PATTERN.matcher(stab);
		if (matcher.find()) {
			return StabsTypeDescriptorFactory.getTypeDescriptor(this, matcher.group(1));
		}
		return null;
	}

	private void fixupGhidraClass() {
		if (stab.contains(CONSTRUCTOR_NAME) || gc.getName().indexOf('<') != -1) {
			// no fixing required
			return;
		}
		DemangledObject o = null;
		for (StabsMemberSymbolDescriptor member : members) {
			o = member.getDemangledObject();
			if (o != null) {
				break;
			}
		}
		if (o != null) {
			DataType dt = getDataType();
			try {
				dt.setName(o.getNamespace().getName());
				gc.getSymbol().setName(o.getNamespace().getName(), SourceType.IMPORTED);
			} catch (Exception e) {
				// don't care
				Msg.error(this, e);
			}
		} /*else {
			likely didn't require fixing
		}*/
	}

	private String getCompositeStart() {
		Matcher matcher = COMPOSITE_START.matcher(stab);
		if (matcher.find()) {
			return stab.substring(matcher.end(1));
		}
		return "";
	}

	private String getMembersStart() {
		if (bases.isEmpty()) {
			return getCompositeStart();
		}
		int index = StabsBaseClassDescriptor.getBaseStartIndex(stab)+getBasesLength();
		return stab.substring(index);
	}

	private int getBasesLength() {
		return bases.stream()
					.mapToInt(StabsBaseClassDescriptor::getLength)
					.sum();
	}

	private DemangledFunction getCtor() throws StabsParseException {
		 int index = stab.indexOf(CONSTRUCTOR_NAME);
		if (index != -1) {
			return StabsMethodSymbolDescriptor.getDemangledFunction(this);
		}
		DemangledFunction result =
			StabsMethodSymbolDescriptor.getDemangledFunction(this);
		if (result != null) {
			return result;
		}
		throw getError();
	}

	private String toNamespace(DemangledFunction fun) {
		return fun.getNamespace().getNamespaceString();
	}

	private GhidraClass getNextAvailableGc() throws StabsParseException {
		SymbolPath sPath = new SymbolPath(name);
		Namespace existingNs = null;
		int i = 0;
		do {
			if (i == 0) {
				i++;
			} else {
				sPath = new SymbolPath(String.format("%s_%d", name, ++i));
			}
			existingNs = NamespaceUtils.getNonFunctionNamespace(program, sPath);
		} while (existingNs != null);
		try {
			existingNs = NamespaceUtils.createNamespaceHierarchy(
				sPath.toString(), null, program, SourceType.IMPORTED);
			if (!(existingNs instanceof GhidraClass)) {
				existingNs = NamespaceUtils.convertNamespaceToClass(existingNs);
			}
			return (GhidraClass) existingNs;
		} catch (InvalidInputException e) {
			// if the input is invalid then so is the stab
			throw new StabsParseException(name, stab);
		}
	}

	private GhidraClass doGetGhidraClass() throws StabsParseException {
		String nsPath;
		try {
			DemangledFunction fun = getCtor();
			if (fun == null || fun.getNamespace() == null) {
				return getNextAvailableGc();
			}
			nsPath = toNamespace(fun);
		} catch (StabsParseException e) {
			// We have no namespace information and no template information. Makeup a namespace.
			return getNextAvailableGc();
		}
		try {
			Namespace ns = NamespaceUtils.createNamespaceHierarchy(
				nsPath, null, program, SourceType.IMPORTED);
			if (!(ns instanceof GhidraClass)) {
				ns = NamespaceUtils.convertNamespaceToClass(ns);
			}
			return (GhidraClass) ns;
		} catch (InvalidInputException e) {
			// if the input is invalid then so is the stab
			throw new StabsParseException(name, stab);
		}
	}

	private void doAddBases() {
		// c++ unions cannot inherit. Safe to cast to Structure
		Structure struct = (Structure) getDataType();
		for (StabsBaseClassDescriptor base : bases) {
			if (!base.isVirtual()) {
				// TODO add virtual bases once supported
				int offset = base.getOffset();
				DataType typeDt = base.getDataType();
				int length = typeDt.getLength();
				String name = String.format(SUPER_CLASS, typeDt.getName());
				String modifier = base.getModifier().getDeclaration();
				struct.insertAtOffset(offset, typeDt, length,name, modifier);
			}
		}
	}

	private void doAddMembers() throws StabsParseException {
		try {
			StabsUtils.addCompositeMembers(getDataType(), members);
		} catch (InvalidDataTypeException e) {
			throw new StabsParseException(name, stab, e);
		}
	}

	static boolean isClass(String stab) {
		if (StabsMethodSymbolDescriptor.containsMethods(stab)) {
			return true;
		}
		Pattern pattern = Pattern.compile(
			String.format(".*?:Tt(%s)=s\\d+\\!", StabsTypeNumber.TYPE_NUMBER_PATTERN));
		if (pattern.matcher(stab).lookingAt()) {
			return true;
		}
		pattern = Pattern.compile(
			String.format(":/[0129](%s)", StabsTypeNumber.TYPE_NUMBER_PATTERN));
		if (pattern.matcher(stab).find()) {
			return true;
		}
		return stab.indexOf('#') != -1 || stab.contains(CONSTRUCTOR_NAME);
	}

	/**
	 * Gets the GhidraClass for this class descriptor
	 * @return the ghidra class
	 */
	public GhidraClass getGhidraClass() {
		return gc;
	}

	/**
	 * @return the methods
	 */
	public List<StabsMethodSymbolDescriptor> getMethods() {
		return methods;
	}

	/**
	 * @return the firstBase
	 */
	public StabsTypeDescriptor getFirstBase() {
		return firstBase;
	}

	/** Potential Visibility Modifiers */
	public static enum Visibility {
		PUBLIC,
		PROTECTED,
		PRIVATE,
		NONE;

		/**
		 * Gets the visibility from the start of the stab
		 * @param stab the portion of the stab where the modifier starts
		 * @return the visibility
		 */
		public static Visibility getVisibility(CharSequence stab) {
			if (stab != null) {
				int index = stab.charAt(0) == '/' ? 1 : 0;
				return getVisibility(stab.charAt(index));
			}
			return NONE;
		}

		/**
		 * Gets the visibility from the start of the stab
		 * @param c the visibility character
		 * @return the visibility
		 */
		public static Visibility getVisibility(char c) {
			switch (c) {
				case '0':
					return PRIVATE;
				case '1':
					return PROTECTED;
				case '2':
					return PUBLIC;
				default:
					return NONE;
			}
		}

		/**
		 * Gets the declaration of this visibility modifier
		 * @return the visibility declaration or an empty string if none
		 */
		public String getDeclaration() {
			if (this == NONE) {
				return "";
			}
			return name().toLowerCase();
		}
	}
}
