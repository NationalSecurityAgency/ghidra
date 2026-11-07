package ghidra.app.util.bin.format.stabs.types;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Scanner;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.util.bin.format.stabs.*;
import ghidra.app.util.bin.format.stabs.cpp.StabsMemberSymbolDescriptor;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import static ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER;

/**
 * Composite Type (Structure, Union, Enum) implementation of the StabTypeDescriptor
 */
public final class StabsCompositeTypeDescriptor extends AbstractStabsTypeDescriptor {

	private static final Pattern ENUM_SPLITTER = Pattern.compile("([^:]*):(\\d+),?;?");
	private static final Pattern COMPOSITE_START = Pattern.compile("=?([su]\\d+)");

	private DataType dt;
	private int anonCount = 0;
	private final String typeStab;
	private final List<StabsMemberSymbolDescriptor> members;

	// Internal use only
	public static StabsCompositeTypeDescriptor getNamedDescriptor(
		StabsCompositeSymbolDescriptor token, String stab) throws StabsParseException {
			return new StabsCompositeTypeDescriptor(token, stab);
	}

	/**
	 * Constructs a new StabsCompositeTypeDescriptor
	 * @param token the token this descriptor is located in
	 * @param stab the portion of the stab containing this descriptor
	 * @throws StabsParseException if the descriptor or one it relies on is invalid
	 */
	StabsCompositeTypeDescriptor(StabsSymbolDescriptor token, String stab) throws StabsParseException {
		super(token, stab);
		this.typeStab = stab;
		if (token instanceof AbstractStabsSymbolDescriptor) {
			anonCount = ((AbstractStabsSymbolDescriptor) token).getNextAnonCount();
		}
		this.dt = createAnonymousDt();
		this.members = doGetMembers();
		parseMembers();
	}

	private StabsCompositeTypeDescriptor(StabsCompositeSymbolDescriptor token, String stab)
			throws StabsParseException {
		super(token, token.getStab());
		String subStab = token.getStab().substring(token.getName().length());
		StabsTypeNumber typeNumber = new StabsTypeNumber(subStab);
		// incase we have a reference to ourselves
		file.addType(this, typeNumber);
		this.typeStab = stab;
		this.dt = token.getDataType();
		this.members = doGetMembers();
		parseMembers();
	}

	private void parseMembers() throws StabsParseException {
		try {
			StabsUtils.addCompositeMembers(dt, members);
		} catch (InvalidDataTypeException e) {
			throw new StabsParseException(symbol.getName(), stab, e);
		}
	}

	private DataType createAnonymousDt() throws StabsParseException {
		DataType initDt = null;
		CategoryPath path = symbol.getFile().getCategoryPath();
		String typeName;
		switch (typeStab.charAt(0)) {
			case 'e':
				typeName = String.format(
					"anon_enum_%s_%d", symbol.getName().replaceAll(" ", "_"), anonCount);
				initDt = parseEnum(typeStab, typeName, path, dtm);
				break;
			case 's':
				typeName = String.format(
					"anon_struct_%s_%d", symbol.getName().replaceAll(" ", "_"), anonCount);
				initDt = new StructureDataType(path, typeName, 0, dtm);
				break;
			case 'u':
				typeName = String.format(
					"anon_union_%s_%d", symbol.getName().replaceAll(" ", "_"), anonCount);
				initDt = new UnionDataType(path, typeName, dtm);
				break;
			default:
				break;
		}
		if (initDt != null) {
			return dtm.resolve(initDt, REPLACE_HANDLER);
		}
		throw new StabsParseException(symbol.getName(), typeStab);
	}

	// internal use only
	public static DataType parseEnum(String typeStab, String name,
		CategoryPath path, DataTypeManager dtm) {
			if (name.equals("")) {
				name = String.format("anon_enum_%s", path.getName());
			}
			Enum mune = new EnumDataType(path, name, getEnumSize(typeStab), dtm);
			// skip past the 'e'
			try (Scanner scanner = new Scanner(typeStab.substring(1))) {
				scanner.findAll(ENUM_SPLITTER).forEach(
					(result) -> mune.add(result.group(1), Long.valueOf(result.group(2))));
			}
			return mune;
	}

	private static int getEnumSize(String typeStab) {
		try (Scanner scanner = new Scanner(typeStab)) {
			Optional<Long> max = scanner.findAll("\\d+")
										.map(MatchResult::group)
										.map(Long::valueOf)
										.collect(Collectors.maxBy(Long::compare));
			if (max.isPresent()) {
				return StabsUtils.getIntegerSize(max.get());
			}
		}
		return 1;
	}

	private String getCompositeStart() {
		Matcher matcher = COMPOSITE_START.matcher(typeStab);
		if (matcher.lookingAt()) {
			return typeStab.substring(matcher.end());
		}
		return typeStab;
	}

	private List<StabsMemberSymbolDescriptor> doGetMembers() throws StabsParseException {
		if (dt instanceof Composite) {
			return StabsMemberSymbolDescriptor.getMembers(symbol, getCompositeStart());
		}
		return Collections.emptyList();
	}

	@Override
	public DataType getDataType() {
		return dt;
	}

	@Override
	public StabsTypeDescriptorType getType() {
		return StabsTypeDescriptorType.COMPOSITE;
	}

	@Override
	public int getLength() {
		int index = stab.indexOf(typeStab);
		return index + members.stream()
							  .mapToInt(StabsMemberSymbolDescriptor::getLength)
							  .sum();
	}
}
