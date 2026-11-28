package ghidra.app.util.bin.format.stabs;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.format.stabs.cpp.StabsMemberSymbolDescriptor;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Program;

public class StabsUtils {

	private static final Map<String, DataType> BUILTIN_TYPES = Map.ofEntries(
		Map.entry("int", IntegerDataType.dataType),
		Map.entry("char", CharDataType.dataType),
		Map.entry("void", VoidDataType.dataType),
		Map.entry("long int", LongDataType.dataType),
		Map.entry("unsigned int", UnsignedIntegerDataType.dataType),
		Map.entry("long unsigned int", UnsignedLongDataType.dataType),
		Map.entry("long long int", LongLongDataType.dataType),
		Map.entry("long long unsigned int", UnsignedLongLongDataType.dataType),
		Map.entry("short int", ShortDataType.dataType),
		Map.entry("short unsigned int", UnsignedShortDataType.dataType),
		Map.entry("signed char", SignedCharDataType.dataType),
		Map.entry("unsigned char", UnsignedCharDataType.dataType),
		Map.entry("float", FloatDataType.dataType),
		Map.entry("double", DoubleDataType.dataType),
		Map.entry("long double", LongDataType.dataType),
		Map.entry("complex float", FloatComplexDataType.dataType),
		Map.entry("complex double", DoubleComplexDataType.dataType),
		Map.entry("complex long double", LongDoubleComplexDataType.dataType),
		Map.entry("__float128", Float16DataType.dataType),
		Map.entry("__int128 unsigned", UnsignedInteger16DataType.dataType),
		Map.entry("__int128", Integer16DataType.dataType),
		Map.entry("__int128_t", Integer16DataType.dataType),
		Map.entry("__uint128_t", UnsignedInteger16DataType.dataType),
		Map.entry("char16_t", WideChar16DataType.dataType),
		Map.entry("char32_t", WideChar32DataType.dataType),
		Map.entry("bool", BooleanDataType.dataType),
		Map.entry("wchar_t", WideCharDataType.dataType),
		Map.entry("__wchar_t", WideCharDataType.dataType)
	);

	private StabsUtils() {
		// static utility class
	}

	/**
	 * Checks if the program was compiled by gcc
	 * @param program the program
	 * @return true if copiled by gcc
	 */
	public static boolean isGnu(Program program) {
		// copied from GnuDemangler#canDemangle
		String executableFormat = program.getExecutableFormat();
		if (isELF(executableFormat) || isMacho(executableFormat)) {
			return true;
		}

		//check if language is GCC
		CompilerSpec compilerSpec = program.getCompilerSpec();
		if (compilerSpec.getCompilerSpecID().getIdAsString().toLowerCase().indexOf(
			"windows") == -1) {
			return true;
		}
		return false;
	}

	private static boolean isELF(String executableFormat) {
		// copied from GnuDemangler
		return executableFormat != null && executableFormat.indexOf(ElfLoader.ELF_NAME) != -1;
	}

	private static boolean isMacho(String executableFormat) {
		// copied from GnuDemangler
		return executableFormat != null && executableFormat.indexOf(MachoLoader.MACH_O_NAME) != -1;
	}

	/**
	 * Gets the number of bytes required for the integer value
	 * @param value the value to get the size of
	 * @return the size of the value in bytes
	 */
	public static int getIntegerSize(long value) {
		int i = 0;
		do {
			i++;
			value >>= Byte.SIZE;
		} while (value != 0);
		return i;
	}

	/**
	 * Gets the number of bytes required for the integer value
	 * @param value the value to get the size of
	 * @return the size of the value in bytes
	 */
	public static int getIntegerSize(BigInteger value) {
		int i = 0;
		do {
			i++;
			value = value.shiftRight(Byte.SIZE);
		} while (value.compareTo(BigInteger.ZERO) != 0);
		return i;
	}

	/**
	 * Checks if the type name is a builtin type
	 * @param typeName the type name
	 * @return true if a builtin type name
	 */
	public static boolean isBuiltin(String typeName) {
		return BUILTIN_TYPES.containsKey(typeName);
	}

	/**
	 * Gets the builtin type of the type name
	 * @param typeName the type name
	 * @return the builtin data type
	 */
	public static DataType getBuiltin(String typeName) {
		if (isBuiltin(typeName)) {
			return BUILTIN_TYPES.get(typeName);
		}
		return null;
	}

	/**
	 * Adds the members to the DataType only if the DataType is a Composite
	 * @param dt the datatype
	 * @param members the members to add
	 * @throws InvalidDataTypeException if the member is determined to be a bitfield
	 * but is not a valid bitfield datatype.
	 */
	public static void addCompositeMembers(DataType dt, List<StabsMemberSymbolDescriptor> members)
		throws InvalidDataTypeException {
			if (!(dt instanceof Composite)) {
				return;
			}
			// c++ unions are classes. Must cast to Composite
			Composite comp = (Composite) dt;
			for (StabsMemberSymbolDescriptor member : members) {
				String name = member.getName();
				String modifier = member.getModifier().getDeclaration();
				if (modifier.isEmpty()) {
					modifier = null;
				}
				DataType compDt = member.getDataType();
				int bitOffset = member.getBitPosition();
				int bitSize = member.getBitSize();
				if (isBitfield(bitOffset, bitSize)) {
					if (BitFieldDataType.isValidBaseDataType(compDt)) {
						comp.addBitField(compDt, bitSize, name, modifier);
					}
				} else if (comp instanceof Structure && bitOffset >= 0 && bitSize > 0) {
					// if we know where it should be, ensure it goes there
					// right shift by 3 to convert bit offset/size to byte offset/size
					((Structure) comp).insertAtOffset(
						bitOffset >> 3, compDt, bitSize >> 3, name, modifier);
				} else if (member.isFlexibleArray()) {
					((Structure) comp).setFlexibleArrayComponent(compDt, name, modifier);
				} else {
					comp.add(compDt, name, modifier);
				}
			}
	}

	private static boolean isBitfield(int bitOffset, int bitSize) {
		if (bitOffset < 0 || bitSize < 0) {
			return false;
		}
		return (bitOffset % Byte.SIZE != 0) || (bitSize % Byte.SIZE != 0);
	}
}
