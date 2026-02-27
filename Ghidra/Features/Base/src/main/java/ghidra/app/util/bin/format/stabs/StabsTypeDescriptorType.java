package ghidra.app.util.bin.format.stabs;

/**
 * Enum constants for possible Stab Type Descriptor Types
 */
public enum StabsTypeDescriptorType {
	/** Reference to a previously parsed Type Descriptor */
	TYPE_REFERENCE,
	/** Builtin Types int, float, etc. */
	BUILTIN,
	/** C++ Class Methods */
	METHOD,
	/** Pointers and References */
	REFERENCE,
	/** AIX Type Attribute */
	TYPE_ATTRIBUTE,
	/** Array Type */
	ARRAY,
	/** Cobol Picture Type */
	COBOL,
	/** Function Type */
	FUNCTION,
	/** String Type */
	STRING,
	/** Opaque Type */
	OPAQUE,
	/** Range Types*/
	RANGE,
	/** Miscellaneous Type */
	MISC,
	/** Structure, Union or Enum Type */
	COMPOSITE,
	/** Forward Declaration for a Structure, Union or Enum */
	CROSS_REFERENCE;
}
