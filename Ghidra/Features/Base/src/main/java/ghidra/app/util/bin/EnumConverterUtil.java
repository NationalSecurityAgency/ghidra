package ghidra.app.util.bin;

import ghidra.app.util.bin.StructConverterUtil;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import java.lang.reflect.Constructor;

public final class EnumConverterUtil {

	/**
	 * This is a convenience method for converting a class into an enum.
	 * The class must contain only 1 constructor which only has a single
     * primitive parameter.
	 * @param object the object to reflect
	 * @return an enum representing the class fields.
	 */
	public static <T extends EnumConverter> DataType toDataType(T object) {
		return toDataType(object.getClass());
	}

    @SuppressWarnings({"unchecked", "rawtypes"})
	public static <T extends EnumConverter> DataType toDataType(Class<T> clazz) {
        int size = 0;
        String name = parseName(clazz);
        Constructor<T>[] ctors = (Constructor<T>[]) clazz.getDeclaredConstructors();
        if (ctors.length == 1) {
            // there should only be 1 constructor
            Class<?>[] params = ctors[0].getParameterTypes();
            if (params.length == 3) {
                // there should only be 1 additional parameter. The first two are from Enum.
                // same rules apply from StructConverter
                if (params[2] == byte.class) {
                    size = 1;
                } else if (params[2] == short.class) {
                    size = 2;
                } else if (params[2] == int.class) {
                    size = 4;
                } else if (params[2] == long.class) {
                    size = 8;
                }
            }
        }
        if (size > 0) {
            Enum dt = new EnumDataType(name, size);
            for (T t : clazz.getEnumConstants()) {
                dt.add(((java.lang.Enum)t).name(), t.getValue());
            }
            return dt;
        }
        return null;
	}

	public static String parseName(Class<?> clazz) {
		return StructConverterUtil.parseName(clazz);
    }
}
