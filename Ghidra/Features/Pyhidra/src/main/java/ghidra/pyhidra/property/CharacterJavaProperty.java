package ghidra.pyhidra.property;

import java.lang.invoke.MethodHandle;

/**
 * The {@link JavaProperty} for the primitive <b>char</b> type
 */
public final class CharacterJavaProperty extends AbstractJavaProperty<Character> {

	CharacterJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
		super(field, getter, setter);
	}

	/**
	 * The method to be used as the fget value for a Python property.
	 *
	 * This method will be called by the Python property __get__ function.
	 *
	 * @param self the object containing the property
	 * @return the property's value
	 * @throws Throwable if any exception occurs while getting the value
	 */
	public char fget(Object self) throws Throwable {
		return doGet(self);
	}
}
