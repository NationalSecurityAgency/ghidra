package ghidra.pyghidra.property;

import java.lang.invoke.MethodHandle;

/**
 * The {@link JavaProperty} for the primitive <b>float</b> type
 */
public final class FloatJavaProperty extends AbstractJavaProperty<Float> {

	FloatJavaProperty(String field, MethodHandle getter, MethodHandle setter) {
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
	public float fget(Object self) throws Throwable {
		return doGet(self);
	}
}
