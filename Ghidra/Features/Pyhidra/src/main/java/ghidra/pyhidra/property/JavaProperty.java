package ghidra.pyhidra.property;

/**
 * Property interface for creating a Python property for getters and setters.
 *
 * Each implementation is required to have a defined fget method which returns
 * the corresponding primitive type. By doing so we can utilize Python duck typing,
 * auto boxing/unboxing and the Jpype conversion system to automatically convert
 * the primitive return types to the equivalent Python type. This removes the
 * headache of having to carefully and explicitly cast things to an int to
 * avoid exceptions in Python code related to type conversion or type attributes.
 *
 * The fget and fset methods are named to correspond with the fget and fset members
 * of Python's property type.
 */
public sealed interface JavaProperty<T> permits AbstractJavaProperty {

	/**
	 * The method to be used as the fset value for a Python property.
	 *
	 * This method will be called by the Python property __set__ function.
	 *
	 * @param self the object containing the property
	 * @param value the value to be set
	 * @throws Throwable if any exception occurs while setting the value
	 */
	public abstract void fset(Object self, T value) throws Throwable;
}
