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
package docking.widgets.table.constraint;

import java.util.List;
import java.util.Objects;

import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;
import ghidra.util.classfinder.ExtensionPoint;
import utilities.util.reflection.ReflectionUtilities;

/**
 * ColumnConstraintTypeMappers allows columns of one type be filterable using an existing {@link ColumnConstraint}
 * for a different type by defining a  mapping from the column type to the desired
 * filter type. To get the benefit of one of these mappers, all that is required is to implement
 * one of these mappers.  The mapper class must be public and it's name must end in "TypeMapper".
 *
 * <P>
 * For example, if you have a column type of "Person" that holds various information about a person
 * including their age and you want to filter on their age, you could define a ColumnTypeMapper that
 * converts a "Person" to an int.  Just by creating such a mapper class, any table with "Person"
 * column types would now be able to filter on a person's age.
 * <P>
 * In the example above, you created a filter of a single attribute of person.  If, however, you
 * want more than that, you could instead create a new {@link ColumnConstraint} that filters on
 * more attributes of a Person.  See {@link NumberColumnConstraintProvider} for an example
 * of how to create these ColumnConstraints and their associated editors.
 * <P>
 * @param <T> The column type that has no inherent {@link ColumnConstraint} for filtering that
 * column type.
 * @param <M> The column type to map to that already has {@link ColumnConstraint}s defined
 * for that type.
 */
public abstract class ColumnTypeMapper<T, M> implements ExtensionPoint {

	private Class<T> sourceType;
	private Class<M> destinationType;

	public ColumnTypeMapper() {
		sourceType = findSourceType();
		destinationType = findDestinationType();
	}

	protected ColumnTypeMapper(Class<T> sourceType, Class<M> destinationType) {
		this.sourceType = sourceType;
		this.destinationType = destinationType;
	}

	@Override
	public int hashCode() {
		return Objects.hash(sourceType, destinationType);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ColumnTypeMapper<?, ?> other = (ColumnTypeMapper<?, ?>) obj;
		return destinationType == other.destinationType && sourceType == other.sourceType;
	}

	/**
	 * Converts an object of type T1 to an object of type T2
	 * @param value the object to convert.
	 * @return the converted object.
	 */
	public abstract M convert(T value);

	/**
	 * Returns the class of the objects that this mapper will convert from.
	 * @return  the class of the objects that this mapper will convert from.
	 */
	public final Class<T> getSourceType() {
		return sourceType;
	}

	/**
	 * Returns the class of the objects that this mapper will convert to.
	 * @return  the class of the objects that this mapper will convert to.
	 */
	public final Class<M> getDestinationType() {
		return destinationType;
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// guaranteed by compile constraints
	private Class<T> findSourceType() {
		Class<? extends ColumnTypeMapper> implementationClass = getClass();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(ColumnTypeMapper.class, implementationClass);
		return (Class<T>) typeArguments.get(0);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// guaranteed by compile constraints
	private Class<M> findDestinationType() {
		Class<? extends ColumnTypeMapper> implementationClass = getClass();
		List<Class<?>> typeArguments =
			ReflectionUtilities.getTypeArguments(ColumnTypeMapper.class, implementationClass);
		return (Class<M>) typeArguments.get(1);
	}

}
