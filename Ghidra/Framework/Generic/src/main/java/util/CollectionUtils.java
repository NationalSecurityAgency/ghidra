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
package util;

import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * A collection of utility methods that prevent you from having to do unsafe casts of
 * {@link Collection} classes due to runtime type erasure.
 * 
 * <P>Be sure to check Apache collection utils before using this class, as it's a 
 * standard utility and often more efficient.
 * 
 * <P>Some examples:
 * <OL>
 *  <LI>{@link org.apache.commons.collections4.CollectionUtils}</LI>
 *  <LI>{@link IterableUtils}</LI>
 *  <LI>{@link IteratorUtils}</LI>
 *  <LI>{@link StringUtils#join(Iterable, char)} - for pretty printing collections with newlines</LI>
 *  <LI><code>Apache CollectionUtils.collect(Collection, Transformer)</code> - to turn a 
 *      collection in to collection of strings when the default <code>toString()</code> is lacking</LI>
 * </OL>
 */
public class CollectionUtils {

	private CollectionUtils() {
		// utility class; can't create
	}

	/**
	 * Turns the given items into a set.  If there is only a single item and it is null, then
	 * an empty set will be returned.
	 * 
	 * @param items the items to put in the set
	 * @return the list of items
	 */
	@SafeVarargs
	public static <T> Set<T> asSet(T... items) {
		Set<T> set = new HashSet<>();
		if (items == null) {
			return set;
		}

		if (items.length == 1 && items[0] == null) {
			return set;
		}

		for (T e : items) {
			set.add(e);
		}
		return set;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static <T> Set<T> asSet(Collection<T> c) {
		if (c instanceof Set) {
			return (Set) c;
		}
		if (c == null) {
			return new HashSet<>();
		}

		return new HashSet<>(c);
	}

	/**
	 * Drains the given iterator into a new Set
	 * 
	 * @param it the iterator 
	 * @return the set
	 */
	public static <T> Set<T> asSet(Iterator<T> it) {
		Set<T> set = new HashSet<>();
		if (it == null) {
			return set;
		}

		while (it.hasNext()) {
			T t = it.next();
			set.add(t);
		}
		return set;
	}

	/**
	 * Turns the given iterable into a new Set, returning it directly if it is a set, draining
	 * it into a set if it is not already. 
	 * 
	 * @param iterable the iterable 
	 * @return the set
	 */
	public static <T> Set<T> asSet(Iterable<T> iterable) {
		if (iterable instanceof Set) {
			return (Set<T>) iterable;
		}

		Set<T> set = new HashSet<>();
		if (iterable == null) {
			return set;
		}

		Iterator<T> it = iterable.iterator();
		while (it.hasNext()) {
			T t = it.next();
			set.add(t);
		}
		return set;
	}

	/**
	 * Similar to {@link Arrays#asList(Object...)}, except that this method will turn a single
	 * null parameter into an empty list.  Also, this method creates a new, mutable array, 
	 * whereas the former's array is not mutable.
	 * 
	 * @param items the items to add to the list
	 * @return the list
	 */
	@SafeVarargs
	public static <T> List<T> asList(T... items) {
		List<T> list = new ArrayList<>();
		if (items == null) {
			return list;
		}

		if (items.length == 1 && items[0] == null) {
			return list;
		}

		for (T arrayElement : items) {
			list.add(arrayElement);
		}

		return list;
	}

	/**
	 * Returns the given list if not null, otherwise returns an empty list. This is
	 * useful for clients avoid null checks.
	 *
	 * @param list the list to check
	 * @return a non-null collection
	 */
	public static <T> List<T> asList(List<T> list) {
		if (list == null) {
			return new ArrayList<>();
		}
		return list;
	}

	/**
	 * A convenient way to check for null and whether the given collection is a {@link List}.
	 * If the value is a list, then it is returned.  If the value is null, an empty list is
	 * returned.  Otherwise, a new list is created from the given collection.
	 *
	 * @param c the collection to check
	 * @return a list
	 */
	public static <T> List<T> asList(Collection<T> c) {
		if (c instanceof List) {
			return (List<T>) c;
		}
		if (c == null) {
			return new ArrayList<>();
		}
		return new ArrayList<>(c);
	}

	/**
	 * Returns the given collection if not null, an empty collection (a Set) otherwise.  This is
	 * useful for clients avoid null checks.
	 *
	 * @param c the collection to check
	 * @return a non-null collection
	 */
	public static <T> Collection<T> nonNull(Collection<T> c) {
		return asCollection(c);
	}

	/**
	 * Returns the given collection if not null, an empty collection otherwise.  This is
	 * useful for clients avoid null checks.
	 *
	 * @param c the collection to check
	 * @return a non-null collection
	 */
	public static <T> Collection<T> asCollection(Collection<T> c) {
		if (c == null) {
			return new HashSet<>();
		}
		return c;
	}

	public static <T> List<T> asList(Enumeration<T> enumeration) {
		List<T> list = new ArrayList<>();
		if (enumeration == null) {
			return list;
		}

		while (enumeration.hasMoreElements()) {
			T t = enumeration.nextElement();
			list.add(t);
		}
		return list;
	}

	public static <T> List<T> asList(Iterable<T> it) {
		return asList(it.iterator());
	}

	public static <T> List<T> asList(Iterator<T> it) {
		List<T> list = new ArrayList<>();
		if (it == null) {
			return list;
		}

		while (it.hasNext()) {
			T t = it.next();
			list.add(t);
		}
		return list;
	}

	/**
	 * Checks that the elements in the given list are of the type specified by <code>clazz</code>
	 * and then casts the list to be of the specified type.
	 *
	 * @param list  the source list
	 * @param clazz the class of T
	 * @return a casted list of type T
	 * @throws IllegalArgumentException if the given list contains elements that are not of the
	 *         type specified by <code>clazz</code>.
	 */
	@SuppressWarnings("unchecked")
	// we checked the elements of the list
	public static <T> List<T> asList(List<?> list, Class<T> clazz) {

		if (list == null) {
			return new ArrayList<>();
		}

		for (Object object : list) {
			if (!clazz.isAssignableFrom(object.getClass())) {
				throw new IllegalArgumentException("Given list contains data that is not " +
					"the type: " + clazz + ".  Value: " + object.getClass());
			}
		}

		return (List<T>) list;
	}

	/**
	 * Checks that the elements in the given collection are of the type specified by
	 * <code>clazz</code> and then casts the collection to be of the specified type.
	 *
	 * @param collection  the source collection
	 * @param clazz the class of T
	 * @return a casted list of type T
	 * @throws IllegalArgumentException if the given collection contains elements that are
	 *         not of the type specified by <code>clazz</code>.
	 */
	@SuppressWarnings("unchecked")
	// we checked the elements of the collection
	public static <T> Collection<T> asCollection(Collection<?> collection, Class<T> clazz) {
		for (Object object : collection) {
			if (!clazz.isAssignableFrom(object.getClass())) {
				throw new IllegalArgumentException("Given collection contains data that is not " +
					"the type: " + clazz + ".  Value: " + object.getClass());
			}
		}

		return (Collection<T>) collection;
	}

	/**
	 * Returns true if each item in the list is of type clazz.
	 * @param <T>     the type
	 * @param list    the list to inspect
	 * @param clazz   the class type
	 * @return true if each item in the list is of type clazz
	 */
	public static <T> boolean isAllSameType(Collection<?> list, Class<T> clazz) {
		for (Object object : list) {
			if (!clazz.isAssignableFrom(object.getClass())) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if the given item is in the collection of possible items
	 *
	 * @param t the item in question
	 * @param possibles the set of things
	 * @return true if the given item is in the collection of possible items
	 */
	@SafeVarargs // this is safe, as we are only using Object methods
	public static <T> boolean isOneOf(T t, T... possibles) {
		for (T possible : possibles) {
			if (Objects.equals(possible, t)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if all the given objects are null.
	 *
	 * <P>See also apache {@link ObjectUtils#anyNotNull(Object...)} and
	 * {@link ObjectUtils#allNotNull(Object...)}
	 *
	 * @param objects the objects to check
	 * @return true if all the given objects are null
	 */
	public static boolean isAllNull(Object... objects) {
		return isAllNull(Arrays.asList(objects));
	}

	/**
	 * Returns true if all the given objects are null.
	 *
	 * <P>See also apache {@link ObjectUtils#anyNotNull(Object...)} and
	 * {@link ObjectUtils#allNotNull(Object...)}
	 *
	 * @param c the objects to check
	 * @return true if all the given objects are null
	 */
	public static <T> boolean isAllNull(Collection<T> c) {
		if (c == null) {
			return true;
		}

		for (T t : c) {
			if (t != null) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if the given array is null or has 0 length
	 * 
	 * @param c the collection to check
	 * @return true if blank
	 */
	public static <T> boolean isBlank(Collection<T> c) {
		return c == null || c.isEmpty();
	}

	/**
	 * Returns true if the given array is null or has 0 length
	 * 
	 * @param t the items to check
	 * @return true if blank
	 */
	@SuppressWarnings("unchecked")
	public static <T> boolean isBlank(T... t) {
		return t == null || t.length == 0;
	}

	/**
	 * Turns the given item into an iterable
	 * @param t the object from which to create an iterable
	 * @return an iterable over the given iterator
	 */
	public static <T> Iterable<T> asIterable(T t) {
		return Arrays.asList(t);
	}

	/**
	 * Returns an iterable over an iterator
	 * @param iterator the iterator to create an iterable from
	 * @return an iterable over the given iterator
	 */
	public static <T> Iterable<T> asIterable(Iterator<T> iterator) {
		return () -> iterator;
	}

	/**
	 * Combines all collections passed-in into a pass-through not creating a new collection) 
	 * Iterable.
	 * 
	 * @param iterables the iterables to combine
	 * @return the iterable
	 */
	@SafeVarargs
	public static <T> Iterable<T> asIterable(Iterable<T>... iterables) {
		Stream<T> s = asStream(iterables);
		return asIterable(s.iterator());
	}

	/**
	 * Turns the given iterator into a stream
	 * 
	 * @param iterator the iterator
	 * @return the stream
	 */
	public static <T> Stream<T> asStream(Iterator<T> iterator) {
		return asStream(asIterable(iterator));
	}

	/**
	 * Combines all iterables passed-in into a pass-through (not creating a new collection) Stream. 
	 * 
	 * @param iterables the iterables to combine 
	 * @return the stream
	 */
	@SafeVarargs
	public static <T> Stream<T> asStream(Iterable<T>... iterables) {
		Stream<T> s = Stream.of(iterables)
				.flatMap(e -> StreamSupport.stream(e.spliterator(), false));
		return s;
	}

	/**
	 * Returns an element from the given collection; null if the collection is null or empty.
	 * This is meant for clients that have a collection with any number of items and just need
	 * to get one.
	 *
	 * @param c the collection
	 * @return the item
	 */
	public static <T> T any(Collection<T> c) {
		return any((Iterable<T>) c);
	}

	/**
	 * Returns an element from the given iterable; null if the iterable is null or empty.
	 * This is meant for clients that have a collection with any number of items and just need
	 * to get one.
	 *
	 * @param iterable the items
	 * @return the item
	 */
	public static <T> T any(Iterable<T> iterable) {
		if (iterable == null) {
			return null;
		}

		Iterator<T> iterator = iterable.iterator();
		if (iterator.hasNext()) {
			return iterator.next();
		}
		return null;
	}
}
