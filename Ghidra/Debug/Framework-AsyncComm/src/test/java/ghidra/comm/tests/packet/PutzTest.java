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
package ghidra.comm.tests.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.TypeUtils;
import org.junit.Ignore;
import org.junit.Test;

public class PutzTest {
	public static class MyList extends ArrayList<Integer> {
		//
	}

	public static class MyList2 implements Collection<Integer> {

		@Override
		public int size() {
			// TODO Auto-generated method stub
			return 0;
		}

		@Override
		public boolean isEmpty() {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean contains(Object o) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public Iterator<Integer> iterator() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public Object[] toArray() {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public <T> T[] toArray(T[] a) {
			// TODO Auto-generated method stub
			return null;
		}

		@Override
		public boolean add(Integer e) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean remove(Object o) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean containsAll(Collection<?> c) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean addAll(Collection<? extends Integer> c) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean removeAll(Collection<?> c) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public boolean retainAll(Collection<?> c) {
			// TODO Auto-generated method stub
			return false;
		}

		@Override
		public void clear() {
			// TODO Auto-generated method stub

		}

	}

	public List<Integer> f1;
	public MyList f2;

	@SuppressWarnings("unchecked")
	@Test
	public <E> void testColType() throws NoSuchFieldException, SecurityException {
		Field field;
		Class<? extends Collection<E>> colType;

		field = PutzTest.class.getField("f1");
		colType = (Class<? extends Collection<E>>) field.getType();

		System.out.println("a:" + colType);
		System.out.println("b:" + colType.getComponentType());
		System.out.println("c:" + colType.getTypeName());
		System.out.println("d:" + StringUtils.join(colType.getGenericInterfaces(), ","));
		System.out.println("e:" + StringUtils.join(colType.getTypeParameters(), ","));
		System.out.println("g:" + colType.getGenericSuperclass());
		System.out.println();

		field = PutzTest.class.getField("f2");
		colType = (Class<? extends Collection<E>>) field.getType();

		System.out.println("a:" + colType);
		System.out.println("b:" + colType.getComponentType());
		System.out.println("c:" + colType.getTypeName());
		System.out.println("d:" + StringUtils.join(colType.getGenericInterfaces(), ","));
		System.out.println("e:" + StringUtils.join(colType.getTypeParameters(), ","));
		Class<?> supType = colType.getSuperclass();
		System.out.println("f:" + supType);
		System.out.println("g:" + colType.getGenericSuperclass());
		System.out.println();

		System.out.println("h:" + StringUtils.join(MyList2.class.getGenericInterfaces(), ","));
		System.out.println("i:" + StringUtils.join(MyList.class.getGenericInterfaces(), ","));
		System.out.println();

		Map<TypeVariable<?>, Type> args =
			TypeUtils.getTypeArguments(MyList.class, Collection.class);
		System.out.println("a:" + args);
		System.out.println("b:" + TypeUtils.getTypeArguments(MyList2.class, Collection.class));

		for (Map.Entry<TypeVariable<?>, Type> ent : args.entrySet()) {
			System.out.println(ent.getKey().getGenericDeclaration());
			System.out.println(ent.getKey().getName());
		}
	}

	public static interface MyI1<T> {
		void someMethod(T t);
	}

	public static interface MyBound1 {
		//
	}

	public static interface MyArg1 extends MyBound1 {
		//
	}

	public static interface MyI2<T extends MyBound1> extends MyI1<T> {
		//
	}

	public static interface MyI3 extends MyI2<MyArg1> {
		//
	}

	public static class MyC1 implements MyI3 {

		@Override
		public void someMethod(MyArg1 t) {
			// TODO Auto-generated method stub

		}

	}

	protected void dumpTypeArguments(Class<?> cls, Map<TypeVariable<?>, Type> map) {
		for (Entry<TypeVariable<?>, Type> entry : map.entrySet()) {
			System.out.println(entry.getValue());
			System.out.println("  val:" + entry.getValue());
			System.out.println("  cls:" + entry.getValue().getClass());
			System.out.println("  raw:" + TypeUtils.getRawType(entry.getValue(), cls));
			System.out.println("  bnd:" + StringUtils.join(entry.getKey().getBounds(), ","));
		}
	}

	@Test
	public void testTypes() {
		dumpTypeArguments(MyI2.class, TypeUtils.getTypeArguments(MyI2.class, MyI1.class));
		//TypeUtils.typesSatisfyVariables(typeVarAssigns);
		for (Method m : MyI2.class.getMethods()) {
			System.out.println(m);
		}
		for (Method m : MyI3.class.getMethods()) {
			System.out.println(m);
		}
		for (Method m : MyC1.class.getMethods()) {
			System.out.println(m);
		}
	}

	@Test
	public void testNumber() {
		System.out.println(Number.class.isAssignableFrom(Integer.class));
		System.out.println(Number.class.isAssignableFrom(int.class));
	}

	public static enum EnumTest {
		ZERO, ONE, TWO, THREE;
	}

	@Test
	public void testEnum() {
		Object et = EnumTest.TWO;

		System.out.println(et.getClass().isEnum());
		Enum<?> e = (Enum<?>) et;
		System.out.println(e.name());
		System.out.println(e.ordinal());

		for (Enum<?> ec : e.getClass().getEnumConstants()) {
			System.out.println(ec);
		}
	}

	@Test
	public void testASCII() {
		Charset cs = Charset.forName("ASCII");
		System.out.println(cs);
	}

	@Ignore
	@Test
	public void testMatcherMutable() {
		Pattern pat = Pattern.compile("#");
		Matcher mat = pat.matcher("Test#aa");
		assertTrue(mat.find());

		StringBuilder buf = new StringBuilder();
		buf.append("Test#aa");
		System.out.println(buf);
		mat = pat.matcher(buf);
		assertTrue(mat.find());
		int i = mat.start();
		System.out.println(i);
		buf.append("More#bb");
		System.out.println(buf);
		assertTrue(mat.find());
		i = mat.start();
		System.out.println(i);
	}

	@Test
	public void testRegexSymbols() {
		Pattern pat = Pattern.compile("[=\\+\\-\\?]");
		Matcher mat = pat.matcher("some:string:more+");
		assertTrue(mat.find());
		assertEquals("+", mat.group());
	}

	@Test
	public void testSpeedFormat() {
		System.out.println(Integer.toHexString(23));
		long start = System.currentTimeMillis();
		for (int i = 0; i < 100000; i++) {
			@SuppressWarnings("unused")
			String ignore = StringUtils.leftPad(Integer.toHexString(i), 4, '0');
		}
		long mid = System.currentTimeMillis();
		for (int i = 0; i < 100000; i++) {
			@SuppressWarnings("unused")
			String ignore = String.format("%04x", i);
		}
		long end = System.currentTimeMillis();

		System.out.println("toHexString time: " + (mid - start));
		System.out.println("format time:      " + (end - mid));
	}

	@Test
	public void testGenerics() throws SecurityException {
		Object o = new Object() {
			@SuppressWarnings("unused")
			public Integer fieldInteger;
			@SuppressWarnings("unused")
			public int fieldInt;
			@SuppressWarnings("unused")
			public List<Integer> fieldListInteger;
		};

		for (Field f : o.getClass().getFields()) {
			System.out.println(f.getName() + ":" + f.getGenericType());
			System.out.println(TypeUtils.getRawType(f.getGenericType(), Object.class));
		}

	}
}
