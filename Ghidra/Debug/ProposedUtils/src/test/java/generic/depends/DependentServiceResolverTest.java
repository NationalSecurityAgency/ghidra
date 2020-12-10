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
package generic.depends;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import generic.depends.err.*;

public class DependentServiceResolverTest {
	public static class A {
		// Nothing here
	}

	public static class B {
		private final A a;

		public B(A a) {
			this.a = a;
		}
	}

	public static class C {
		private final A a;

		public C(A a) {
			this.a = a;
		}
	}

	public static class D {
		private final B b;
		private final C c;

		public D(B b, C c) {
			this.b = b;
			this.c = c;
		}
	}

	public static class NeedsInjectionNoExtends {
		@DependentService
		protected D d; // declared first on purpose
		@DependentService
		protected A a;
		@DependentService
		protected B b;
		@DependentService
		protected C c;

		public NeedsInjectionNoExtends() throws Exception {
			DependentServiceResolver.inject(this);
		}

		@DependentService
		private A createA() {
			return new A();
		}

		@SuppressWarnings("hiding")
		@DependentService
		private B createB(A a) {
			return new B(a);
		}

		@SuppressWarnings("hiding")
		@DependentService
		private C createC(A a) {
			return new C(a);
		}

		@SuppressWarnings("hiding")
		@DependentService
		private D createD(B b, C c) {
			return new D(b, c);
		}
	}

	@Test
	public void testNoExtends() throws Exception {
		NeedsInjectionNoExtends needs = new NeedsInjectionNoExtends();
		assertEquals(needs.c, needs.d.c);
		assertEquals(needs.b, needs.d.b);
		assertEquals(needs.a, needs.c.a);
		assertEquals(needs.a, needs.b.a);
	}

	public static class E {
		// Nothing
	}

	public static class D2 extends D {
		private final E e;

		public D2(B b, C c, E e) {
			super(b, c);
			this.e = e;
		}
	}

	public static class F {
		private final D d;
		private final D2 d2;

		public F(D d, D2 d2) {
			this.d = d;
			this.d2 = d2;
		}
	}

	public static class NeedsInjectionOverrideD extends NeedsInjectionNoExtends {
		public NeedsInjectionOverrideD() throws Exception {
			super();
		}

		@DependentService
		private E e;

		@DependentService
		private F f;

		@DependentService
		private E createE() {
			return new E();
		}

		@SuppressWarnings("hiding")
		@DependentService(override = D.class)
		private D2 createD2(B b, C c, E e) {
			return new D2(b, c, e);
		}

		@SuppressWarnings("hiding")
		@DependentService
		private F createF(D d, D2 d2) {
			return new F(d, d2);
		}
	}

	@Test
	public void testOverrideD() throws Exception {
		NeedsInjectionOverrideD needs = new NeedsInjectionOverrideD();
		assertEquals(needs.c, needs.d.c);
		assertEquals(needs.b, needs.d.b);
		assertEquals(needs.a, needs.c.a);
		assertEquals(needs.a, needs.b.a);

		assertTrue(needs.d instanceof D2);
		assertEquals(needs.e, ((D2) needs.d).e);
		assertEquals(needs.d, needs.f.d);
		assertEquals(needs.d, needs.f.d2);
	}

	public static class MyException extends Exception {
		// Nothing here
	}

	public static class NeedsInjectionExceptionThrower {
		@DependentService
		private A a;

		public NeedsInjectionExceptionThrower() throws ServiceConstructionException,
				UnsatisfiedParameterException, UnsatisfiedFieldsException {
			DependentServiceResolver.inject(this);
		}

		@DependentService
		private A createA() throws MyException {
			throw new MyException();
		}
	}

	@Test(expected = MyException.class)
	public void testException() throws Throwable {
		try {
			@SuppressWarnings("unused")
			NeedsInjectionExceptionThrower needs = new NeedsInjectionExceptionThrower();
		}
		catch (ServiceConstructionException e) {
			throw e.getCause();
		}
	}

	public static class NeedsInjectionTwoStepExceptionThrower {
		@DependentService
		private B b;
		@DependentService
		private A a;

		public NeedsInjectionTwoStepExceptionThrower() throws ServiceConstructionException,
				UnsatisfiedParameterException, UnsatisfiedFieldsException {
			DependentServiceResolver.inject(this);
		}

		@SuppressWarnings("hiding")
		@DependentService
		private B createB(A a) {
			return new B(a);
		}

		@DependentService
		private A createA() throws MyException {
			throw new MyException();
		}
	}

	@Test(expected = MyException.class)
	public void testTwoStepException() throws Throwable {
		try {
			@SuppressWarnings("unused")
			NeedsInjectionTwoStepExceptionThrower needs =
				new NeedsInjectionTwoStepExceptionThrower();
		}
		catch (ServiceConstructionException e) {
			throw e.getCause();
		}
	}

	public static class UnsatisfiedParameter {
		@DependentService
		private B b;

		public UnsatisfiedParameter() throws ServiceConstructionException,
				UnsatisfiedParameterException, UnsatisfiedFieldsException {
			DependentServiceResolver.inject(this);
		}

		@DependentService
		private B createB(A a) {
			return new B(a);
		}
	}

	@Test(expected = UnsatisfiedParameterException.class)
	public void testUnsatisfiedParamter() throws Throwable {
		@SuppressWarnings("unused")
		UnsatisfiedParameter up = new UnsatisfiedParameter();
	}

	public static class UnsatisfieldField {
		@DependentService
		private A a;

		public UnsatisfieldField() throws ServiceConstructionException,
				UnsatisfiedParameterException, UnsatisfiedFieldsException {
			DependentServiceResolver.inject(this);
		}
	}

	@Test(expected = UnsatisfiedFieldsException.class)
	public void testUnsatisfiedField() throws Throwable {
		@SuppressWarnings("unused")
		UnsatisfieldField uf = new UnsatisfieldField();
	}
}
