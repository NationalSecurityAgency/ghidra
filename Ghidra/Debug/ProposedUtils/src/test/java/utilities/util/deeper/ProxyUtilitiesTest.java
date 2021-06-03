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
package utilities.util.deeper;

import static org.junit.Assert.assertEquals;

import java.lang.invoke.MethodHandles;
import java.util.List;

import org.junit.Test;

import utilities.util.ProxyUtilities;

// NOTE: This class is one package deeper to ensure access permissions work correctly
public class ProxyUtilitiesTest {

	interface RootIf {

	}

	interface AFeatureIf extends RootIf {
		String prependA();

		default String callPrependA() {
			return prependA();
		}
	}

	interface BFeatureIf extends RootIf {
		String prependB();
	}

	interface ExtRootIf extends RootIf {
		String getCommonThing();
	}

	interface ExtAFeatureIf extends AFeatureIf, ExtRootIf {
		@Override
		default String prependA() {
			return "A: " + getCommonThing();
		}
	}

	interface ExtBFeatureIf extends BFeatureIf, ExtRootIf {
		@Override
		default String prependB() {
			return "B: " + getCommonThing();
		}
	}

	@Test
	public void testComposeOnDelegate() {
		ExtRootIf composed = ProxyUtilities.composeOnDelegate(ExtRootIf.class, new ExtRootIf() {
			@Override
			public String getCommonThing() {
				return "Hello, World!";
			}
		}, List.of(ExtAFeatureIf.class, ExtBFeatureIf.class), MethodHandles.lookup());
		assertEquals("Hello, World!", composed.getCommonThing());
		AFeatureIf a = (AFeatureIf) composed;
		assertEquals("A: Hello, World!", a.prependA());
		BFeatureIf b = (BFeatureIf) composed;
		assertEquals("B: Hello, World!", b.prependB());
	}

	@Test
	public void testComposedOnDelegatePolymorphic() {
		ExtRootIf composed = ProxyUtilities.composeOnDelegate(ExtRootIf.class, new ExtRootIf() {
			@Override
			public String getCommonThing() {
				return "Hello, World!";
			}
		}, List.of(ExtAFeatureIf.class), MethodHandles.lookup());
		assertEquals("Hello, World!", composed.getCommonThing());
		AFeatureIf a = (AFeatureIf) composed;
		assertEquals("A: Hello, World!", a.prependA());
		assertEquals("A: Hello, World!", a.callPrependA());
	}
}
