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
package mdemangler;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * This class represents a higher level than the highest level object that maps to a Microsoft
 *  mangled symbol... this might be temporary until we can take time to study much of the facets
 *  of dotted names in much more detail.  For now, we will put each dot-separated component into
 *  a separate part for processing.
 * Some places where we have seen dotted symbols:
 *  -Symbols from load time, where the dots represent namespace delimitation
 *    -includes CLI binaries, from CliTableMethodDef: "?A0xfedcba98.blah"
 *  -LLVM has flags or attributes; e.g., ".weak." prefix on a mangled datatype name; also had
 *    suffix of ".default.__xmm@blahblahblahblahblahblahblahblah"
 */
public class MDDotSeparatedItem extends MDParsableItem {
	private List<MDParsableItem> subItems = new ArrayList<>();
	private boolean firstIsDot = false;

	public MDDotSeparatedItem(MDMang dmang) {
		super(dmang);
	}

	@Override
	protected void parseInternal() throws MDException {
		// check first character
		String whole = dmang.getMangledSymbol();
		int start = dmang.getIndex(); // better be zero... but we are not testing it
		// We know that a beginning dot is found for mangled "type" names, but perhaps this could
		//  be found for starts of flags as well.
		if (start != 0) {
			return;
		}
		firstIsDot = (dmang.peek() == '.'); // might need this
		List<String> dotStrings = Arrays.asList(whole.split("\\."));

		for (String sub : dotStrings) {
			// I don't want to use reflection, but doing so for now as we investigate.
			// The overall MDMang model revamping will take time, but is when this fix will
			//  likely occur.
			MDParsableItem subItem = null;
			try {
				Constructor<? extends MDMang> ctor = dmang.getClass().getDeclaredConstructor();
				MDMang subDmang = ctor.newInstance();
				subItem = subDmang.demangle(sub, false);
			}
			// might want to handle these separately for now... later can possibly group all
			//  together
			catch (NoSuchMethodException e) {
				e.printStackTrace();
			}
			catch (SecurityException e) {
				e.printStackTrace();
			}
			catch (InstantiationException e) {
				e.printStackTrace();
			}
			catch (IllegalAccessException e) {
				e.printStackTrace();
			}
			catch (IllegalArgumentException e) {
				e.printStackTrace();
			}
			catch (InvocationTargetException e) {
				e.printStackTrace();
			}
			subItems.add(subItem);
		}

	}

}

/******************************************************************************/
/******************************************************************************/
