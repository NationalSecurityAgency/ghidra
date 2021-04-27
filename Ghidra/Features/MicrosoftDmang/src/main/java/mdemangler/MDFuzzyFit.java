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

import ghidra.util.Msg;
import mdemangler.datatype.MDDataType;
import mdemangler.datatype.MDDataTypeParser;
import mdemangler.functiontype.MDFunctionType;
import mdemangler.typeinfo.MDTypeInfo;
import mdemangler.typeinfo.MDTypeInfoParser;

/**
 * This class is still not used and might be turned into a derivative of the MDMang class.
 * The intention is to have a class that can be used to explore a symbol that cannot currently
 * be parsed into portions of already-recognizable components by trying to apply these
 * components against different offsets within a mangled string.
 * The details of this class are still vague and incomplete.
 */
// TODO: consider making this an MDMang extension.
public class MDFuzzyFit {
	// private String mangled;
	private int numCharsRemaining = 0;
	// private String errorMessage = "";

	// private Class<? extends MDParsableItem> ClassMyType;
	private List<Class<? extends MDParsableItem>> classList = new ArrayList<>();

	public MDFuzzyFit() {
		// Add the various classes in a particular order?
		// Should we have multiple lists that are used to attack the problem in
		// a specific way?
		// What are the possible strategies (combinations of these too)?
		// * internal, contiguous strings?
		// * outside-in processing (removing internals)?
		// * more popular constructs first?
		classList.add(MDType.class); // TODO: remove
		// TODO: Figure out the factory model stuff
		classList.add(MDDataType.class); // TODO: remove; needs factory
		classList.add(MDFunctionType.class);

	}

	// 20161007: Started development--not complete. Depends on all parsable
	// types for dmang to
	// be based on MDType, which is not true yet. TODO.
	public boolean fuzz(String mangledArg) {

		Msg.info(this, "Symbol: " + mangledArg);
		Msg.info(this, "Length: " + mangledArg.length());

		int bestTypeInfoLocation = getBestTypeInfoLocation(mangledArg);
		Msg.info(this, "Best type location: " + bestTypeInfoLocation);

		int bestTypeLocation = getBestTypeLocation(mangledArg);
		Msg.info(this, "Best type location: " + bestTypeLocation);

		StringBuilder outputBuilder = new StringBuilder();
		if (mangledArg == null) {
			// errorMessage = "MDMang: Mangled string is null.";
			return false;
		}
		MDMang dmang = new MDMang();
		String substring;
		int offset = mangledArg.length();
		// System.out.println("Symbol: " + mangled);
		outputBuilder.append("Symbol: ");
		outputBuilder.append(mangledArg);
		while (--offset >= 0) {
			substring = mangledArg.substring(offset);
			Iterator<Class<? extends MDParsableItem>> classIter = classList.iterator();
			while (classIter.hasNext()) {
				Class<? extends MDParsableItem> tryClass = classIter.next();
				boolean pass = true;
				try {
					dmang.setMangledSymbol(substring);
					dmang.pushContext();
					numCharsRemaining = substring.length();
					MDParsableItem tryItem = createItem(tryClass, dmang);
					tryItem.parse();
					numCharsRemaining = dmang.getNumCharsRemaining();
					dmang.popContext();
					StringBuilder builder = new StringBuilder();
					tryItem.insert(builder);
					String substringDemangled = builder.toString();
					if (numCharsRemaining == 0) {
						// System.out.println("Offset: " + offset + ";
						// Class: " +
						// tryClass.getSimpleName() + "; Output:" +
						// substringDemangled);
						outputBuilder.append("Offset: ");
						outputBuilder.append(offset);
						outputBuilder.append("; Class: ");
						outputBuilder.append(tryClass.getSimpleName());
						outputBuilder.append("; Output:");
						outputBuilder.append(substringDemangled);
					}
				}
				catch (MDException e) {
					// errorMessage = e.getMessage();
					pass = false;
				}
				// errorMessage = "";
				// System.out.println("Offset: " + offset + "; Class: " +
				// tryClass.getSimpleName() + "; GoodResult: " + pass);
				outputBuilder.append("Offset: ");
				outputBuilder.append(offset);
				outputBuilder.append("; Class: ");
				outputBuilder.append(tryClass.getSimpleName());
				outputBuilder.append("; GoodResult: ");
				outputBuilder.append(pass);
			}
		}
		Msg.info(this, outputBuilder);
		return true;
	}

	private int getBestTypeInfoLocation(String mangledArg) {
		MDMang dmang = new MDMang();
		int offset = mangledArg.length();
		boolean highest = false;
		int bestOffset = offset;

		while (--offset >= 0) {
			try {
				String substring = mangledArg.substring(offset);
				dmang.setMangledSymbol(substring);
				dmang.pushContext();
				MDTypeInfo typeInfo = MDTypeInfoParser.parse(dmang, -1);
				typeInfo.parse();
				int num = dmang.getNumCharsRemaining();
				dmang.popContext();
				if (num == 0) {
					bestOffset = offset;
				}
			}
			catch (MDException mde) {
				// Ignore for now
				int a = 1;
				a = a + 1;
			}
			catch (Exception e) {
				// Ignore for now
				int a = 1;
				a = a + 1;
			}
		}

		return bestOffset;
	}

	private int getBestTypeLocation(String mangledArg) {
		MDMang dmang = new MDMang();
		int offset = mangledArg.length();
		boolean highest = false;
		int bestOffset = offset;

		while (--offset >= 0) {
			try {
				String substring = mangledArg.substring(offset);
				dmang.setMangledSymbol(substring);
				dmang.pushContext();
				MDDataType type = MDDataTypeParser.parseDataType(dmang, highest);
				type.parse();
				int num = dmang.getNumCharsRemaining();
				dmang.popContext();
				if (num == 0) {
					bestOffset = offset;
				}
			}
			catch (MDException mde) {
				// Ignore for now
				int a = 1;
				a = a + 1;
			}
			catch (Exception e) {
				// Ignore for now
				int a = 1;
				a = a + 1;
			}
		}

		return bestOffset;
	}

	private MDParsableItem createItem(Class<? extends MDParsableItem> clazz, MDMang dmang)
			throws MDException {
		Class<?>[] constructorClassArgs = new Class[1];
		constructorClassArgs[0] = MDMang.class;
		Constructor<? extends MDParsableItem> constructor;
		try {
			constructor = clazz.getDeclaredConstructor(constructorClassArgs);
		}
		catch (SecurityException e) {
			throw new MDException("Security exception when getting constructor for class: " +
				clazz.getName() + ": " + e);
		}
		catch (NoSuchMethodException e) {
			throw new MDException("Constructor not found for class: " + clazz.getName() + ": " + e);
		}

		MDParsableItem item;
		try {
			item = constructor.newInstance(dmang);
		}
		catch (InstantiationException | IllegalAccessException | IllegalArgumentException
				| InvocationTargetException e) {
			throw new MDException("Cannot create new instance of: " + clazz.getName() + ": " + e);
		}

		return item;
	}

}

/******************************************************************************/
/******************************************************************************/
