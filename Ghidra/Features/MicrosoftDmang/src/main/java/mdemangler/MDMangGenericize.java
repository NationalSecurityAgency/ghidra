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

import java.util.HashMap;
import java.util.Map;

import mdemangler.naming.MDFragmentName;
import mdemangler.object.MDMangObjectParser;

/**
 * A new built-from-scratch class for demangling debug symbols created using
 * Microsoft Visual Studio.
 */
public class MDMangGenericize extends MDMang {
	/*
	 * Used for creating a copy-with-substitutes of the original string
	 */
	private StringBuilder genericizedString = new StringBuilder();
	// uniqueCount must start at -1 as nextUnique() pre-creates a potential
	// fragment for use.
	private int uniqueCount = -1;
	private String nextUnique = nextUnique();
	private Map<String, String> uniqueFragments = new HashMap<>();

	// @Override
	// public MDParsableItem demangle_orig(Boolean errorOnRemainingChars) {
	// //ignoring the parameter (for now)
	// if (mangled == null) {
	// errorMessage = "MDMang: Mangled string is null.";
	// return null;
	// }
	// try {
	// pushContext();
	// item = MDMangObjectParser.parse(this);
	// numCharsRemaining = iter.getLength() - iter.getIndex();
	// appendRemainder();
	// popContext();
	// errorMessage = "";
	// }
	// catch (MDException e) {
	// errorMessage = e.getMessage();
	// item = null;
	// }
	// return item;
	// }
	@Override
	public MDParsableItem demangle(boolean errorOnRemainingChars) throws MDException {
		// ignoring the parameter (for now)
		if (mangled == null) {
			throw new MDException("MDMang: Mangled string is null.");
		}
		pushContext();
		item = MDMangObjectParser.parse(this);
		if (item != null) {
			item.parse();
		}
		int numCharsRemaining = getNumCharsRemaining();
		appendRemainder();
		popContext();
		// if (errorOnRemainingChars && (numCharsRemaining > 0)) {
		// throw new MDException(
		// "MDMang: characters remain after demangling: " + numCharsRemaining +
		// ".");
		// }
		return item;
	}

	// NOTE: we are not changing next(). Thus, the users of next() and
	// getAndIncrement() must
	// be aware that only the getAndIncrement() method will add to the
	// genericizedString. But
	// it is only users of this MDMang class extension (MDMangGeneric) that
	// would be aware of
	// these differences. Users of other MDMang extended classes or the base
	// class itself
	// would not see the problems that using one method over the other would
	// cause for the
	// users of MDMangGenericize, who need to differentiate their use of these
	// methods. Thus,
	// the MDMangGenericize users will need to make changes to use uses of the
	// two methods.
	// USES: use peek() followed by next() when not wanting to add to the
	// genericizedString.
	// Use getAndIncrement(), with or without the prior use of peek() to add a
	// character to
	// genericizeString.
	/**
	 * Increments the current index by one and returns the character at the new
	 * index. If the resulting index is greater or equal to the end index, the
	 * current index is reset to the end index and a value of DONE is returned.
	 * NOTE: For this extended class, we are not modifying the behavior of this
	 * method, but want to caution against its use, except for when desiring the
	 * specific behavior of not having the returned character added to the
	 * genericizedString. Suggested use is to use peek() and next() when not
	 * wanting to add the character, but to use getAndIncrement() when wanting
	 * to add the character.
	 * 
	 * @return the character at the new position or DONE
	 */
	@Override
	public char next() {
		return super.next();
	}

	/**
	 * Returns the character at the current index and then increments the index
	 * by one. If the resulting index is greater or equal to the end index, the
	 * current index is reset to the end index and a value of DONE is returned.
	 * Also adds the character to the genericizedString.
	 * 
	 * @return the character at the new position or DONE
	 */
	@Override
	public char getAndIncrement() {
		char c = super.getAndIncrement();
		genericizedString.append(c);
		return c;
	}

	/**
	 * Increments the index by one.  Does no testing for whether the index
	 * surpasses the length of the string.
	 */
	@Override
	public void increment() {
		char c = super.getAndIncrement();
		genericizedString.append(c);
	}

	/**
	 * Increments the index by count.  Does no testing for whether the index
	 * surpasses the length of the string.  Also does internal processing
	 * for creating a genericized String.
	 * 
	 * @param count
	 *            number of characters to move ahead
	 */
	@Override
	public void increment(int count) {
		while (count-- > 0) {
			char c = super.getAndIncrement();
			genericizedString.append(c);
		}
	}

	/**
	 * Creates next unique fragment string for potential use.
	 */
	private String nextUnique() {
		uniqueCount++;
		return "name" + uniqueCount;
	}

	/**
	 * Converts Fragment to generic name fragment and appends it to the generic
	 * string. If the fragment has been seen before, uses previously devised
	 * generic name for that fragment.
	 */
	private void createAndAppendGenericFragment(String fragment) {
		// If fragment key does not already exist, insert nextUnique and
		// pre-calculate
		// a new nextUnique value. Regardless, uniqueFragment is a valid mapped
		// unique
		// value for fragment.
		// If fragment is empty string, just copy that.
		if (fragment.isEmpty()) {
			return;
		}
		// Inserting first char of real fragment (this fixes up anonymous
		// namespace 'A' code).
		if (fragment.charAt(0) == 'A') {
			nextUnique = 'A' + nextUnique;
		}
		String uniqueFragment = uniqueFragments.putIfAbsent(fragment, nextUnique);
		if (uniqueFragment == null) {
			uniqueFragment = nextUnique;
			nextUnique = nextUnique();
		}
		// Use the uniqueFragment associated with fragment.
		genericizedString.append(uniqueFragment);
	}

	/**
	 * Appends string to generic string.
	 */
	private void appendRemainder() {
		if (iter.getIndex() < iter.getLength()) {
			genericizedString.append(iter.getString().substring(iter.getIndex()));
		}
	}

	/******************************************************************************/
	/******************************************************************************/
	public String getGenericSymbol() {
		return genericizedString.toString();
	}

	/******************************************************************************/
	/******************************************************************************/
	// SPECIALIZATION METHODS

	@Override
	public String parseFragmentName(MDFragmentName fn) throws MDException {
		String name = super.parseFragmentName(fn);
		createAndAppendGenericFragment(name);
		return name;
	}
}

/******************************************************************************/
/******************************************************************************/
