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
package mdemangler.object;

import ghidra.util.Msg;
import mdemangler.*;
import mdemangler.functiontype.MDFunctionType;
import mdemangler.naming.*;
import mdemangler.typeinfo.MDTypeInfo;
import mdemangler.typeinfo.MDTypeInfoParser;

/**
 * This class represents a derivative of an <b><code>MDObject</code></b> which is a C++ object.
 */
public class MDObjectCPP extends MDObject {
	protected MDHashedObject hashedObject;
	protected MDQualifiedBasicName qualifiedName;
	protected MDTypeInfo typeInfo;
	protected boolean embeddedObjectFlag;
	protected boolean hashedObjectFlag;

	public MDObjectCPP(MDMang dmang) {
		super(dmang);
	}

	public MDQualifiedBasicName getQualifiedName() {
		return qualifiedName;
	}

	public MDTypeInfo getTypeInfo() {
		return typeInfo;
	}

	/**
	 * Returns the embedded object if there is one.  Else returns itself.
	 *  @see MDBasicName#getEmbeddedObject()
	 * @return An MDObjectCPP representing the original or the embedded object.
	 */
	public MDObjectCPP getEmbeddedObject() {
		if (embeddedObjectFlag) {
			return qualifiedName.getBasicName().getEmbeddedObject();
		}
		return this;
	}

	/**
	 * Returns the name of the symbol, minus any namespace component.
	 * @return the name.
	 */
	public String getName() {
		if (hashedObjectFlag) {
			return hashedObject.toString();
		}
		return getQualifiedName().getBasicName().toString();
	}

	/**
	 * Returns the {@link MDQualification} component that represents the namespace.
	 * @return the namespace information.
	 */
	public MDQualification getQualfication() {
		if (hashedObjectFlag) {
			return hashedObject.getQualification();
		}
		return getQualifiedName().getQualification();
	}

	/**
	 * Returns {@code true} if the symbol's Basic Name is of a {@link MDString} type.
	 *  @return {@code true} if Basic Name is of {@link MDString} type.
	 */
	public boolean isString() {
		if (qualifiedName == null) {
			return false;
		}
		return qualifiedName.isString();
	}

	/**
	 * Returns the {@link MDString} from the Basic Name if it is a symbol of that type; else
	 *  returns null.
	 *  @return the {@link MDString} or null if does not exist.
	 */
	public MDString getMDString() {
		if (isString()) {
			return qualifiedName.getMDString();
		}
		return null;
	}

	@Override
	public void insert(StringBuilder builder) {
		if (hashedObjectFlag) {
			hashedObject.insert(builder);
		}
		else {
			qualifiedName.insert(builder);
			if (typeInfo != null) {
				typeInfo.insert(builder);
			}
		}
	}

	@Override
	protected void parseInternal() throws MDException {
		if (dmang.peek() != '?') {
			throw new MDException("Invalid ObjectCPP");
		}
		dmang.increment();
		if ((dmang.peek(0) == '?') && (dmang.peek(1) == '?')) { //??? prefix
			embeddedObjectFlag = true;
		}

		if ((dmang.peek(0) == '?') && (dmang.peek(1) == '@')) { //??@ prefix
			// MDMANG SPECIALIZATION USED.
			dmang.processHashedObject(this);
		}
		else {
			qualifiedName = new MDQualifiedBasicName(dmang);
			qualifiedName.parse();
			if (qualifiedName.isString()) {
				return;
			}
			if (dmang.peek() != MDMang.DONE) {
				int RTTINum = qualifiedName.getRTTINumber();
				typeInfo = MDTypeInfoParser.parse(dmang, RTTINum);
				if (qualifiedName.isTypeCast()) {
					typeInfo.setTypeCast();
				}
				typeInfo.parse();
				if (!typeInfo.getNameModifier().isEmpty()) {
					qualifiedName.setNameModifier(typeInfo.getNameModifier());
				}
				if (qualifiedName.isTypeCast()) {
					applyFunctionReturnTypeToTypeCastOperatorName();
				}
			}
		}
	}

	private void applyFunctionReturnTypeToTypeCastOperatorName() {
		// Make sure there is a function with a return type
		if (!(typeInfo.getMDType() instanceof MDFunctionType)) {
			Msg.warn(this, "Cannot get function return type from non-function");
			return;
		}
		MDFunctionType functionType = (MDFunctionType) typeInfo.getMDType();
		if (!functionType.hasReturn() || functionType.getReturnType() == null) {
			Msg.warn(this, "No return type available to set to cast operator name");
			return;
		}
		qualifiedName.setCastTypeString(functionType.getReturnType().toString());
	}

	/**
	 * Processes the hashed object in the normal fashion.
	 * @throws MDException On parsing error.
	 */
	public void processHashedObject() throws MDException {
		hashedObject = new MDHashedObject(dmang);
		hashedObject.parse();
		hashedObjectFlag = true;
	}

	/**
	 * Always throws an exception, mimicking the MSFT "failure" behavior, which cuts the parsing
	 *  process short...  This is one of two choice methods than can be used.
	 * @throws MDException always.
	 * @see #processHashedObject()
	 */
	public void processHashedObjectMSVC() throws MDException {
		throw new MDException("cannot parse hashed symbol");
	}

	/**
	 * Represents the MD5 hashed representation of the internals of the {@link MDObjectCPP}.
	 *  It takes the place of the {@link MDQualifiedBasicName}.  We have included an unused
	 *  (except to be able to return one that is empty) {@link MDQualification} so that the
	 *  {@link MDObjectCPP} has one to return.
	 * <p>
	 * Not sure that we will keep this class in the long run or find a way to include it
	 *  inside of the {@link MDObjectCPP} or if this {@link MDHashedObject} should be pulled
	 *  out separately and detected/parsed by the {@link MDMangObjectParser}.  If this last
	 *  thing is done, then we would have to find places in the package where we explicitly
	 *  create {@link MDObjectCPP MDObjectCPPs}, such as in {@link MDNestedName}, and check to
	 *  see if we can modify those locations (in all cases) to perform the detecting/parsing
	 *  using the {@link MDMangObjectParser}.  This will need more study when more time is
	 *  available.
	 */
	public class MDHashedObject extends MDParsableItem {
		private String hashString = "";
		private MDQualification qualification; // We are making this dummy object

		/**
		 * Constructor for {@link MDHashedObject}
		 * @param dmang The {@link MDMang} for which the work is performed and from from which
		 *  the information is parsed.
		 */
		public MDHashedObject(MDMang dmang) {
			super(dmang);
			qualification = new MDQualification(dmang);
		}

		/**
		 * Returns the hashed string.
		 * @return the hashed string.
		 */
		public String getHashString() {
			return hashString;
		}

		/**
		 * Returns an empty {@link MDQualification} that represents the namespace of the symbol.
		 *  Note: we have yet to decide whether we should do anything but this.
		 * @return the namespace information (empty for now).
		 */
		public MDQualification getQualification() {
			return qualification;
		}

		@Override
		protected void parseInternal() throws MDException {

			if ((dmang.peek() != '?') && (dmang.peek(1) != '@')) {
				throw new MDException("Invalid HashedObject");
			}
			dmang.increment(2);

			StringBuilder builder = new StringBuilder();
			char ch;
			int start = dmang.getIndex();
			while ((ch = dmang.peek()) != MDMang.DONE) {
				if (ch == '@') {
					break;
				}
				if (!(Character.isLetter(ch) || Character.isDigit(ch))) {
					break;
				}
				builder.append(ch);
				dmang.next();
			}
			int end = dmang.getIndex();
			if ((end - start) != 32 || ch != '@') {
				throw new MDException("Invalid HashedObject");
			}
			dmang.increment();
			hashString = builder.toString();
		}

		@Override
		public void insert(StringBuilder builder) {
			// We have made up the output format.  Nothing is sacrosanct about this output.
			builder.append("`" + hashString + "'");
		}
	}

}

/******************************************************************************/
/******************************************************************************/
