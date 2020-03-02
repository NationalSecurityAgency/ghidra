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
package ghidra.app.util.demangler;

/**
 * A unifying top-level interface for all {@link DemangledObject}s and {@link DemangledType}s
 * 
 * <p>This class and its children have many overlapping concepts that we wish to refine at a 
 * future date.  Below is a listing of know uses:
 * <TABLE>
 * 		<TR>
 * 			<TH ALIGN="left">Method</TH><TH ALIGN="left">Description</TH>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getName()}
 * 			</TD>
 * 			<TD>
 * 			A 'safe' name that is the {@link #getDemangledName()}, but with some characters
 * 			changed to be valid for use within Ghidra.
 * 			</TD>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getDemangledName()}
 * 			</TD>
 * 			<TD>
 * 			The unmodified name that was set upon this object.
 * 			</TD>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getNamespaceName()}
 * 			</TD>
 * 			<TD>
 * 			The name of this object when it is used as a namespace name.   This usually has 
 * 			parameter and template information.  Further, some characters within templates and
 * 			function signatures are replaced, such as spaces and namespace separators.
 * 			</TD>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getNamespaceString()}
 * 			</TD>
 * 			<TD>
 * 			Similar to {@link #getNamespaceName()}, but contains all parent namespaces as well.
 * 			</TD>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getSignature()}
 * 			</TD>
 * 			<TD>
 * 			Returns the complete string form of this object, with most known attributes.  For 
 * 			functions, this will be a complete signature. 
 * 			</TD>
 * 		</TR>
 * 		<TR>
 * 			<TD>
 * 			{@link #getOriginalDemangled()}
 * 			</TD>
 * 			<TD>
 * 			The original unmodified demangled string.
 * 			</TD>
 * 		</TR>
 * </TABLE>
 */
public interface Demangled {

	/**
	 * Returns the original mangled string
	 * @return the string
	 */
	public String getMangledString();

	/**
	 * Sets the original mangled string
	 * @param mangled the mangled string
	 */
	public void setMangledString(String mangled);

	/**
	 * Returns the original demangled string returned by the demangling service
	 * @return the original demangled string
	 */
	public String getOriginalDemangled();

	/**
	 * Sets the original demangles string returned by the demangling service
	 * @param originalDemangled the original demangled string
	 */
	public void setOriginalDemangled(String originalDemangled);

	/** 
	 * Returns the demangled name of this object.
	 * NOTE: unsupported symbol characters, like whitespace, will be converted to an underscore.
	 * @return name of this DemangledObject with unsupported characters converted to underscore
	 * @see #getDemangledName()
	 */
	public String getName();

	/**
	 * Sets the name for this object
	 * @param name the name
	 */
	public void setName(String name);

	/** 
	 * Returns the unmodified demangled name of this object. This name may contain whitespace 
	 * and other characters not supported for symbol or data type creation.  See {@link #getName()} 
	 * for the same name modified for use within Ghidra.
	 * @return name of this DemangledObject
	 */
	public String getDemangledName();

	/**
	 * Returns the namespace containing this demangled object
	 * @return the namespace containing this demangled object
	 */
	public Demangled getNamespace();

	/**
	 * Sets the namespace of this demangled object
	 * @param ns the namespace
	 */
	public void setNamespace(Demangled ns);

	/**
	 * Returns a representation of this object as fully-qualified namespace.  The 
	 * value returned here may have had some special characters replaced, such as ' ' replaced
	 * with '_' and '::' replaced with '--'.
	 * @return the full namespace
	 */
	public String getNamespaceString();

	/**
	 * Returns a this object's namespace name without the full-qualified parent path. The 
	 * value returned here may have had some special characters replaced, such as ' ' replaced
	 * with '_' and '::' replaced with '--'.
	 * 
	 * @return the name
	 */
	public String getNamespaceName();

	/**
	 * Generates a complete representation of this object to include all know attributes of this
	 * object 
	 * @return the signature
	 */
	public String getSignature();
}
