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
package ghidra.javaclass.format.attributes;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

/**
 * NOTE: THE FOLLOWING TEXT EXTRACTED FROM JVMS7.PDF
 * <p>
 * The RuntimeVisibleParameterAnnotations attribute is a variable-length
 * attribute in the attributes table of the method_info structure. The
 * RuntimeVisibleParameterAnnotations attribute records runtime-visible Java
 * programming language annotations on the parameters of the corresponding
 * method.
 * <p>
 * The RuntimeInvisibleParameterAnnotations attribute is similar to the
 * RuntimeVisibleParameterAnnotations attribute, except that the annotations
 * represented by a RuntimeInvisibleParameterAnnotations attribute must not
 * be made available for return by reflective APIs, unless the the Java virtual
 * machine has specifically been instructed to retain these annotations via some
 * implementation-specific mechanism such as a command line flag. In the absence
 * of such instructions, the Java virtual machine ignores this attribute.
 * <p>
 * Each method_info structure may contain at most one
 * RuntimeVisibleParameterAnnotations attribute, which records all the runtimevisible
 * Java programming language annotations on the parameters of the
 * corresponding method. The Java virtual machine must make these annotations
 * available so they can be returned by the appropriate reflective APIs.
 * <p>
 * The Runtime(In)VisibleParameterAnnotations attribute has the following format:
 * <pre>
 * 	Runtime(In)VisibleParameterAnnotations_attribute {
 * 		u2 attribute_name_index;
 * 		u4 attribute_length;
 * 		u1 num_parameters;
 * 		{
 * 			u2 num_annotations;
 * 			annotation annotations[num_annotations];
 * 		} parameter_annotations[num_parameters];
 * 	}
 * </pre>
 */
public class RuntimeParameterAnnotationsAttribute extends AbstractAttributeInfo {

	private boolean _isVisible;

	private byte numberOfParameters;
	private Map<Integer, AnnotationJava[]> parameterAnnotations =
		new HashMap<Integer, AnnotationJava[]>();

	public RuntimeParameterAnnotationsAttribute(BinaryReader reader, boolean isVisible)
			throws IOException {
		super(reader);

		_isVisible = isVisible;

		numberOfParameters = reader.readNextByte();

		for (int i = 0; i < getNumberOfParameters(); ++i) {
			short numberOfAnnotations = reader.readNextShort();
			AnnotationJava[] annotations = new AnnotationJava[(numberOfAnnotations & 0xffff)];
			for (int a = 0; a < (numberOfAnnotations & 0xffff); ++a) {
				annotations[a] = new AnnotationJava(reader);
			}
			parameterAnnotations.put(i, annotations);
		}
	}

	/**
	 * If true, these parameters are "RuntimeVisibleParameterAnnotations".
	 * Otherwise, these parameters are "RuntimeInvisibleParameterAnnotations".
	 * @return true if visible parameters
	 */
	public boolean isVisible() {
		return _isVisible;
	}

	/**
	 * The value of the num_parameters item gives the number of parameters of
	 * the method represented by the method_info structure on which the annotation
	 * occurs.
	 * (This duplicates information that could be extracted from the method descriptor.)
	 * @return the number of parameters for this method
	 */
	public int getNumberOfParameters() {
		return numberOfParameters & 0xff;
	}

	/**
	 * Each value of the parameter_annotations table represents all of the runtimevisible
	 * annotations on a single parameter. The sequence of values in the table
	 * corresponds to the sequence of parameters in the method descriptor. Each
	 * parameter_annotations entry contains the following two items:
	 * 	num_annotations
	 * 		The value of the num_annotations item indicates the number of runtimevisible
	 * 		annotations on the parameter corresponding to the sequence number
	 * 		of this parameter_annotations element.
	 * 	annotations
	 * 		Each value of the annotations table represents a single runtime-visible
	 * 		annotation on the parameter corresponding to the sequence number of this
	 * 		parameter_annotations element.
	 * @param parameter the parameter index
	 * @return the annotations for the given parameter
	 */
	public AnnotationJava[] getParameterAnnotations(int parameter) {
		return parameterAnnotations.get(parameter);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String name = _isVisible
				? "RuntimeVisibleParameterAnnotations_attribute" + "|" + numberOfParameters + "|"
				: "RuntimeInvisibleParameterAnnotations_attribute" + "|" + numberOfParameters + "|";

		StructureDataType structure = getBaseStructure(name);
		structure.add(BYTE, "num_parameters", null);
		for (int i = 0; i < numberOfParameters; ++i) {
			structure.add(WORD, "num_annotations_" + i, null);
			AnnotationJava[] annotations = parameterAnnotations.get(i);
			for (int a = 0; a < annotations.length; ++a) {
				structure.add(annotations[a].toDataType(), "annotations_" + i + "_" + a, null);
			}
		}

		return structure;
	}

}
