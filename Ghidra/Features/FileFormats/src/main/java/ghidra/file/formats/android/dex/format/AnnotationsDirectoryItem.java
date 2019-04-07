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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.util.*;

/**
 * annotations_directory_item
 * 
 * referenced from class_def_item
 * 
 * appears in the data section
 * 
 * alignment: 4 bytes
 */
public class AnnotationsDirectoryItem implements StructConverter {

	private int classAnnotationsOffset;
	private int fieldsSize;
	private int annotatedMethodsSize;
	private int annotatedParametersSize;
	private List< FieldAnnotation > fieldAnnotations = new ArrayList< FieldAnnotation >( );
	private List< MethodAnnotation > methodAnnotations = new ArrayList< MethodAnnotation >( );
	private List< ParameterAnnotation > parameterAnnotations = new ArrayList< ParameterAnnotation >( );
	private AnnotationSetItem _classAnnotations;

	public AnnotationsDirectoryItem( BinaryReader reader ) throws IOException {

		classAnnotationsOffset = reader.readNextInt( );
		fieldsSize = reader.readNextInt( );
		annotatedMethodsSize = reader.readNextInt( );
		annotatedParametersSize = reader.readNextInt( );

		for ( int i = 0 ; i < fieldsSize ; ++i ) {
			fieldAnnotations.add( new FieldAnnotation( reader ) );
		}
		for ( int i = 0 ; i < annotatedMethodsSize ; ++i ) {
			methodAnnotations.add( new MethodAnnotation( reader ) );
		}
		for ( int i = 0 ; i < annotatedParametersSize ; ++i ) {
			parameterAnnotations.add( new ParameterAnnotation( reader ) );
		}

		if ( classAnnotationsOffset > 0 ){
			long oldIndex = reader.getPointerIndex( );
			try {
				reader.setPointerIndex( classAnnotationsOffset );
				_classAnnotations = new AnnotationSetItem( reader );
			}
			finally {
				reader.setPointerIndex( oldIndex );
			}
		}
	}

	public int getClassAnnotationsOffset( ) {
		return classAnnotationsOffset;
	}

	public int getFieldsSize( ) {
		return fieldsSize;
	}

	public int getAnnotatedMethodsSize( ) {
		return annotatedMethodsSize;
	}

	public int getAnnotatedParametersSize( ) {
		return annotatedParametersSize;
	}

	public List< FieldAnnotation > getFieldAnnotations( ) {
		return Collections.unmodifiableList( fieldAnnotations );
	}

	public List< MethodAnnotation > getMethodAnnotations( ) {
		return Collections.unmodifiableList( methodAnnotations );
	}

	public List< ParameterAnnotation > getParameterAnnotations( ) {
		return Collections.unmodifiableList( parameterAnnotations );
	}

	public AnnotationSetItem getClassAnnotations( ) {
		return _classAnnotations;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "annotations_directory_item_" + fieldsSize + "_" + annotatedMethodsSize + "_" + annotatedParametersSize, 0 );
		structure.add( DWORD, "class_annotations_off", null );
		structure.add( DWORD, "fields_size", null );
		structure.add( DWORD, "annotated_methods_size", null );
		structure.add( DWORD, "annotated_parameters_size", null );
		int index = 0;
		for ( FieldAnnotation field : fieldAnnotations ) {
			structure.add( field.toDataType( ), "field_" + index, null );
			++index;
		}
		index = 0;
		for ( MethodAnnotation method : methodAnnotations ) {
			structure.add( method.toDataType( ), "method_" + index, null );
			++index;
		}
		index = 0;
		for ( ParameterAnnotation parameter : parameterAnnotations ) {
			structure.add( parameter.toDataType( ), "parameter_" + index, null );
			++index;
		}
		structure.setCategoryPath( new CategoryPath( "/dex/annotations_directory_item" ) );
		return structure;
	}

}
