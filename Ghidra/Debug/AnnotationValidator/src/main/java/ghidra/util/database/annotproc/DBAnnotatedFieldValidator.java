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
package ghidra.util.database.annotproc;

import java.util.*;

import javax.lang.model.element.*;
import javax.lang.model.type.*;
import javax.tools.Diagnostic.Kind;

import ghidra.util.database.annot.DBAnnotatedField;

/**
 * A class for validating fields annotated with {@link DBAnnotatedField}
 * 
 * <p>
 * To ensure fields annotated with {@link DBAnnotatedField} meet the criteria required for database
 * fields in Ghidra. It extends the {@code AbstractDBAnnotationValidator} to provide additional
 * validation logic specific to database field annotations.
 */
public class DBAnnotatedFieldValidator extends AbstractDBAnnotationValidator {
	final VariableElement field;
	final Map<TypeMirror, TypeElement> javaToDBTypeMap;
	final static String FACTORY_NAME = "ghidra.util.database.DBCachedObjectStoreFactory";
	final static String BOOLEAN_CODEC_NAME = FACTORY_NAME + ".BooleanDBFieldCodec";
	final static String BYTE_CODEC_NAME = FACTORY_NAME + ".ByteDBFieldCodec";
	final static String SHORT_CODEC_NAME = FACTORY_NAME + ".ShortDBFieldCodec";
	final static String INT_CODEC_NAME = FACTORY_NAME + ".IntDBFieldCodec";
	final static String LONG_CODEC_NAME = FACTORY_NAME + ".LongDBFieldCodec";
	final static String STRING_CODEC_NAME = FACTORY_NAME + ".StringDBFieldCodec";
	final static String BYTE_ARRAY_CODEC_NAME = FACTORY_NAME + ".ByteArrayDBFieldCodec";
	final static String LONG_ARRAY_CODEC_NAME = FACTORY_NAME + ".LongArrayDBFieldCodec";
	final static String ENUM_CODEC_NAME = FACTORY_NAME + ".EnumDBByteFieldCodec";

	final TypeElement ENUM_CODEC_ELEM;

	/**
	 * Construct a new {@code DBAnnotatedFieldValidator} with the specified validation context and
	 * field element.
	 * 
	 * @param ctx the validation context
	 * @param field the field to validate
	 */
	public DBAnnotatedFieldValidator(ValidationContext ctx, VariableElement field) {
		super(ctx);
		this.field = field;

		Map<TypeMirror, TypeElement> typeMap = new LinkedHashMap<>();
		putPrimitiveTypeCodec(typeMap, TypeKind.BOOLEAN, BOOLEAN_CODEC_NAME);
		putPrimitiveTypeCodec(typeMap, TypeKind.BYTE, BYTE_CODEC_NAME);
		putPrimitiveTypeCodec(typeMap, TypeKind.SHORT, SHORT_CODEC_NAME);
		putPrimitiveTypeCodec(typeMap, TypeKind.INT, INT_CODEC_NAME);
		putPrimitiveTypeCodec(typeMap, TypeKind.LONG, LONG_CODEC_NAME);
		putTypeCodec(typeMap, String.class, STRING_CODEC_NAME);
		putPrimitiveArrayTypeCodec(typeMap, TypeKind.BYTE, BYTE_ARRAY_CODEC_NAME);
		putPrimitiveArrayTypeCodec(typeMap, TypeKind.LONG, LONG_ARRAY_CODEC_NAME);
		// NOTE: Enum requires subtype check

		javaToDBTypeMap = Map.copyOf(typeMap);

		ENUM_CODEC_ELEM = ctx.elementUtils.getTypeElement(ENUM_CODEC_NAME);
	}

	/**
	 * Associate a primitive type and its boxed type with the specified codec type in the map.
	 * 
	 * @param map the map linking java types to their corresponding codec types
	 * @param kind the primitive type kind
	 * @param codecName the fully qualified name of the codec type
	 */
	protected void putPrimitiveTypeCodec(Map<TypeMirror, TypeElement> map, TypeKind kind,
			String codecName) {
		PrimitiveType primitive = ctx.typeUtils.getPrimitiveType(kind);
		TypeMirror boxed = ctx.typeUtils.boxedClass(primitive).asType();
		TypeElement codec = ctx.elementUtils.getTypeElement(codecName);
		map.put(primitive, codec);
		map.put(boxed, codec);
	}

	/**
	 * Associate a specified class type with the specified codec type in the map.
	 * 
	 * @param map the map linking Java types to their corresponding codec types
	 * @param cls the class type
	 * @param codecName the fully qualified name of the codec type
	 */
	protected void putTypeCodec(Map<TypeMirror, TypeElement> map, Class<?> cls, String codecName) {
		TypeMirror type = ctx.elementUtils.getTypeElement(cls.getCanonicalName()).asType();
		TypeElement codec = ctx.elementUtils.getTypeElement(codecName);
		map.put(type, codec);
	}

	/**
	 * Associate a primitive array type with the specified codec type inthe map.
	 * 
	 * @param map the map linking Java types to their corresponding codec types
	 * @param kind the primitive type kind
	 * @param codecName the fully qualified name of the codec type
	 */
	protected void putPrimitiveArrayTypeCodec(Map<TypeMirror, TypeElement> map, TypeKind kind,
			String codecName) {
		PrimitiveType primitive = ctx.typeUtils.getPrimitiveType(kind);
		ArrayType array = ctx.typeUtils.getArrayType(primitive);
		TypeElement codec = ctx.elementUtils.getTypeElement(codecName);
		map.put(array, codec);
	}

	/**
	 * Validate the annotated field to ensure it meets the requirements for database fields.
	 * 
	 * <p>
	 * It performs the following checks:
	 * <ul>
	 * <li>The field must not be declared as {@code final}.</li>
	 * <li>The field must not be declared as {@code static}.</li>
	 * <li>The enclosing type of the field must meet the criteria defined in
	 * {@code checkEnclosingType}.</li>
	 * <li>The codec types for the field must be appropriate.</li>
	 * </ul>
	 */
	public void validate() {
		Set<Modifier> mods = field.getModifiers();
		if (mods.contains(Modifier.FINAL)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s cannot be applied to a final field",
					DBAnnotatedField.class.getSimpleName()),
				field);
		}
		if (mods.contains(Modifier.STATIC)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("@%s cannot be applied to a static field",
					DBAnnotatedField.class.getSimpleName()),
				field);
		}
		TypeElement type = (TypeElement) field.getEnclosingElement();
		checkEnclosingType(DBAnnotatedField.class, field, type);
		checkCodecTypes(type);
	}

	/**
	 * Return the default codec type element for the specified Java type.
	 * 
	 * @param javaType the Java type for which the default codec is needed
	 * @return the default codec type element, or {@code null} if no default codec is found
	 */
	protected TypeElement getDefaultCodecType(TypeMirror javaType) {
		if (ctx.isEnumType(javaType)) {
			return ENUM_CODEC_ELEM;
		}
		return javaToDBTypeMap.get(javaType);
	}

	/**
	 * Return the codec type element specified in the {@link DBAnnotatedField} annotation for the
	 * field, or the default codec type if none is specified.
	 * 
	 * @return the codec type element for the field
	 */
	protected TypeElement getCodecTypeElement() {
		DBAnnotatedField annotation = field.getAnnotation(DBAnnotatedField.class);
		TypeElement codecElem;
		try {
			codecElem = ctx.elementUtils.getTypeElement(annotation.codec().getCanonicalName());
		}
		catch (MirroredTypeException e) {
			codecElem = (TypeElement) ((DeclaredType) e.getTypeMirror()).asElement();
		}
		if (codecElem == ctx.DEFAULT_CODEC_ELEM) {
			return getDefaultCodecType(field.asType());
		}
		return codecElem;
	}

	/**
	 * Check the codec types associated with the field to ensure they meet the necessary
	 * requirements.
	 * 
	 * @param objectType the type of the enclosing object
	 */
	protected void checkCodecTypes(TypeElement objectType) {

		TypeElement codecType = getCodecTypeElement();
		if (codecType == null) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("Could not select default codec for %s. @%s.codec must be specified.",
					field.asType(), DBAnnotatedField.class.getSimpleName()),
				field);
			return;
		}

		// REQUIREMENTS:
		//   1) ValueType matches the field's type exactly
		//      Cannot be super or extends because it's read/write
		//   2) ObjectType is super of the containing object
		//      Need to ensure extra interfaces (intersection) are considered
		//   3) FieldType is non-abstract
		//   4) The codec has an appropriate constructor

//		for (Element enc : codecType.getEnclosedElements()) {
//			if (enc.getKind() == ElementKind.CONSTRUCTOR) {
//				ExecutableElement exe = (ExecutableElement) enc;
//				ExecutableType exeType = (ExecutableType) exe.asType();
//				//throw new RuntimeException();
//			}
//		}

		Map<String, TypeMirror> args = ctx.getArguments(codecType, ctx.DB_FIELD_CODEC_ELEM);

		// 1)
		TypeMirror argVT = args.get("VT");
		if (!ctx.hasType(field, argVT)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("Codec %s can only be used with fields of type %s", codecType, argVT),
				field);
		}

		// 2) (INCOMPLETE)
		TypeMirror argOT = args.get("OT");
		if (!ctx.isCapturable(objectType.asType(), argOT)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("Codec %s requires the containing object to conform to %s", codecType,
					ctx.format(argOT)),
				field);
		}

		// 3)
		TypeMirror argFT = args.get("FT");
		if (argFT.getKind() != TypeKind.DECLARED) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("Codec %s must have a non-abstract class for its field type, not %s",
					codecType, argFT),
				codecType);
		}
		else if (((DeclaredType) argFT).asElement().getModifiers().contains(Modifier.ABSTRACT)) {
			ctx.messager.printMessage(Kind.ERROR,
				String.format("Codec %s must have a non-abstract class for its field type, not %s",
					codecType, argFT),
				codecType);
		}
	}
}
