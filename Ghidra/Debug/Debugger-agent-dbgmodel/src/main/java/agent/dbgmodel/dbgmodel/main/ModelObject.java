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
package agent.dbgmodel.dbgmodel.main;

import java.util.List;
import java.util.Map;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Guid.REFIID;
import com.sun.jna.platform.win32.Variant.VARIANT;
import com.sun.jna.platform.win32.WTypes.VARTYPE;

import agent.dbgmodel.dbgmodel.UnknownEx;
import agent.dbgmodel.dbgmodel.datamodel.DataModelManager1;
import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.jna.dbgmodel.DbgModelNative.*;
import agent.dbgmodel.jna.dbgmodel.IUnknownEx;
import agent.dbgmodel.jna.dbgmodel.main.IModelObject;

/**
 * A wrapper for {@code IModelObject} and its newer variants.
 */
public interface ModelObject extends UnknownEx {

	DebugHostContext getContext();

	ModelObjectKind getKind();

	Object getIntrinsicValue();

	VARIANT getIntrinsicValueAs(VARTYPE vt);

	ModelObject getKeyValue(String key);

	void setKeyValue(WString key, ModelObject object);

	KeyEnumerator enumerateKeyValues();

	ModelObject getRawValue(int kind, WString name, int searchFlags);

	RawEnumerator enumerateRawValues(int kind, int searchFlags);

	ModelObject dereference();

	ModelObject tryCastToRuntimeType();

	UnknownEx getConcept(REFIID conceptId);

	LOCATION getLocation();

	DebugHostType1 getTypeInfo();

	DebugHostType1 getTargetInfo();

	long getNumberOfParentModels();

	ModelObject getParentModel(int i);

	void addParentModel(ModelObject model, ModelObject contextObject, boolean override);

	void removeParentModel(ModelObject model);

	ModelObject getKey(String key);

	ModelObject getKeyReference(String key);

	void setKey(WString key, ModelObject object, KeyStore conceptMetadata);

	void clearKeys();

	KeyEnumerator enumerateKeys();

	KeyEnumerator enumerateKeyReferences();

	void setConcept(REFIID conceptId, ModelObject conceptInterface, ModelObject conceptMetadata);

	void clearConcepts();

	ModelObject getRawReference(int kind, WString name, int searchFlags);

	RawEnumerator enumerateRawReferences(int kind, int searchFlags);

	void setContextForDataModel(ModelObject dataModelObject, IUnknownEx context);

	UnknownEx getContextForDataModel(ModelObject dataModelObject);

	boolean compare(ModelObject contextObject, ModelObject other);

	/*******/

	KeyStore getMetadata();

	void setMetadata(KeyStore metadata);

	void setContextObject(ModelObject context);

	ModelObject getIndexer();

	void setIndexer(ModelObject indexer);

	List<ModelObject> getElements();

	ModelObject getChild(DataModelManager1 manager, VARIANT v);

	Map<String, ModelObject> getKeyValueMap();

	Map<String, ModelObject> getRawValueMap();

	Object getValue();

	String getValueString();

	IModelObject getJnaData();

	void switchTo(DataModelManager1 manager, VARIANT v);

	ModelMethod getMethod(String name);

	String getOriginalKey();

	String getSearchKey();

	void setSearchKey(String key);

	TypeKind getTypeKind();

}
