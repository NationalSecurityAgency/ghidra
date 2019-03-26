/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
#include "StdAfx.h"
#include "Gadget.h"
#include "iostream"
#include "ostream"

Gadget::Gadget(char *gname)
{
	this->name = gname;
	this->deployed = false;
	this->type = 0;
	this->workingOn = NULL;
}

char *Gadget::getName()
{
	return name;
}

bool Gadget::isDeployed()
{
	return deployed;
}

int Gadget::getType()
{
	return type;
}

void Gadget::use(Person *person)
{
	if (deployed) {
		return;
	}

	deployed = true;
	workingOn = person;
}


Gadget::~Gadget(void)
{
}
