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
#include "Gadget.h"
#include "iostream"
#include "ostream"
#include "stdio.h"

Gadget::Gadget(char *gname)
{
	this->name = gname;
	this->deployed = false;
	this->broken = false;
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

bool Gadget::isBroken()
{
	return broken;
}

int Gadget::getType()
{
	return type;
}

void Gadget::setBroken(bool state) {
	broken = state;
	if (broken) {
		deployed = false;
		workingOn = 0;
	}
}

void Gadget::use(Person *person)
{
	if (deployed || broken) {
		return;
	}

	deployed = true;
	workingOn = person;
}

void Gadget::print() {
	char *depstr = (deployed == false ? "is not" : "is");
	char *who = (deployed == false ? "anyone" : workingOn->name);
	printf("%s %s deployed on %s\n", name, depstr, who);
}


Gadget::~Gadget(void)
{
}
