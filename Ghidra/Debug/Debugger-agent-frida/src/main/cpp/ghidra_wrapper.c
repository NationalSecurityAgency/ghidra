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
#include "frida-core.h"
#include <stdio.h>
#include <stdarg.h>

extern "C" {

void GH_frida_init (void) {
	frida_init ();
}

FridaDeviceManager * GH_frida_device_manager_new (void) {
	return frida_device_manager_new();
}

void GH_frida_device_manager_close_sync (FridaDeviceManager * self, GCancellable * cancellable, GError ** error) {
	frida_device_manager_close_sync(self, cancellable, error);
}


FridaDevice * GH_frida_device_manager_find_device_by_type_sync (FridaDeviceManager * self, FridaDeviceType type, gint timeout, GCancellable * cancellable, GError ** error) {
	return frida_device_manager_find_device_by_type_sync(self, type, timeout, cancellable, error);
}

FridaDevice * GH_frida_device_manager_find_device_by_id_sync (FridaDeviceManager * self, const gchar * id, gint timeout, GCancellable * cancellable, GError ** error) {
	return frida_device_manager_find_device_by_id_sync(self, id, timeout, cancellable, error);
}

FridaDeviceList * GH_frida_device_manager_enumerate_devices_sync (FridaDeviceManager * self, GCancellable * cancellable, GError ** error) {
	return frida_device_manager_enumerate_devices_sync(self, cancellable, error);
}

gint GH_frida_device_list_size (FridaDeviceList * self) {
	return frida_device_list_size (self);
}

FridaDevice * GH_frida_device_list_get (FridaDeviceList * self, gint index) {
	return frida_device_list_get(self, index);
}

const gchar * GH_frida_device_get_id (FridaDevice * self) {
	return frida_device_get_id(self);
}

const gchar * GH_frida_device_get_name (FridaDevice * self) {
	return frida_device_get_name(self);
}


FridaProcessList * GH_frida_device_enumerate_processes_sync (FridaDevice * self, FridaProcessQueryOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_device_enumerate_processes_sync(self, options, cancellable, error);
}

/* ProcessList */
gint GH_frida_process_list_size (FridaProcessList * self) {
	return frida_process_list_size(self);
}

FridaProcess * GH_frida_process_list_get (FridaProcessList * self, gint index) {
	return frida_process_list_get(self, index);
}

/* Process */
guint GH_frida_process_get_pid (FridaProcess * self) {
	return frida_process_get_pid(self);
}

const gchar * GH_frida_process_get_name (FridaProcess * self) {
	return frida_process_get_name(self);
}

GHashTable * GH_frida_process_get_parameters (FridaProcess * self) {
	return frida_process_get_parameters(self);
}


FridaApplicationList * GH_frida_device_enumerate_applications_sync (FridaDevice * self, FridaApplicationQueryOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_device_enumerate_applications_sync(self, options, cancellable, error);
}

/* ApplicationList */
gint GH_frida_application_list_size (FridaApplicationList * self) {
	return frida_application_list_size(self);
}

FridaApplication * GH_frida_application_list_get (FridaApplicationList * self, gint index) {
	return frida_application_list_get(self, index);
}

/* Application */
const gchar * GH_frida_application_get_identifier (FridaApplication * self) {
	return frida_application_get_identifier(self);
}

const gchar * GH_frida_application_get_name (FridaApplication * self) {
	return frida_application_get_name(self);
}

guint GH_frida_application_get_pid (FridaApplication * self) {
	return frida_application_get_pid(self);
}

GHashTable * GH_frida_application_get_parameters (FridaApplication * self) {
	return frida_application_get_parameters(self);
}


FridaSession * GH_frida_device_attach_sync (FridaDevice * self, guint pid, FridaSessionOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_device_attach_sync(self, pid, options, cancellable, error);
}

guint GH_frida_device_spawn_sync (FridaDevice * self, const gchar * program, FridaSpawnOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_device_spawn_sync(self, program, options, cancellable, error);
}

/* Session */
guint GH_frida_session_get_pid (FridaSession * self) {
	return frida_session_get_pid(self);
}

FridaProcess * GH_frida_device_get_process_by_pid_sync (FridaDevice * self, guint pid, FridaProcessMatchOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_device_get_process_by_pid_sync(self, pid, options, cancellable, error);
}

void GH_frida_device_resume_sync (FridaDevice * self, guint pid, GCancellable * cancellable, GError ** error) {
	frida_device_resume_sync(self, pid, cancellable, error);
}

void GH_frida_device_kill_sync (FridaDevice * self, guint pid, GCancellable * cancellable, GError ** error) {
	frida_device_kill_sync(self, pid, cancellable, error);
}


gboolean GH_frida_session_is_detached (FridaSession * self) {
	return frida_session_is_detached(self);

}

void GH_frida_session_detach_sync (FridaSession * self, GCancellable * cancellable, GError ** error) {
	frida_session_detach_sync(self, cancellable,  error);
}

void GH_frida_session_resume_sync (FridaSession * self, GCancellable * cancellable, GError ** error) {
	frida_session_resume_sync(self, cancellable, error);
}


/* ScriptOptions */
FridaScriptOptions * GH_frida_script_options_new (void) {
	return frida_script_options_new();
}

void GH_frida_script_options_set_name (FridaScriptOptions * self, const gchar * value) {
	frida_script_options_set_name(self, value);
}

void GH_frida_script_options_set_runtime (FridaScriptOptions * self, FridaScriptRuntime value) {
	frida_script_options_set_runtime(self, value);
}

FridaScript * GH_frida_session_create_script_sync (FridaSession * self, const gchar * source, FridaScriptOptions * options, GCancellable * cancellable, GError ** error) {
	return frida_session_create_script_sync(self, source, options, cancellable, error);
}

/* Object lifetime */
void GH_frida_unref (gpointer obj) {
	frida_unref(obj);
}

/* Script */
void GH_frida_script_load_sync (FridaScript * self, GCancellable * cancellable, GError ** error) {
	frida_script_load_sync(self, cancellable, error);
}

void GH_frida_script_unload_sync (FridaScript * self, GCancellable * cancellable, GError ** error) {
	frida_script_unload_sync(self, cancellable, error);
}

void GH_frida_session_enable_debugger_sync (FridaSession * self, guint16 port, GCancellable * cancellable, GError ** error) {
	frida_session_enable_debugger_sync(self, port, cancellable, error);
}


gulong GH_g_signal_connect_data (gpointer instance, const gchar *detailed_signal, GCallback c_handler, gpointer data, GClosureNotify destroy_data, GConnectFlags connect_flags) {
	return g_signal_connect_data(instance, detailed_signal, c_handler, data, destroy_data, connect_flags);
}

void GH_g_signal_handler_disconnect (gpointer instance, gulong handler_id) {
	g_signal_handler_disconnect(instance, handler_id);
}

void GH_g_signal_emit_by_name (FridaHostSession *session, const gchar *signal_name, const gchar *message) {
	g_signal_emit_by_name(session, signal_name, message);
}

guint GH_g_signal_new (const gchar *signal_name, GType itype, GSignalFlags signal_flags, guint class_offset, GSignalAccumulator accumulator, gpointer accu_data, GSignalCMarshaller c_marshaller, GType return_type, guint n_params, ...) {
	va_list args;
	va_start(args, n_params);
	return g_signal_new(signal_name, itype, signal_flags, class_offset, accumulator, accu_data, c_marshaller, return_type, n_params, args);
}

}
