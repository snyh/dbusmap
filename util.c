#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>


#include "util.h"

static gchar* dump_property(xmlNodePtr node, const char* prop)
{
    xmlChar* value = xmlGetProp(node, (const xmlChar*)prop);
    char* ret = g_strdup((gchar*)value);
    if (value != NULL)
        xmlFree(value);
    return ret;
}

GVariant* build_zero_body(const gchar* sig)
{
    if (sig == NULL) return NULL;

    if (g_str_equal(sig, "s")) {
        return  g_variant_new("(s)","");
    }

    GVariant* v = g_variant_new(g_strdup_printf("(%s)", sig == NULL ? "" : sig));

    return v;
}

GVariant* build_invalid_body(const gchar* sig)
{
    return build_zero_body(sig);

    if (sig == NULL || g_str_equal(sig, "s")) {
        return g_variant_new("(d)", 0);
    } else {
        return g_variant_new("(s)", "INVALID STRING");
    }
}

gchar* get_method_signature(xmlNodePtr node) {
    if (node == NULL) {
        return NULL;
    }
    xmlNodePtr cur = node->children;
    while (cur != NULL) {
        const gchar* name = (const gchar*)cur->name;
        if (name == NULL) {
            cur = cur->next;
            continue;
        }
        if (g_str_equal("arg", name)) {
            xmlChar* s = xmlGetProp(cur, (const xmlChar*)"direction");
            if (!g_str_equal(s, "out")) {
                xmlFree(s);
                return dump_property(cur, "type");
            }
            xmlFree(s);
        }
        cur = cur->next;
    }
    return NULL;
}

gchar* get_property_signature(xmlNodePtr node) {
    if (node == NULL) {
        return NULL;
    }
    return dump_property(node, "type");
}



// Simple wrapper for a common D-Bus pattern.
GVariant * g_dbus_simple_send(GDBusConnection *bus, GDBusMessage *msg, const gchar *type)
{
    GDBusMessage *reply;
    GVariant *body;
    gchar *fmt;

    if (!(reply = g_dbus_send(bus, msg, 0, timeout, 0, 0, 0))) {
        g_object_unref(msg);
        return NULL;
    }

    body  = g_dbus_message_get_body(reply);
    fmt   = g_dbus_message_print(reply, 0);

    g_variant_ref(body);

    if (g_strcmp0(g_variant_type_peek_string(g_variant_get_type(body)), type) != 0) {
        g_message("body type %s does not match expected type %s, message: %s",
                  g_variant_type_peek_string(g_variant_get_type(body)),
                  type,
                  fmt);
        g_variant_unref(body);

        // return error
        body = NULL;
    }

    g_free(fmt);
    g_object_unref(reply);
    g_object_unref(msg);
    return body;
}


gboolean check_access_by_reply(GDBusMessage* reply) {
    GError* err = NULL;
    if (!g_dbus_message_to_gerror(reply, &err)) {
        return true;
    }
    if (g_strrstr(err->message, "auth") && g_strrstr(err->message, "fail")) {
        g_error_free(err);
        return false;
    }
    printf("ErrorMessage:%s\n",err->message);
    g_error_free(err);

    // check by reply type
    const gchar* type = g_dbus_message_get_error_name(reply);

    if (g_strcmp0(type, "org.freedesktop.DBus.Error.InvalidArgs") == 0)
        return true;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.AccessDenied") == 0)
        return false;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.PropertyReadOnly") == 0)
        return false;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.UnknownMethod") == 0)
        return false;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.NoReply") == 0)
        return true;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.ServiceUnknown") == 0)
        return true;

    if (g_strstr_len(type, -1, "authorization_2derror"))
        return false;

    if (g_strcmp0(type, "org.freedesktop.DBus.Python.dbus.exceptions.DBusException") == 0)
        return false;
    if (g_strcmp0(type, "org.freedesktop.DBus.Python.TypeError") == 0)
        return true;
    if (g_strcmp0(type, "org.freedesktop.DBus.Python.ValueError") == 0)
        return true;

    if (g_strcmp0(type, "org.freedesktop.PolicyKit.Error.NotAuthorized") == 0)
        return false;
    if (g_strstr_len(type, -1, "PolKit.NotAuthorizedException"))
        return false;

    g_debug("unknown method error string received `%s`", type);
    return true;
}


gboolean skip(const gchar* dest, const gchar* ifc) {
    if (g_str_equal(ifc, "org.freedesktop.DBus.Introspectable")) {
        return true;
    }

    /* if (!g_str_equal(dest, "com.deepin.daemon.Accounts")) { */
    /*     return true; */
    /* } */

    if (g_str_has_prefix(dest, ":")) {
        return true;
    }

    if (g_str_equal(dest, "org.freedesktop.DBus")) {
        return true;
    }

    if (g_str_equal(ifc, "org.freedesktop.DBus.Peer")) {
        return true;
    }

    if (g_strrstr(dest, "deepin") ||
        g_str_equal(dest, "org.freedesktop.DBus")) {
        return false;
    }
    return true;
}
