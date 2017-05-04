#define _GNU_SOURCE
#include <gio/gio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "probes.h"

gboolean enable_access_probes;

// Call a remote method with invalid arguments and check whether the error
// returned is access denied or invalid args. If it's the former, it's not very
// interesting.
gboolean check_access_method(GDBusConnection *bus, const gchar *dest, const gchar *path, const gchar *instance, const gchar *method, const gchar* sig)
{
    GDBusMessage *request;
    GDBusMessage *reply;
    gchar        *type;

    if (!enable_access_probes)
        return true;

    request = g_dbus_message_new_method_call(dest, path, instance, method);

    g_dbus_message_set_body(request, build_invalid_body(sig));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);

    if (g_dbus_message_get_message_type(reply) == G_DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        g_object_unref(reply);
        g_object_unref(request);
        printf("!!%s",method);
        return true;
    }


    gboolean v = check_access_by_reply(reply);
    g_object_unref(reply);
    g_object_unref(request);
    return v;
}

gboolean check_name_protected(GDBusConnection *bus, const gchar *name)
{
    GDBusMessage *request;
    GDBusMessage *reply;
    gchar        *type;

    if (!enable_access_probes)
        return true;

    request = g_dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName");

    g_dbus_message_set_body(request, g_variant_new ("(su)", name, 2));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);

    // Sometimes the parameters are not checked.
    if (g_dbus_message_get_message_type(reply) == G_DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        g_object_unref(reply);
        g_object_unref(request);
        return true;
    }

    g_assert_cmpint(g_dbus_message_get_message_type(reply), ==, G_DBUS_MESSAGE_TYPE_ERROR);

    type = strdupa(g_dbus_message_get_error_name(reply));

    g_object_unref(reply);
    g_object_unref(request);

    if (g_strcmp0(type, "org.freedesktop.DBus.Error.AccessDenied") == 0)
        return true;
    if (g_strcmp0(type, "org.freedesktop.DBus.Error.InvalidArgs") == 0)
        return true;

    g_print("Unknown Method Error String: %s\n", type);
    return false;
}

// Try to read the property, then set it to it's own value.
/// If we can't read it, set it to "test" and see if it works.
gboolean check_access_property(GDBusConnection *bus, const gchar *dest, const gchar *path, const gchar *instance, const gchar *property, const gchar* sig)
{
    GDBusMessage *request;
    GDBusMessage *reply;
    GVariant     *body;
    GVariant     *test;
    gchar        *type;

    if (!enable_access_probes)
        return true;

    g_debug("testing access to property %s on %s", property, instance);

    request = g_dbus_message_new_method_call(dest, path, "org.freedesktop.DBus.Properties", "Get");

    // Read the current value
    g_dbus_message_set_body(request, g_variant_new ("(ss)", instance, property));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);

    if (g_dbus_message_get_message_type(reply) != G_DBUS_MESSAGE_TYPE_METHOD_RETURN) {
        body = build_invalid_body(sig);
        g_variant_ref(body);
    } else {
        body = g_dbus_message_get_body(reply);

        g_assert_cmpstr(g_variant_get_type_string(body), ==, "(v)");

        g_variant_get(body, "(v)", &test);
        body = test;
        g_variant_ref(body);
    }

    g_object_unref(reply);
    g_object_unref(request);

    request = g_dbus_message_new_method_call(dest, path, "org.freedesktop.DBus.Properties", "Set");

    g_dbus_message_set_body(request, g_variant_new("(ssv)", instance, property, body));

    reply = g_dbus_send(bus, request, G_DBUS_SEND_MESSAGE_FLAGS_NONE, timeout, NULL, NULL, NULL);

    if (g_dbus_message_get_message_type(reply) == G_DBUS_MESSAGE_TYPE_ERROR) {


        type = strdupa(g_dbus_message_get_error_name(reply));

        gboolean v = check_access_by_reply(reply);

        g_object_unref(reply);
        g_object_unref(request);
        g_variant_unref(body);

        return v;
    }

    g_object_unref(reply);
    g_object_unref(request);
    g_variant_unref(body);

    return true;
}

