# --- JNI bridge -------------------------------------------------------------
# Native method symbol names (Java_..._nativeStartCapture) depend on the class
# and method names, so they must survive R8.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
-keep class com.example.tlswatchdog.vpn.NativeBridge { *; }

# VpnCallbacks methods are looked up from native by name/signature via
# GetMethodID (protectSocket / onFlow / onFlowUpdate / onFlowClose), so keep the
# interface and every implementer's members.
-keep interface com.example.tlswatchdog.vpn.VpnCallbacks { *; }
-keep class * implements com.example.tlswatchdog.vpn.VpnCallbacks { *; }

# --- Room -------------------------------------------------------------------
# Entities are populated by generated code; keep their shape to be safe.
-keep class com.example.tlswatchdog.data.FlowEntity { *; }
