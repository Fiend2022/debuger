#pragma once


#ifdef __cplusplus
extern "C" {
#endif


    struct DebugCAPI;

    typedef bool (*plugin_init_fn)(const DebugCAPI*);
    typedef void (*plugin_shutdown_fn)();   

    struct PluginAPI
    {
        plugin_init_fn init;        
        plugin_shutdown_fn shutdown; 
    };



#ifdef __cplusplus
}
#endif