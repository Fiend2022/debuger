#include "pluginManager.hpp"
#include "pluginAPI.hpp"
#include <filesystem>
#include "DebugAPI.hpp"

void PluginManager::loadPluginsFromDir(const std::string& dir)
{
    for (const auto& entry : std::filesystem::directory_iterator(dir))
    {
        if (entry.path().extension() != ".dll") continue;
        loadPlugin(entry);
    }
}

void PluginManager::unloadAll()
{
    for (auto& loaded : plugins)
    {
        HMODULE hMod = loaded.handle;

        auto getApiFunc = (PluginAPI(*)()) GetProcAddress(hMod, "get_plugin_api");
        if (getApiFunc)
        {
            PluginAPI api = getApiFunc();
            if (api.shutdown)
                api.shutdown();
        }
        FreeLibrary(hMod);
    }
    plugins.clear();
}

PluginManager::~PluginManager()
{
    unloadAll();
}

void PluginManager::loadPlugin(const std::filesystem::directory_entry& file)
{

    HMODULE hMod = LoadLibraryA(file.path().string().c_str());
    if (!hMod) return;

    auto getApi = (PluginAPI(*)()) GetProcAddress(hMod, "get_plugin_api");
    if (!getApi)
    {
        FreeLibrary(hMod);
        return;
    }

    PluginAPI pluginApi = getApi();
    if (pluginApi.init(get_debug_api())) {
        plugins.push_back({ hMod, file.path().filename().string() });
    }
}