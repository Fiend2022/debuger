#pragma once

#include <string>
#include <vector>
#include <Windows.h>
#include <filesystem>

class PluginManager
{
public:
    void loadPluginsFromDir(const std::string& dir);
    void loadPlugin(const std::filesystem::directory_entry& file);
    void unloadAll();
    ~PluginManager();

private:
    struct LoadedPlugin {
        HMODULE handle;
        std::string name;
    };
    std::vector<LoadedPlugin> plugins;
};